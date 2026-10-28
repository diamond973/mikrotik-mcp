#!/usr/bin/env python3
"""MCP server for MikroTik RouterOS over the binary API. Standard library only.

Usage:
  python mikrotik_mcp.py                - stdio MCP server (this is how Claude Code runs it)
  python mikrotik_mcp.py setup ...      - add a router to the config (password prompted via getpass)
  python mikrotik_mcp.py list           - list known routers
  python mikrotik_mcp.py test [name]    - check connectivity (/system/resource/print)
  python mikrotik_mcp.py cmd <name> <command> [words...]  - one-off call from the terminal

Config: ~/.mikrotik-mcp/config.json (or the path in MIKROTIK_MCP_CONFIG):
  {"devices": [
     {"name": "rtr1", "host": "10.0.0.1", "user": "mcp", "password": "...",
      "port": 8728, "tls": false, "default": true}
  ]}

Changing the router configuration is allowed only with MIKROTIK_ALLOW_WRITE=true.
"""

import hashlib
import json
import os
import socket
import ssl
import sys
import time
from pathlib import Path

PROTOCOL_VERSION = "2025-06-18"
SERVER_INFO = {"name": "mikrotik", "version": "1.0.0"}

# on Windows the standard streams default to cp1251, which breaks non-ASCII text in JSON-RPC
for _stream in (sys.stdin, sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

CONFIG_PATH = Path(
    os.environ.get("MIKROTIK_MCP_CONFIG") or Path.home() / ".mikrotik-mcp" / "config.json"
)
ALLOW_WRITE = (os.environ.get("MIKROTIK_ALLOW_WRITE") or "").strip().lower() in (
    "1",
    "true",
    "yes",
    "on",
)
BACKUP_DIR = Path(
    os.environ.get("MIKROTIK_BACKUP_DIR") or CONFIG_PATH.parent / "backups"
)
MAX_CHARS = int(os.environ.get("MIKROTIK_MAX_CHARS") or 40000)
TIMEOUT = float(os.environ.get("MIKROTIK_TIMEOUT") or 30)

# read-only command verbs; everything else requires MIKROTIK_ALLOW_WRITE
READ_VERBS = {
    "print",
    "get",
    "getall",
    "export",
    "monitor",
    "monitor-traffic",
    "ping",
    "traceroute",
    "resolve",
    "find",
    "check-installation",
}


class MtError(Exception):
    pass


# ---------------------------------------------------------------- config


def load_devices():
    devices = []
    if CONFIG_PATH.exists():
        try:
            data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        except Exception as exc:
            raise MtError(f"cannot read {CONFIG_PATH}: {exc}")
        devices = list(data.get("devices") or [])
    env_host = os.environ.get("MIKROTIK_HOST")
    env_user = os.environ.get("MIKROTIK_USER")
    env_pass = os.environ.get("MIKROTIK_PASSWORD")
    if env_host and env_user and env_pass:
        devices.append(
            {
                "name": os.environ.get("MIKROTIK_NAME") or env_host,
                "host": env_host,
                "user": env_user,
                "password": env_pass,
                "port": int(os.environ.get("MIKROTIK_PORT") or 8728),
                "tls": (os.environ.get("MIKROTIK_TLS") or "").lower()
                in ("1", "true", "yes"),
                "default": True,
            }
        )
    return devices


def save_devices(devices):
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = CONFIG_PATH.with_suffix(".json.tmp")
    tmp.write_text(
        json.dumps({"devices": devices}, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    tmp.replace(CONFIG_PATH)
    try:
        os.chmod(CONFIG_PATH, 0o600)
    except OSError:
        pass


def pick_device(name=None):
    devices = load_devices()
    if not devices:
        raise MtError(
            f"no routers configured: fill in {CONFIG_PATH} "
            "(python mikrotik_mcp.py setup --host ... --user ...)"
        )
    if name:
        for dev in devices:
            if dev.get("name") == name:
                return dev
        known = ", ".join(d.get("name", "?") for d in devices)
        raise MtError(f"no router named '{name}'. Known routers: {known}")
    for dev in devices:
        if dev.get("default"):
            return dev
    return devices[0]


# ---------------------------------------------------------------- API protocol


def encode_length(n):
    if n < 0x80:
        return bytes([n])
    if n < 0x4000:
        return (n | 0x8000).to_bytes(2, "big")
    if n < 0x200000:
        return (n | 0xC00000).to_bytes(3, "big")
    if n < 0x10000000:
        return (n | 0xE0000000).to_bytes(4, "big")
    return b"\xf0" + n.to_bytes(4, "big")


class ApiConn:
    """A single connection to a router: login, talk, close."""

    def __init__(self, host, port, use_tls, timeout):
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
        except OSError as exc:
            raise MtError(
                f"cannot connect to {host}:{port} ({exc}). "
                "Check that the api service is enabled: /ip service print"
            )
        if use_tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            # by default RouterOS serves api-ssl with anonymous DH, which a normal client rejects
            for ciphers in ("ALL:@SECLEVEL=0", "ADH:@SECLEVEL=0", "DEFAULT"):
                try:
                    ctx.set_ciphers(ciphers)
                    break
                except ssl.SSLError:
                    continue
            try:
                sock = ctx.wrap_socket(sock)
            except ssl.SSLError as exc:
                raise MtError(f"TLS to {host}:{port} failed: {exc}")
        sock.settimeout(timeout)
        self.sock = sock
        self.buf = b""

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass

    # --- low level

    def _recv_exact(self, n):
        while len(self.buf) < n:
            try:
                chunk = self.sock.recv(max(4096, n - len(self.buf)))
            except socket.timeout:
                raise MtError("router did not respond in time")
            if not chunk:
                raise MtError("router closed the connection")
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def _read_length(self):
        first = self._recv_exact(1)[0]
        if first & 0x80 == 0:
            return first
        if first & 0xC0 == 0x80:
            return ((first & ~0xC0) << 8) + self._recv_exact(1)[0]
        if first & 0xE0 == 0xC0:
            rest = self._recv_exact(2)
            return ((first & ~0xE0) << 16) + (rest[0] << 8) + rest[1]
        if first & 0xF0 == 0xE0:
            rest = self._recv_exact(3)
            return ((first & ~0xF0) << 24) + (rest[0] << 16) + (rest[1] << 8) + rest[2]
        if first == 0xF0:
            return int.from_bytes(self._recv_exact(4), "big")
        raise MtError(f"unknown length prefix: {first:#x}")

    def _write_word(self, word):
        data = word.encode("utf-8") if isinstance(word, str) else word
        self.sock.sendall(encode_length(len(data)) + data)

    def _read_word(self):
        length = self._read_length()
        if length == 0:
            return None
        return self._recv_exact(length).decode("utf-8", "replace")

    def send_sentence(self, words):
        for word in words:
            self._write_word(word)
        self._write_word(b"")  # an empty word terminates the sentence

    def read_sentence(self):
        words = []
        while True:
            word = self._read_word()
            if word is None:
                return words
            words.append(word)

    # --- command level

    def talk(self, words, read_timeout=None):
        """Send a command and collect the reply up to !done / !fatal."""
        if read_timeout:
            self.sock.settimeout(read_timeout)
        self.send_sentence(words)
        replies = []
        while True:
            sentence = self.read_sentence()
            if not sentence:
                continue
            kind, attrs = sentence[0], parse_words(sentence[1:])
            if kind == "!re":
                replies.append(attrs)
            elif kind == "!done":
                if attrs:
                    replies.append(attrs)
                return replies
            elif kind == "!trap":
                raise MtError(
                    "router rejected the command: "
                    + (attrs.get("message") or json.dumps(attrs, ensure_ascii=False))
                )
            elif kind == "!fatal":
                raise MtError(
                    "router dropped the session: "
                    + (attrs.get("message") or " ".join(sentence[1:]) or "no reason given")
                )
            else:
                replies.append({"_raw": " ".join(sentence)})

    def login(self, user, password):
        # 6.43+ accepts the password directly; older versions reply !done with =ret= and expect an MD5 response
        replies = self.talk(["/login", f"=name={user}", f"=password={password}"])
        challenge = None
        for attrs in replies:
            if attrs.get("ret"):
                challenge = attrs["ret"]
        if not challenge:
            return "plain"
        digest = hashlib.md5(
            b"\x00" + password.encode("utf-8") + bytes.fromhex(challenge)
        ).hexdigest()
        self.talk(["/login", f"=name={user}", f"=response=00{digest}"])
        return "legacy-md5"


def parse_words(words):
    attrs = {}
    for word in words:
        if word.startswith("="):
            key, _, value = word[1:].partition("=")
            attrs[key] = value
        elif word.startswith("."):
            key, _, value = word[1:].partition("=")
            attrs["." + key] = value
        else:
            attrs.setdefault("_flags", []).append(word)
    return attrs


def connect(dev):
    conn = ApiConn(
        dev["host"],
        int(dev.get("port") or 8728),
        bool(dev.get("tls")),
        TIMEOUT,
    )
    try:
        conn.login(dev["user"], dev.get("password") or "")
    except MtError:
        conn.close()
        raise
    return conn


def run(dev, words, read_timeout=None):
    conn = connect(dev)
    try:
        return conn.talk(words, read_timeout=read_timeout)
    finally:
        conn.close()


# ---------------------------------------------------------------- output


def check_write(command, words=()):
    verb = command.rstrip("/").rsplit("/", 1)[-1]
    # "export file=..." writes a file on the router, so it is not read-only
    writes_file = verb == "export" and any(w.lstrip("=").startswith("file=") for w in words)
    if verb in READ_VERBS and not writes_file:
        return
    if not ALLOW_WRITE:
        raise MtError(
            f"command '{command}' changes the router, but the server was started without MIKROTIK_ALLOW_WRITE=true. "
            "Read-only commands only (print/get/export/ping/traceroute)."
        )


def clip(text, limit=None):
    limit = limit or MAX_CHARS
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n... truncated, {len(text)} characters in total"


def format_replies(replies, max_chars=None):
    if not replies:
        return "(empty reply, command completed)"
    lines = []
    for idx, attrs in enumerate(replies, 1):
        if "_raw" in attrs:
            lines.append(attrs["_raw"])
            continue
        flags = attrs.pop("_flags", None)
        head = f"--- {idx}"
        if flags:
            head += " [" + " ".join(flags) + "]"
        lines.append(head)
        for key, value in attrs.items():
            lines.append(f"  {key}: {value}")
    return clip("\n".join(lines), max_chars)


def build_words(command, extra):
    if not command.startswith("/"):
        command = "/" + command
    command = command.replace(" ", "/")
    words = [command]
    for word in extra or []:
        word = str(word)
        if word[:1] in ("=", "?", "."):
            words.append(word)
        else:  # convenience: turn key=value into =key=value
            words.append("=" + word)
    return words


# ---------------------------------------------------------------- tools


def t_list_devices(args):
    devices = load_devices()
    if not devices:
        return f"No routers. Config: {CONFIG_PATH}"
    lines = [f"Config: {CONFIG_PATH}", f"Configuration changes: {'allowed' if ALLOW_WRITE else 'disabled'}", ""]
    for dev in devices:
        mark = " (default)" if dev.get("default") else ""
        proto = "api-ssl" if dev.get("tls") else "api"
        lines.append(
            f"- {dev.get('name')}{mark}: {dev.get('host')}:{dev.get('port') or 8728} "
            f"[{proto}] user {dev.get('user')}"
        )
    return "\n".join(lines)


def t_system_info(args):
    dev = pick_device(args.get("device"))
    out = [f"Router {dev['name']} ({dev['host']})"]
    for title, cmd in (
        ("identity", "/system/identity/print"),
        ("resource", "/system/resource/print"),
        ("routerboard", "/system/routerboard/print"),
    ):
        try:
            replies = run(dev, [cmd])
            out.append(f"\n=== {title} ===")
            out.append(format_replies(replies, 4000))
        except MtError as exc:
            out.append(f"\n=== {title} ===\n{exc}")
    return clip("\n".join(out), args.get("max_chars"))


def t_cmd(args):
    command = (args.get("command") or "").strip()
    if not command:
        raise MtError("the command parameter is required, for example /ip/route/print")
    check_write(command, args.get("words") or ())
    dev = pick_device(args.get("device"))
    words = build_words(command, args.get("words"))
    replies = run(dev, words, read_timeout=args.get("timeout"))
    head = f"{dev['name']}: {' '.join(words)}\n"
    return head + format_replies(replies, args.get("max_chars"))


def t_ping(args):
    address = (args.get("address") or "").strip()
    if not address:
        raise MtError("the address parameter is required")
    dev = pick_device(args.get("device"))
    count = int(args.get("count") or 4)
    words = ["/ping", f"=address={address}", f"=count={count}"]
    if args.get("source"):
        words.append(f"=src-address={args['source']}")
    if args.get("interface"):
        words.append(f"=interface={args['interface']}")
    if args.get("size"):
        words.append(f"=size={int(args['size'])}")
    replies = run(dev, words, read_timeout=max(TIMEOUT, count * 2 + 10))

    sent = received = 0
    times = []
    notes = []
    for attrs in replies:
        if attrs.get("sent"):
            sent = max(sent, int(attrs["sent"]))
        if attrs.get("received"):
            received = max(received, int(attrs["received"]))
        if attrs.get("time"):
            times.append(attrs["time"])
        for key in ("status", "message"):
            if attrs.get(key) and attrs[key] not in notes:
                notes.append(attrs[key])
    lines = [f"{dev['name']} -> ping {address}: sent {sent}, received {received}"]
    if times:
        lines.append("times: " + ", ".join(times))
    if notes:
        lines.append("status: " + "; ".join(notes))
    if not sent and not received:
        lines.append(format_replies(replies, 3000))
    return "\n".join(lines)


def t_traceroute(args):
    address = (args.get("address") or "").strip()
    if not address:
        raise MtError("the address parameter is required")
    dev = pick_device(args.get("device"))
    count = int(args.get("count") or 1)
    words = ["/tool/traceroute", f"=address={address}", f"=count={count}"]
    if args.get("source"):
        words.append(f"=src-address={args['source']}")
    replies = run(dev, words, read_timeout=max(TIMEOUT, 45))
    hops = []
    for attrs in replies:
        addr = attrs.get("address") or "*"
        status = attrs.get("status") or ""
        avg = attrs.get("avg") or attrs.get("last") or ""
        loss = attrs.get("loss") or ""
        if addr == "*" and not status:
            continue
        hops.append(f"  {addr:<18} avg={avg:<8} loss={loss:<5} {status}".rstrip())
    head = f"{dev['name']} -> traceroute {address}\n"
    return clip(head + ("\n".join(hops) if hops else format_replies(replies, 3000)),
                args.get("max_chars"))


def t_routes(args):
    dev = pick_device(args.get("device"))
    words = ["/ip/route/print"]
    if args.get("dst"):
        words.append(f"?dst-address={args['dst']}")
    replies = run(dev, words)
    lines = []
    for attrs in replies:
        flags = " ".join(attrs.get("_flags") or [])
        active = "A" if attrs.get("active") == "true" else " "
        dyn = "D" if attrs.get("dynamic") == "true" else " "
        dis = "X" if attrs.get("disabled") == "true" else " "
        lines.append(
            f"  {active}{dyn}{dis} {attrs.get('dst-address', '?'):<20} "
            f"gw={attrs.get('gateway', '-'):<18} dist={attrs.get('distance', '-'):<4} "
            f"if={attrs.get('immediate-gw') or attrs.get('gateway-status') or '-'} {flags}".rstrip()
        )
    head = f"{dev['name']}: routes (A=active D=dynamic X=disabled), {len(replies)} in total\n"
    return clip(head + "\n".join(lines), args.get("max_chars"))


def t_firewall(args):
    dev = pick_device(args.get("device"))
    table = (args.get("table") or "filter").strip()
    if table not in ("filter", "nat", "mangle", "raw"):
        raise MtError("table must be filter, nat, mangle or raw")
    words = [f"/ip/firewall/{table}/print"]
    if args.get("chain"):
        words.append(f"?chain={args['chain']}")
    replies = run(dev, words)
    lines = []
    skip = {".id", "bytes", "packets", "invalid", "dynamic"}
    for idx, attrs in enumerate(replies):
        flags = " ".join(attrs.get("_flags") or [])
        parts = [
            f"{key}={value}"
            for key, value in attrs.items()
            if key not in skip and not key.startswith("_")
        ]
        lines.append(f"  {idx}: " + " ".join(parts) + (f"  [{flags}]" if flags else ""))
    head = f"{dev['name']}: /ip/firewall/{table}, {len(replies)} rules\n"
    return clip(head + "\n".join(lines), args.get("max_chars"))


# sections that are enough to understand and restore the routing setup
BACKUP_SECTIONS = [
    "/system/identity/print",
    "/system/resource/print",
    "/interface/print",
    "/ip/address/print",
    "/ip/route/print",
    "/ip/firewall/filter/print",
    "/ip/firewall/nat/print",
    "/ip/firewall/mangle/print",
    "/ip/dhcp-server/print",
    "/ip/dhcp-server/network/print",
    "/ip/dhcp-server/lease/print",
    "/ip/pool/print",
    "/ip/service/print",
    "/ip/dns/print",
    "/interface/vlan/print",
    "/interface/bridge/print",
    "/interface/bridge/port/print",
    "/ip/arp/print",
    "/user/print",
]


def t_backup(args):
    dev = pick_device(args.get("device"))
    conn = connect(dev)
    chunks = []
    try:
        for cmd in BACKUP_SECTIONS:
            try:
                replies = conn.talk([cmd])
                chunks.append(f"\n########## {cmd} ##########\n" + format_replies(replies, 200000))
            except MtError as exc:
                chunks.append(f"\n########## {cmd} ##########\n(error: {exc})")
    finally:
        conn.close()
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    path = BACKUP_DIR / f"{dev['name']}-{time.strftime('%Y%m%d-%H%M%S')}.txt"
    text = f"# MikroTik {dev['name']} ({dev['host']}) {time.strftime('%Y-%m-%d %H:%M:%S')}\n" + "".join(chunks)
    path.write_text(text, encoding="utf-8")
    return f"Configuration snapshot of {dev['name']} saved: {path} ({len(text)} characters)"


DEVICE_ARG = {
    "type": "string",
    "description": "Router name from the config. Defaults to the one marked default.",
}

TOOLS = [
    {
        "name": "mt_list_devices",
        "description": "List known MikroTik routers and the write mode.",
        "inputSchema": {"type": "object", "properties": {}},
        "handler": t_list_devices,
    },
    {
        "name": "mt_system_info",
        "description": "RouterOS version, model, load, uptime (identity + resource + routerboard).",
        "inputSchema": {
            "type": "object",
            "properties": {"device": DEVICE_ARG, "max_chars": {"type": "integer"}},
        },
        "handler": t_system_info,
    },
    {
        "name": "mt_cmd",
        "description": (
            "Arbitrary RouterOS API command. command is a slash-separated path, for example "
            "/ip/route/print, /interface/print, /ip/firewall/filter/print. "
            "words are extra API words: '?dst-address=10.0.0.0/24' is a query filter, "
            "'=comment=text' is a parameter (plain 'comment=text' also works). "
            "Commands outside the read-only list (add/set/remove/...) require MIKROTIK_ALLOW_WRITE=true."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "command": {"type": "string"},
                "words": {"type": "array", "items": {"type": "string"}},
                "timeout": {"type": "number"},
                "device": DEVICE_ARG,
                "max_chars": {"type": "integer"},
            },
            "required": ["command"],
        },
        "handler": t_cmd,
    },
    {
        "name": "mt_ping",
        "description": (
            "Ping from the router. Covers what the Palo Alto XML API cannot do, "
            "useful for checking reachability of hosts behind the MikroTik. "
            "source sets the source address."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "address": {"type": "string"},
                "count": {"type": "integer"},
                "source": {"type": "string"},
                "interface": {"type": "string"},
                "size": {"type": "integer"},
                "device": DEVICE_ARG,
            },
            "required": ["address"],
        },
        "handler": t_ping,
    },
    {
        "name": "mt_traceroute",
        "description": "Traceroute from the router (/tool/traceroute).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "address": {"type": "string"},
                "count": {"type": "integer"},
                "source": {"type": "string"},
                "device": DEVICE_ARG,
                "max_chars": {"type": "integer"},
            },
            "required": ["address"],
        },
        "handler": t_traceroute,
    },
    {
        "name": "mt_routes",
        "description": "Compact routing table. dst filters by dst-address.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "dst": {"type": "string"},
                "device": DEVICE_ARG,
                "max_chars": {"type": "integer"},
            },
        },
        "handler": t_routes,
    },
    {
        "name": "mt_firewall",
        "description": "Firewall rules: table = filter|nat|mangle|raw, optional chain.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "table": {"type": "string"},
                "chain": {"type": "string"},
                "device": DEVICE_ARG,
                "max_chars": {"type": "integer"},
            },
        },
        "handler": t_firewall,
    },
    {
        "name": "mt_backup",
        "description": (
            "Save a configuration snapshot to a file (interfaces, addresses, routes, firewall, DHCP, users). "
            "Do this before any change."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {"device": DEVICE_ARG},
        },
        "handler": t_backup,
    },
]

HANDLERS = {tool["name"]: tool.pop("handler") for tool in TOOLS}


# ---------------------------------------------------------------- MCP stdio


def send(msg):
    sys.stdout.write(json.dumps(msg, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def log(msg):
    sys.stderr.write(f"[mikrotik-mcp] {msg}\n")
    sys.stderr.flush()


def handle(req):
    method = req.get("method")
    req_id = req.get("id")
    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": SERVER_INFO,
            },
        }
    if method in ("notifications/initialized", "notifications/cancelled"):
        return None
    if method == "ping":
        return {"jsonrpc": "2.0", "id": req_id, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}}
    if method == "tools/call":
        params = req.get("params") or {}
        name = params.get("name")
        args = params.get("arguments") or {}
        handler = HANDLERS.get(name)
        if not handler:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": f"no such tool: {name}"},
            }
        try:
            text = handler(args)
            is_error = False
        except MtError as exc:
            text, is_error = str(exc), True
        except Exception as exc:  # keep the whole server from crashing
            text, is_error = f"{type(exc).__name__}: {exc}", True
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {"content": [{"type": "text", "text": text}], "isError": is_error},
        }
    if req_id is None:
        return None
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32601, "message": f"method not supported: {method}"},
    }


def serve():
    log(f"started, config {CONFIG_PATH}, writes {'allowed' if ALLOW_WRITE else 'disabled'}")
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError as exc:
            log(f"bad JSON: {exc}")
            continue
        resp = handle(req)
        if resp is not None:
            send(resp)


# ---------------------------------------------------------------- CLI


def cli_setup(argv):
    import argparse
    import getpass

    ap = argparse.ArgumentParser(prog="mikrotik_mcp.py setup")
    ap.add_argument("--host", required=True)
    ap.add_argument("--user", required=True)
    ap.add_argument("--password")
    ap.add_argument("--name")
    ap.add_argument("--port", type=int, default=8728)
    ap.add_argument("--tls", action="store_true", help="use api-ssl (usually port 8729)")
    ap.add_argument("--default", action="store_true")
    args = ap.parse_args(argv)

    password = args.password or getpass.getpass(f"Password for {args.user}@{args.host}: ")
    probe = {
        "name": args.name or args.host,
        "host": args.host,
        "user": args.user,
        "password": password,
        "port": args.port,
        "tls": bool(args.tls),
    }
    conn = ApiConn(probe["host"], probe["port"], probe["tls"], TIMEOUT)
    try:
        mode = conn.login(args.user, password)
        res = conn.talk(["/system/resource/print"])
        ident = conn.talk(["/system/identity/print"])
    finally:
        conn.close()
    version = (res[0].get("version") if res else "?") or "?"
    board = (res[0].get("board-name") if res else "?") or "?"
    name = (ident[0].get("name") if ident else "?") or "?"

    devices = [d for d in load_devices() if d.get("name") != probe["name"]]
    if args.default:
        for dev in devices:
            dev.pop("default", None)
    if args.default or not devices:
        probe["default"] = True
    devices.append(probe)
    save_devices(devices)
    print(
        f"Done: '{probe['name']}' = {name}, {board}, RouterOS {version} "
        f"(login {mode}). Saved to {CONFIG_PATH}"
    )


def cli_cmd(argv):
    if len(argv) < 2:
        print("usage: cmd <router-name|-> <command> [words...]", file=sys.stderr)
        sys.exit(2)
    device = argv[0] if argv[0] != "-" else None
    print(t_cmd({"device": device, "command": argv[1], "words": argv[2:], "max_chars": 200000}))


def main():
    argv = sys.argv[1:]
    if not argv:
        serve()
        return
    cmd, rest = argv[0], argv[1:]
    try:
        if cmd == "setup":
            cli_setup(rest)
        elif cmd == "list":
            print(t_list_devices({}))
        elif cmd == "test":
            print(t_system_info({"device": rest[0] if rest else None}))
        elif cmd == "cmd":
            cli_cmd(rest)
        else:
            print(__doc__)
            sys.exit(2)
    except MtError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
