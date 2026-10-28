# mikrotik-mcp

An MCP (Model Context Protocol) server for MikroTik RouterOS, using the native binary API
(port 8728, or api-ssl on 8729). It is a single Python file with no dependencies outside the
standard library.

## Why

AI agents such as Claude Code are useful for routine router work: reading routing tables
and firewall rules, pinging and tracing from the router itself, collecting a snapshot before
a change. They should not get unrestricted write access or see your passwords in the chat.
This server gives an agent a small, predictable set of tools:

- it is read-only unless you explicitly start it with writes enabled;
- it has a snapshot tool meant to be used before any change;
- the router password is entered in the terminal, never through the chat.

## Tools

| Tool | What it does | Writes |
|------|--------------|--------|
| `mt_list_devices` | List known MikroTik routers and the write mode. | no |
| `mt_system_info` | RouterOS version, model, load, uptime (identity + resource + routerboard). | no |
| `mt_cmd` | Arbitrary RouterOS API command, e.g. `/ip/route/print`. `words` adds query filters (`?dst-address=10.0.0.0/24`) and parameters (`=comment=text` or just `comment=text`). | only verbs outside the read list |
| `mt_ping` | Ping from the router, with optional `source`, `interface`, `size`, `count`. | no |
| `mt_traceroute` | Traceroute from the router (`/tool/traceroute`). | no |
| `mt_routes` | Compact routing table, optional `dst` filter. | no |
| `mt_firewall` | Firewall rules for `filter`, `nat`, `mangle` or `raw`, optional `chain`. | no |
| `mt_backup` | Save a configuration snapshot to a local text file (interfaces, addresses, routes, firewall, DHCP, DNS, VLANs, bridges, ARP, users). | no (local file) |

## Safety model

- **Read-only by default.** `mt_cmd` looks at the last element of the command path. Only
  `print`, `get`, `getall`, `export`, `monitor`, `monitor-traffic`, `ping`, `traceroute`,
  `resolve`, `find` and `check-installation` are allowed without
  `MIKROTIK_ALLOW_WRITE=true`. Everything else (`add`, `set`, `remove`, `enable`,
  `disable`, `reboot`, ...) is refused. `mt_list_devices` shows the current mode.
- **Snapshot first.** `mt_backup` writes the output of the key `print` commands to
  `~/.mikrotik-mcp/backups/<router>-<timestamp>.txt`. The tool description tells the agent
  to call it before any change.
- **Least privilege on the router.** Create a dedicated user. For read-only work put it in
  the built-in `read` group; then even a mistake in the client cannot change anything.
- **Secrets stay out of the chat.** `python3 mikrotik_mcp.py setup` asks for the password
  via `getpass`, logs in to verify it, and stores it in the config file (mode 0600). None of
  the tools return the password.

## Requirements

Python 3.10 or newer. No packages to install. The `api` (or `api-ssl`) service must be
enabled on the router: `/ip service print`.

## Setup

1. On the router, create a user for the agent, for example:

   ```
   /user add name=mcp group=read
   ```

   Use a group with `write` policy only if you plan to enable writes. Restricting the `api`
   service with `address=` to your management host is a good idea.

2. Add the router to the config:

   ```sh
   python3 mikrotik_mcp.py setup --host 192.0.2.1 --user mcp --name rtr1 --default
   ```

   You will be prompted for the password. Add `--tls --port 8729` for api-ssl. A
   `--password` flag exists, but it leaves the password in shell history; prefer the prompt.

3. Check it:

   ```sh
   python3 mikrotik_mcp.py list
   python3 mikrotik_mcp.py test rtr1
   python3 mikrotik_mcp.py cmd rtr1 /ip/address/print
   ```

### Config file

Default location: `~/.mikrotik-mcp/config.json` (override with `MIKROTIK_MCP_CONFIG`).
See `config.example.json`:

```json
{
  "devices": [
    {"name": "rtr1", "host": "192.0.2.1", "user": "mcp", "password": "REPLACE_WITH_PASSWORD",
     "port": 8728, "tls": false, "default": true},
    {"name": "rtr2", "host": "192.0.2.2", "user": "mcp", "password": "REPLACE_WITH_PASSWORD",
     "port": 8729, "tls": true}
  ]
}
```

### Environment variables

| Variable | Default | Meaning |
|----------|---------|---------|
| `MIKROTIK_MCP_CONFIG` | `~/.mikrotik-mcp/config.json` | Config file path |
| `MIKROTIK_ALLOW_WRITE` | unset (read-only) | `true`/`1`/`yes`/`on` allows commands that change the router |
| `MIKROTIK_BACKUP_DIR` | `<config dir>/backups` | Where `mt_backup` writes files |
| `MIKROTIK_MAX_CHARS` | `40000` | Default output truncation limit |
| `MIKROTIK_TIMEOUT` | `30` | Socket timeout, seconds |
| `MIKROTIK_HOST`, `MIKROTIK_USER`, `MIKROTIK_PASSWORD` | | Add one router from the environment instead of the config file |
| `MIKROTIK_NAME`, `MIKROTIK_PORT`, `MIKROTIK_TLS` | | Optional extras for the environment router |

## Register in Claude Code

Read-only:

```sh
claude mcp add mikrotik -- python3 /path/to/mikrotik_mcp.py
```

With writes enabled:

```sh
claude mcp add mikrotik -e MIKROTIK_ALLOW_WRITE=true -- python3 /path/to/mikrotik_mcp.py
```

Any other MCP client that speaks stdio works the same way: run `python3 mikrotik_mcp.py`
with no arguments.

## Command line

```
python3 mikrotik_mcp.py                                stdio MCP server
python3 mikrotik_mcp.py setup ...                      add a router to the config
python3 mikrotik_mcp.py list                           list known routers
python3 mikrotik_mcp.py test [name]                    identity, resource, routerboard
python3 mikrotik_mcp.py cmd <name|-> <command> [words] one-off API call ("-" = default router)
```

## Example prompts

- "What RouterOS version and uptime does rtr1 have?"
- "Show the route to 10.0.0.0/24 and ping 10.0.0.20 from source 10.0.0.1."
- "Traceroute to 198.51.100.7 from the router and tell me where it stops."
- "List the NAT rules in the srcnat chain."
- "Take a snapshot of rtr1, then add a comment `uplink` to ether1 and show the result."

## Limitations

- Each tool call opens a new API connection and logs in; there is no session reuse.
- The write gate checks the command verb. `export` is read-only, except `export file=...`,
  which writes a file on the router and therefore needs write mode.
- `mt_backup` is a readable snapshot of selected `print` output, not a RouterOS `.backup`
  or a full `/export`; it cannot be restored with one command.
- With `tls: true` the router certificate is not verified, and weak ciphers are allowed
  because RouterOS serves api-ssl with anonymous DH by default.
- Both the modern (6.43+) and the legacy MD5 challenge login are supported.
- The password is stored in plain text in the config file. Protect the file, and prefer a
  dedicated low-privilege user.

## License

MIT, see `LICENSE`.
