# heimdall-cli reference

`heimdall-cli` is the headless Heimdall Listener. Every command prints detailed help with `--help`;
this page collects all of it in one place. Nothing the tool does transmits a packet.

```
heimdall-cli [--no-color] <command> [flags]
```

| Command | Purpose |
|---|---|
| `interfaces` | List interfaces you can capture on |
| `capture` | Capture until Ctrl-C or a duration, then write files and a report |
| `diff` | Compare two run files: new, resolved, unchanged |
| `export` | Render a saved run as CSV, a remediation summary, or JSON |
| `service run` / `install` / `uninstall` | Long-running sensor with periodic snapshots |
| `version` | Version, commit and capture backend |
| `completion bash\|zsh\|fish\|powershell` | Shell completion script |

Global flag: `--no-color` disables ANSI colour (the `NO_COLOR` environment variable does the same).

## Privileges and exit codes

Capturing needs raw-socket rights: `sudo` or, better, `sudo setcap cap_net_raw,cap_net_admin+eip heimdall-cli`
on Linux (repeat after replacing the binary); an elevated prompt with Npcap installed on Windows.

| Exit status | Meaning |
|---|---|
| 0 | Finished normally |
| 1 | Error (bad arguments, unreadable file, capture failure); the message is on stderr |
| 2 | Missing capture privileges; a hint for this OS is printed |
| 3 | `capture` finished but at least one **HIGH** alert was raised (suspected poisoner or rogue DHCPv6 server) |

## interfaces

```
heimdall-cli interfaces [--all] [--json]
```

Lists usable interfaces (up, not loopback, with a routable address) as NAME, DESCRIPTION, ADDRESSES, UP.
`--all` includes loopback and address-less interfaces; `--json` prints the list as JSON. On Windows the
DESCRIPTION column is the friendly name you can pass to `-i`.

## capture

```
heimdall-cli capture -i IFACE [-i IFACE...] [-d DURATION] [-o run.json] [flags]
```

| Flag | Default | Meaning |
|---|---|---|
| `-i, --interface` | required | Interface to capture on; repeat for several. Name, or Windows friendly name |
| `-d, --duration` | 0 (until Ctrl-C) | Stop after this long, e.g. `30s`, `30m`, `2h` |
| `-o, --output` | | Write the run file (JSON). This is what `diff` and the GUI read |
| `--csv` | | Write aggregated entries as CSV |
| `--summary` | | Write the per-host remediation report (text) |
| `--summary-csv` | | Write the per-host summary as CSV |
| `-q, --quiet` | off | No live table, status lines or report. Alerts and `wrote ...` notices still print |
| `--jsonl` | off | Stream one JSON object per event to stdout (no live table); combine with `-q` for logs/SIEM |
| `--no-promisc` | off | Do not enable promiscuous mode (broadcast/multicast are still received) |
| `--filter` | the default BPF expression | libpcap filter expression; only with the libpcap backend (GUI, Windows CLI) |
| `--trusted-dhcpv6` | | Comma-separated IPv6 addresses of legitimate DHCPv6 servers; suppresses the `dhcpv6-server` alert for them |
| `--status-every` | 1m | Interval of the status line when stdout is not a terminal |

What you see while it runs:

- On a terminal: a live view redrawn every second. Top line: interfaces, backend, elapsed time. If any
  alert exists, a red framed **ALERTS** box comes next. Then counters (packets, events, hosts, kernel
  drops, decode errors, per-protocol totals) and a table of the aggregated entries sorted WPAD first,
  then most recent. Press **Ctrl-C** to stop early; results are still written.
- Not on a terminal (cron, systemd, a pipe): one status line per `--status-every` on stderr.
- With `--jsonl`: one JSON object per decoded event on stdout, fields `time`, `source_ip`, `dest_ip`,
  `source_mac`, `protocol`, `kind`, `name`, `query_type`, `answers`, `wpad`, `detail`.

When the capture ends: the remediation report is printed to stdout (unless `-q` or `--jsonl`), alert
lines are printed to stderr, requested files are written, and the exit status reflects HIGH alerts.

Stopping: `-d` elapsed, Ctrl-C, or SIGTERM (so `timeout` and service managers work).

## diff

```
heimdall-cli diff BASELINE.json CURRENT.json [-f table|json|csv] [-o FILE]
```

Compares two run files. A *pair* is one host doing one protocol as one kind (query or response).

- **NEW**: pairs present now but not in the baseline. `(new host)` marks a host absent from the baseline.
- **RESOLVED**: pairs in the baseline that are gone now. This is your proof that a remediation worked.
  `(host gone)` marks a host that vanished entirely.
- **UNCHANGED**: pairs in both; names added since the baseline are prefixed `+`, names gone `-`.
- **ALERTS**: new, cleared and persisting alerts.

The header line counts pairs, hosts and WPAD-related pairs on each side. `-f json` gives the full
structure (for tooling), `-f csv` one row per pair.

## export

```
heimdall-cli export RUN.json [-f summary|csv|summary-csv|json] [-o FILE]
```

| Format | Content |
|---|---|
| `summary` (default) | The remediation report: capture window and counters, exposure by protocol, alerts with evidence and advice, then every host with its protocols, names, WPAD involvement and the exact steps to turn each protocol off |
| `csv` | One row per aggregated entry: `source_ip, source_mac, protocol, kind, name, wpad, query_types, answers, count, first_seen, last_seen` |
| `summary-csv` | One row per host: protocols, WPAD flag, alerts, names, counts, first/last seen |
| `json` | The run file itself, re-sorted and pretty-printed |

## service

`service run` is the foreground process that systemd or the Windows Service Control Manager starts.
It keeps capturing and writes `run-<UTC stamp>.json` plus `latest.json` into `--out-dir` every
`--snapshot-interval`, pruning to `--retain` files, with a final snapshot on shutdown. Logs go to
`--log-file` (default `<out-dir>/heimdall.log`), and to stderr as well when run from a terminal.

```
heimdall-cli service run -i IFACE [flags]
heimdall-cli service install -i IFACE [flags]      # root / elevated
heimdall-cli service uninstall [--name NAME]      # root / elevated
```

| Flag (run and install) | Default | Meaning |
|---|---|---|
| `-i, --interface` | required | Interface(s) to capture on |
| `--out-dir` | `/var/lib/heimdall-listener` (Linux), `%ProgramData%\HeimdallListener` (Windows) | Snapshot directory |
| `--snapshot-interval` | 5m | How often to write a snapshot |
| `--retain` | 48 | Snapshots to keep; 0 keeps all |
| `--rollover` | 0 (cumulative) | Reset the aggregation after this long, e.g. `24h` |
| `--log-file` | `<out-dir>/heimdall.log` | Log file |
| `--no-promisc`, `--filter`, `--trusted-dhcpv6` | | As for `capture` |
| `--name` | `heimdall-listener` | Service / unit name |

`install` only:

| Flag | Meaning |
|---|---|
| `--force` | Replace an existing unit or service |
| `--exe` | Path to the binary the service should run (default: the one you are running) |
| `--unit-dir` | Linux: systemd unit directory (default `/etc/systemd/system`) |

On Linux `install` writes a hardened unit (dynamic unprivileged user, only `CAP_NET_RAW` and
`CAP_NET_ADMIN`, `ProtectSystem=strict`, state directory `/var/lib/heimdall-listener` with mode 0750)
and prints the `systemctl` commands to enable it. On Windows it creates an automatic-start service that
depends on the Npcap driver, registers an Event Log source and sets restart-on-failure. `uninstall`
removes the registration and keeps the snapshots.

## Files

Run files are JSON with `schema_version: 1`, tool and host metadata, the capture window and counters,
`entries` (one per host/protocol/kind/name with counts and timestamps) and `alerts`. They are written
atomically (temp file plus rename), so `latest.json` is always complete even while it is being replaced.
