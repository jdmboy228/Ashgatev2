# External client comparison

This directory is a blind, external benchmark. It compares the Ashgate build in
this checkout with pinned official Windows builds of sing-box and v2rayN.
It does not change Ashgate, and it does not score Ashgate from Ashgate's API,
logs, or test helpers.

The workflow is manual: `.github/workflows/compare.yml` runs only on
`workflow_dispatch`.

## Clients

| Client | Build | Why it is included |
| --- | --- | --- |
| Ashgate | This repository, installed from `Setup.exe` | The client under test. |
| sing-box 1.14.4 | `SagerNet/sing-box` `sing-box-1.14.4-windows-amd64.zip` | Official command-line client. Route rules can name one process. VLESS and REALITY are supported. XHTTP is not in this version, so that transport is recorded as unsupported. |
| v2rayN 7.25.6 | `2dust/v2rayN` `v2rayN-windows-64.zip` | Widely used Windows client. It ships Xray, so it speaks XHTTP and RAW+REALITY, and its TUN mode can route by process name. A Fallback policy group is its documented multi-server failover. |

Hiddify's Windows build was not included. Its own issue tracker still treats
per-process routing on Windows as unavailable, so it cannot apply the same
"one application" rule without a third-party tool.

Every zip is pinned by URL and SHA-256 in `VERSIONS.json`. The runner checks
the hash before it unpacks the zip. The Xray hash also matches the publisher's
`.dgst` file for `v26.10.31`.

## Server

The lab starts official Xray `v26.10.31` on the runner. Keys, UUIDs and the
short id are generated in the job. Nothing dials a real server. Two inbounds
share one REALITY identity:

- VLESS + XHTTP + REALITY
- VLESS + RAW + REALITY + Vision

A local TCP gate sits in front of each inbound so the runner can reset or
black-hole that port. Documentation addresses `198.51.100.0/24` and
`2001:db8:2::/48` are redirected to a local HTTP echo. A few well-known
connectivity host names answer HTTP 204 locally, so a health check has
something to reach without using the public internet. Everything else is
black-holed.

Before any client runs, the lab dials both inbounds with Xray itself. If that
self-test fails, the job fails. A client that cannot connect is recorded; it
is not treated as a broken harness unless no client that should support the
transport ever connects.

## The same rule and the same workload

`rules.json` is the bypass list: the zones `.ru`, `.su` and `.рф`, plus the
usual Russian service names (state services, banks, Yandex, VK, MAX). Each
client expresses that list in its own configuration format.

One copy of the workload, `compare-probe.exe`, is the proxied application.
`compare-control.exe` is the same program under another file name and has no
rule. The workload opens its own sockets and ignores `HTTP_PROXY`.

Ashgate is given a normal config file and started with `ashgate --autostart`,
which is the documented way to run capture. sing-box is given a TUN config
with `process_name` rules, `auto_route` and `strict_route`, as its TUN
documentation describes for Windows. v2rayN is started so it creates its own
database, then the profile, TUN switch and routing rows are written the way
that database stores an imported server and a per-app rule. System proxy is
left unchanged. v2rayN's own notes say process rules require TUN.

Client order is shuffled on every round. The runner CPU, OS and logical
processor count are stored with the results.

## What is measured

Packet counts come from `pktmon` on the physical NIC, converted to pcapng and
reduced to the documentation ranges and the unique DNS names. Loopback traffic
to the lab is not on that NIC. The workload's own success or failure is the
other half of each check.

| Field | Meaning |
| --- | --- |
| `dns_*_tunnel_packets` | Plaintext DNS on the NIC for a unique name that is not on the bypass list. |
| `dns_lookup_bypass_packets` | Plaintext DNS on the NIC for a unique `.ru` name. A working bypass shows this query. |
| `ipv4_leak_packets` / `ipv6_leak_packets` | NIC packets for the documentation address while the proxied workload talks to it. |
| `control_leak_packets` | The same kind of packets while the unruly copy talks to the documentation address. |
| `*_probe_ok` | The workload received the answer it expected. |
| `disconnect_*` | The lab resets the server port while the client is still running. |
| `down_*` / `up_*` | A fixed-length transfer. Speed is megabytes per second. CPU is the client process tree's processor time, scaled to 100 MB. Private MB is the tree's private bytes at the end of the window, not divided by the byte count. |
| `latency_median_ms` / `latency_p95_ms` | Twenty new connections, each a one-request HTTP ping. |
| `launch_to_first_response_seconds` | From the process start that should connect until the first successful ping. |
| `actions` | The user-equivalent steps taken before that process starts. |
| `kill_switch` | Ashgate's switch is turned on for this phase only. Other clients have no documented kill switch; the phase is `unsupported` and the crash is still observed on the ordinary configuration. Crash kills the root process, then the whole tree. |
| `failover` | Only when the client can prefer XHTTP and fall back to RAW. The lab then resets XHTTP. `switched` requires a new forwarded connection on RAW and a successful ping. sing-box is `unsupported` here because it cannot speak XHTTP. |
| `soak` | Private bytes and working set about every 30 seconds, with a ping every 15 seconds, once per client on its primary transport. |
| `secrets_on_disk` | Whether this run's UUID and REALITY material were stored in plaintext, and whether that file is a config, log, database, or something else. |
| `listen_ports` | TCP listeners, and UDP ports below the ephemeral range, owned by the client process tree. |

`results.json` uses labels A, B and C. `mapping.json` is the only file that
says which label is which product. Names, versions and executable names are
removed from `results.json`. Full paths and the unblinded measurements are
under `raw/` for debugging. The private key is not uploaded.

Short measurements repeat for every round. The kill-switch phase, failover and
the 10-minute sample run once per client, after the rounds, in a fresh random
order. Repeating the 10-minute sample inside every round would only rerun the
same condition.

## Known limits

- The server is on the same machine as the clients, so throughput and latency
  are not wide-area numbers. They are comparable with each other.
- Bypass is observed as DNS for a `.ru` name, not as a completed request to a
  Russian site. The lab does not host one.
- Ashgate's failover timer is the product's own (on the order of a minute or
  more). The runner waits up to 200 seconds and records whether traffic moved.
- v2rayN is driven through the files the application writes, not by clicking
  its window. The first launch is the application creating those files.
- sing-box 1.14.4 has no XHTTP. That is recorded as unsupported, including
  XHTTP-to-RAW failover.
- Secret file paths and process names identify the product, so the blind file
  keeps only the kind of file and the role of the listening process.
- The GitHub Actions log names the clients so a failed run can be fixed. The
  blind artifact does not.
- RAM is reported as a level. Dividing it by bytes transferred would make a
  faster client look lighter without the footprint changing, so that ratio is
  not the RAM figure.
