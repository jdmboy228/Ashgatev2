#!/usr/bin/env python3
"""Turn the unblinded measurement file into results.json and mapping.json.

results.json uses labels A/B/C only. Product names, versions and executable
names stay in mapping.json and in the raw file.
"""

from __future__ import annotations

import argparse
import json
import random
import re
import statistics
from pathlib import Path

_IDENTIFYING = re.compile(r"ashgate|sing-box|singbox|v2rayn|xray\.exe|windivert", re.IGNORECASE)


def median(values: list[float]) -> float:
    return statistics.median(values)


def as_list(value):
    """PowerShell's JSON encoder unwraps a one-element array."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def summarize_transport(rounds: list[dict]) -> dict:
    measured = [r for r in rounds if r.get("status") == "measured"]
    if not measured:
        status = rounds[-1].get("status", "error") if rounds else "error"
        reason = ""
        for r in rounds:
            if r.get("reason"):
                reason = r["reason"]
            if r.get("error"):
                reason = r["error"]
        out = {"status": status, "rounds": rounds}
        if reason:
            out["reason"] = reason
        return out
    summary: dict = {"rounds_measured": len(measured), "rounds_total": len(rounds)}
    keys = set()
    for r in measured:
        keys.update(r.keys())
    for key in sorted(keys):
        if key in {"status", "actions", "error", "reason", "transport"}:
            continue
        vals = [r.get(key) for r in measured if key in r and r.get(key) is not None]
        if not vals:
            continue
        if all(isinstance(v, bool) for v in vals):
            summary[key] = {"true": sum(1 for v in vals if v), "false": sum(1 for v in vals if not v)}
        elif all(isinstance(v, (int, float)) and not isinstance(v, bool) for v in vals):
            summary[key] = {"median": median([float(v) for v in vals]), "min": min(vals), "max": max(vals)}
    return {"status": "measured", "summary": summary, "rounds": rounds}


def classify_path(path: str) -> str:
    name = path.replace("\\", "/").rsplit("/", 1)[-1].lower()
    if name.endswith(".db") or name.endswith(".sqlite"):
        return "database"
    if name.endswith(".log") or name.endswith(".txt"):
        return "log"
    if name.endswith(".json") or name.endswith(".conf") or name.endswith(".yml"):
        return "config"
    return "other"


def blind_secrets(rows: list[dict]) -> dict:
    kinds = {"uuid": False, "reality_public": False, "reality_private": False, "short_id": False}
    locations = set()
    for row in rows or []:
        locations.add(classify_path(row.get("path", "")))
        for kind in row.get("kinds") or []:
            if kind in kinds:
                kinds[kind] = True
    return {
        "plaintext_uuid": kinds["uuid"],
        "plaintext_reality_public": kinds["reality_public"],
        "plaintext_reality_private": kinds["reality_private"],
        "plaintext_short_id": kinds["short_id"],
        "file_count": len(rows or []),
        "location_kinds": sorted(locations),
    }


def blind_ports(rows: list[dict]) -> list[dict]:
    out = []
    for row in rows or []:
        out.append(
            {
                "proto": row.get("proto"),
                "local": row.get("local"),
                "role": row.get("role") or "child",
            }
        )
    return out


def scrub(value):
    if isinstance(value, str):
        return _IDENTIFYING.sub("client", value)
    if isinstance(value, list):
        return [scrub(v) for v in value]
    if isinstance(value, dict):
        return {k: scrub(v) for k, v in value.items()}
    return value


def build(doc: dict) -> tuple[dict, dict]:
    tool_ids = list(doc["tools"].keys())
    labels = ["A", "B", "C"][: len(tool_ids)]
    rng = random.SystemRandom()
    rng.shuffle(tool_ids)
    assigned = dict(zip(labels, tool_ids))
    label_of = {tool: label for label, tool in assigned.items()}

    mapping = {
        "labels": {},
        "server": doc.get("server") or {},
        "note": "Labels were assigned at random for this run. results.json does not contain product names.",
    }
    for label, tool in assigned.items():
        meta = dict(doc["tools"][tool])
        meta["id"] = tool
        mapping["labels"][label] = meta

    clients = {}
    rounds = as_list(doc.get("rounds"))
    for rnd in rounds:
        rnd["order"] = as_list(rnd.get("order"))
    for tool, label in label_of.items():
        transports: dict = {}
        by_transport: dict[str, list] = {}
        for rnd in rounds:
            block = ((rnd.get("by_tool") or {}).get(tool) or {}).get("transports") or {}
            for name, metrics in block.items():
                if isinstance(metrics, dict) and "actions" in metrics:
                    metrics["actions"] = as_list(metrics.get("actions"))
                by_transport.setdefault(name, []).append(metrics)
        for name, series in by_transport.items():
            transports[name] = summarize_transport(series)
        once = (doc.get("once") or {}).get(tool) or {}
        clients[label] = {
            "transports": transports,
            "kill_switch": once.get("kill_switch") or {"status": "missing"},
            "failover": once.get("failover") or {"status": "missing"},
            "soak": blind_soak(once.get("soak")),
            "secrets_on_disk": blind_secrets(as_list(once.get("secrets"))),
            "listen_ports": blind_ports(as_list(once.get("ports"))),
            "actions": as_list(once.get("actions")),
        }
    results = {
        "schema": 1,
        "blind": True,
        "runner": doc.get("runner") or {},
        "scenario": doc.get("scenario") or {},
        "metrics": metric_notes(),
        "round_order": [[label_of[t] for t in rnd.get("order") or []] for rnd in rounds],
        "clients": scrub(clients),
    }
    return results, mapping


def blind_soak(soak: dict | None) -> dict:
    if not soak:
        return {"status": "missing"}
    out = {k: v for k, v in soak.items() if k != "samples"}
    samples = as_list(soak.get("samples"))
    out["sample_count"] = len(samples)
    if samples:
        out["samples"] = [
            {
                "t_seconds": s.get("t_seconds"),
                "private_mb": s.get("private_mb"),
                "working_set_mb": s.get("working_set_mb"),
            }
            for s in samples
        ]
    return out


def metric_notes() -> dict:
    return {
        "dns_tunnel_packets": "Packets on the physical NIC whose DNS query name is the unique non-bypass name. Counted from pktmon via a pcapng parse. Zero means that name was not seen in plaintext outside the machine.",
        "dns_bypass_packets": "Same capture method for a unique name under .ru. A bypass that works shows this query on the NIC.",
        "ipv4_leak_packets": "NIC packets to or from 198.51.100.0/24 while the proxied app requested 198.51.100.10. The lab answers that address only through the tunnel, so a packet on the NIC left the tunnel.",
        "ipv6_leak_packets": "NIC packets to or from 2001:db8:2::/48 during the proxied app's IPv6 request.",
        "control_leak_packets": "NIC packets for the same address range while a second copy of the workload, with a different file name and no rule, makes the same request. This is the 'everyone else stays direct' check.",
        "probe_ok": "The workload got the expected response. It is the application, not the proxy, reporting success.",
        "disconnect_leak_packets": "NIC packets for the documentation range after the lab resets the server port and the client process is still running.",
        "throughput": "The workload transfers for a fixed number of seconds. Megabits per second is bytes over wall time. CPU seconds per 100 MB is the client process tree's processor time over that window, scaled to 100 MB. Private MB is the tree's private bytes at the end of the window, not divided by bytes.",
        "latency_ms": "Twenty new connections, each a one-byte HTTP ping through the tunnel. Median and p95 are taken from the samples that succeeded.",
        "launch_to_first_response_seconds": "Wall time from the client process start that is meant to connect until the workload's first successful ping.",
        "kill_switch": "If the client documents a kill switch, it is turned on for this phase only. Crash kills the root process, then the whole tree, and the workload tries the documentation address again. A client without the feature is marked unsupported; the same crash is still observed on its ordinary configuration.",
        "failover": "Supported only when the client can prefer XHTTP and fall back to RAW+Reality. The lab then resets the XHTTP port. switched requires the RAW port to receive a new forwarded connection and the workload to succeed.",
        "soak": "One sample of private bytes and working set, about every 30 seconds, while the workload pings every 15 seconds. Not repeated inside every round.",
        "secrets_on_disk": "Files under the client's own data directories were searched for this run's UUID and Reality material. results.json records which kinds were stored in plaintext and the kind of file, not the path or the secret.",
        "listen_ports": "TCP and UDP listeners owned by the client process tree after the first successful connect. Executable names are omitted here.",
        "actions": "User-equivalent steps the adapter performed before the connecting process was started. Names of products are not included.",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("measurements")
    parser.add_argument("--results", required=True)
    parser.add_argument("--mapping", required=True)
    args = parser.parse_args()
    doc = json.loads(Path(args.measurements).read_text(encoding="utf-8"))
    results, mapping = build(doc)
    Path(args.results).write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    Path(args.mapping).write_text(json.dumps(mapping, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {args.results} and {args.mapping}")


if __name__ == "__main__":
    main()
