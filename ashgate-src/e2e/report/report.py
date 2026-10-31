#!/usr/bin/env python3
"""Summarize a windows-e2e run for the GitHub job summary.

usage: report.py ARTIFACTS_DIR PREVIOUS_PERF_JSON|- OUT_DIR

Reads every junit*.xml, notes.md and metrics.json under ARTIFACTS_DIR
(one folder per job artifact), writes OUT_DIR/summary.md and
OUT_DIR/perf.json (all metrics of this run), compares the metrics with the
previous run of the same kind, and checks that no artifact still carries a
credential-shaped string. Exit code 1 if such a string is found.
"""
import json
import os
import re
import sys
import xml.etree.ElementTree as ET

art, prev_path, out = sys.argv[1], sys.argv[2], sys.argv[3]
os.makedirs(out, exist_ok=True)

jobs = {}  # job -> dict(tests, failures, skipped, time, failed=[...])
notes = {"finding": [], "skipped": [], "info": []}
metrics = {}

for root, _, files in os.walk(art):
    job = os.path.relpath(root, art).split(os.sep)[0]
    for f in files:
        p = os.path.join(root, f)
        if f.startswith("junit") and f.endswith(".xml"):
            try:
                tree = ET.parse(p)
            except ET.ParseError:
                continue
            j = jobs.setdefault(job, {"tests": 0, "failures": 0, "skipped": 0, "time": 0.0, "failed": []})
            for tc in tree.iter("testcase"):
                j["tests"] += 1
                j["time"] += float(tc.get("time") or 0)
                fail = tc.find("failure")
                if fail is None:
                    fail = tc.find("error")
                if fail is not None:
                    j["failures"] += 1
                    msg = (fail.get("message") or fail.text or "").strip().splitlines()
                    j["failed"].append((tc.get("name"), msg[0][:200] if msg else ""))
                elif tc.find("skipped") is not None:
                    j["skipped"] += 1
        elif f == "notes.md":
            for line in open(p, encoding="utf-8", errors="replace"):
                m = re.match(r"- \*\*(\w+)\*\* (.*)", line.strip())
                if m:
                    notes.setdefault(m.group(1), []).append(f"{job}: {m.group(2)}")
        elif f == "metrics.json":
            try:
                for k, v in json.load(open(p, encoding="utf-8")).items():
                    metrics[k] = v
            except (ValueError, OSError):
                pass

prev = {}
if prev_path != "-" and os.path.exists(prev_path):
    try:
        prev = json.load(open(prev_path, encoding="utf-8"))
    except ValueError:
        prev = {}

json.dump(metrics, open(os.path.join(out, "perf.json"), "w"), indent=2, sort_keys=True)

# Credential-shaped strings that masking should have removed.
patterns = [
    (re.compile(rb"vless://[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}@"), "vless link with a UUID"),
    (re.compile(rb"/sub/[0-9a-f]{32}"), "subscription token"),
    (re.compile(rb"\"(?:password|localPass|pass)\"\s*:\s*\"[^\"*]{6,}\""), "password field"),
]
leaks = []
for root, _, files in os.walk(art):
    for f in files:
        if not f.lower().endswith((".log", ".txt", ".json", ".xml", ".md", ".html")):
            continue
        p = os.path.join(root, f)
        try:
            data = open(p, "rb").read()
        except OSError:
            continue
        for rx, what in patterns:
            if rx.search(data):
                leaks.append(f"{os.path.relpath(p, art)}: {what}")

lines = ["# Windows E2E", ""]
lines.append("| Job | Tests | Failed | Skipped | Time |")
lines.append("|---|---:|---:|---:|---:|")
for job in sorted(jobs):
    j = jobs[job]
    lines.append(f"| {job} | {j['tests']} | {j['failures']} | {j['skipped']} | {j['time']/60:.1f} min |")
for job in sorted(jobs):
    for name, msg in jobs[job]["failed"]:
        lines.append(f"- ❌ **{job}** `{name}`: {msg}")
lines.append("")


def fmt(v):
    if isinstance(v, (int, float)):
        return f"{v:.3g}" if abs(v) < 1000 else f"{v:.0f}"
    return str(v)


if metrics:
    lines += ["## Performance", "", "| Metric | Value | Previous | Change |", "|---|---:|---:|---:|"]
    for k in sorted(metrics):
        m = metrics[k]
        v, unit, better = m.get("value"), m.get("unit", ""), m.get("better", "")
        pv = prev.get(k, {}).get("value") if isinstance(prev.get(k), dict) else None
        change = ""
        if isinstance(pv, (int, float)) and pv:
            d = (v - pv) / abs(pv) * 100
            worse = (better == "lower" and d > 25) or (better == "higher" and d < -20)
            change = f"{d:+.0f}%" + (" ⚠️" if worse else "")
        lines.append(f"| {k} | {fmt(v)} {unit} | {fmt(pv) if pv is not None else ''} | {change} |")
    lines.append("")

for kind, title in (("finding", "Findings"), ("skipped", "Skipped (and why)"), ("info", "Notes")):
    items = sorted(set(notes.get(kind, [])))
    if items:
        lines += [f"## {title}", ""] + [f"- {i}" for i in items] + [""]

if leaks:
    lines += ["## ❌ Credential-shaped strings in artifacts", ""] + [f"- {l}" for l in leaks] + [""]

text = "\n".join(lines) + "\n"
open(os.path.join(out, "summary.md"), "w", encoding="utf-8").write(text)
print(text)
sys.exit(1 if leaks else 0)
