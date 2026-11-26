#!/usr/bin/env python3
"""Write one client's configuration for the shared lab.

The commands follow each client's own documented configuration. They do not
score anything. Exit code 3 means the requested transport is unsupported.
"""

from __future__ import annotations

import argparse
import base64
import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse


def load_json(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def suffixes(rules: dict) -> list[str]:
    out = ["." + z for z in rules["zones_ascii"]]
    out += ["." + d for d in rules["domains"]]
    return out


def direct_domains(rules: dict) -> list[str]:
    return list(rules["zones_unicode"]) + list(rules["domains"])


def xray_domains(rules: dict) -> list[str]:
    return [f"domain:{z}" for z in rules["zones_ascii"]] + [f"domain:{d}" for d in rules["domains"]]


def endpoint(lab: dict, transport: str) -> dict:
    if transport == "xhttp":
        return lab["xhttp"]
    if transport == "raw":
        return lab["raw"]
    raise SystemExit(f"unknown transport {transport}")


def write(path: str, doc: dict) -> None:
    Path(path).write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(path)


def subscription_payload(url: str, links: list[str]) -> bytes:
    return json.dumps({"url": url, "links": links}, separators=(",", ":")).encode()


def seal_subscription(url: str, links: list[str]) -> str:
    """DPAPI blob Ashgate stores in config.json after a subscription is added."""
    if sys.platform != "win32":
        raise SystemExit("sealing a subscription requires Windows DPAPI")
    import ctypes
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]

    def blob(data: bytes):
        buf = ctypes.create_string_buffer(data, len(data))
        item = DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_byte)))
        return item, buf

    plain = subscription_payload(url, links)
    entropy = b"ashgate/subscription/v1"
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    crypt32.CryptProtectData.argtypes = [
        ctypes.POINTER(DATA_BLOB),
        wintypes.LPCWSTR,
        ctypes.POINTER(DATA_BLOB),
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(DATA_BLOB),
    ]
    crypt32.CryptProtectData.restype = wintypes.BOOL
    src, src_buf = blob(plain)
    ent, ent_buf = blob(entropy)
    out = DATA_BLOB()
    if not crypt32.CryptProtectData(ctypes.byref(src), None, ctypes.byref(ent), None, None, 0x01, ctypes.byref(out)):
        raise ctypes.WinError()
    try:
        protected = ctypes.string_at(out.pbData, out.cbData)
    finally:
        kernel32.LocalFree(ctypes.cast(out.pbData, ctypes.c_void_p))
    del src_buf, ent_buf
    return "dpapi:" + base64.b64encode(protected).decode("ascii")


def cmd_ashgate(args: argparse.Namespace) -> None:
    lab = load_json(args.lab)
    rules = load_json(args.rules)
    if args.mode == "failover":
        host = urlparse(lab["subscriptionUrl"]).netloc
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        sealed = seal_subscription(lab["subscriptionUrl"], [lab["raw"]["link"], lab["xhttp"]["link"]])
        proxy = {
            "name": "bench",
            "type": "vless",
            "subscription": {
                "sealed": sealed,
                "count": 2,
                "host": host,
                "updatedAt": now,
                "checkedAt": now,
            },
        }
    else:
        ep = endpoint(lab, args.transport)
        proxy = {
            "name": "bench",
            "type": "vless",
            "address": f"{ep['host']}:{ep['port']}",
            "link": ep["link"],
        }
    doc = {
        "version": 1,
        "revision": 1,
        "killSwitch": args.kill_switch == "true",
        "directDomains": direct_domains(rules),
        "proxies": [proxy],
        "rules": [
            {
                "enabled": True,
                "process": args.probe,
                "action": "proxy",
                "proxy": "bench",
            }
        ],
    }
    write(args.out, doc)


def cmd_singbox(args: argparse.Namespace) -> None:
    if args.transport != "raw":
        print("unsupported: this build has no XHTTP transport", file=sys.stderr)
        raise SystemExit(3)
    lab = load_json(args.lab)
    rules = load_json(args.rules)
    ep = endpoint(lab, "raw")
    names = [args.probe_name]
    if args.probe_name.lower().endswith(".exe"):
        names.append(args.probe_name[:-4])
    suf = suffixes(rules)
    doc = {
        "log": {"level": "info", "timestamp": True, "output": args.log},
        "dns": {
            "servers": [
                {"type": "udp", "tag": "remote", "server": "1.1.1.1", "server_port": 53, "detour": "proxy"},
                {"type": "local", "tag": "local"},
            ],
            "rules": [
                {"domain_suffix": suf, "server": "local"},
                {"process_name": names, "server": "remote"},
            ],
            "final": "local",
            "strategy": "prefer_ipv4",
        },
        "inbounds": [
            {
                "type": "tun",
                "tag": "tun-in",
                "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
                "auto_route": True,
                "strict_route": True,
                "stack": "mixed",
                # The lab server is on loopback. Windows TUN will capture that
                # address unless it is excluded, and the handshake then sees
                # the wrong certificate.
                "route_exclude_address": ["127.0.0.0/8", "::1/128"],
            }
        ],
        "outbounds": [
            {
                "type": "vless",
                "tag": "proxy",
                "server": ep["host"],
                "server_port": ep["port"],
                "uuid": ep["uuid"],
                "flow": "xtls-rprx-vision",
                "packet_encoding": "xudp",
                "tls": {
                    "enabled": True,
                    "server_name": lab["sni"],
                    "utls": {"enabled": True, "fingerprint": lab["fingerprint"]},
                    "reality": {
                        "enabled": True,
                        "public_key": lab["realityPublicKey"],
                        "short_id": lab["shortId"],
                    },
                },
            },
            {"type": "direct", "tag": "direct"},
        ],
        "route": {
            "auto_detect_interface": True,
            "default_domain_resolver": "local",
            "final": "direct",
            "rules": [
                {"action": "sniff"},
                {"protocol": "dns", "action": "hijack-dns"},
                {"domain_suffix": suf, "action": "route", "outbound": "direct"},
                {"process_name": names, "action": "route", "outbound": "proxy"},
            ],
        },
    }
    write(args.out, doc)


def routing_rules(rules: dict, probe_name: str) -> list[dict]:
    return [
        {
            "remarks": "bypass listed domains",
            "outboundTag": "direct",
            "domain": xray_domains(rules),
            "enabled": True,
        },
        {
            "remarks": "proxied application",
            "outboundTag": "proxy",
            "process": [probe_name],
            "enabled": True,
        },
        {
            "remarks": "other applications direct",
            "outboundTag": "direct",
            "port": "0-65535",
            "enabled": True,
        },
    ]


def profile_row(lab: dict, transport: str) -> dict:
    ep = endpoint(lab, transport)
    network = "xhttp" if transport == "xhttp" else "raw"
    flow = "" if transport == "xhttp" else "xtls-rprx-vision"
    transport_extra = {"Path": "/xh", "XhttpMode": "auto"} if transport == "xhttp" else {"RawHeaderType": "none"}
    return {
        "IndexId": f"bench-{transport}",
        "ConfigType": 5,
        "CoreType": 2,
        "ConfigVersion": 4,
        "Subid": "",
        "IsSub": 0,
        "Remarks": f"bench-{transport}",
        "Address": ep["host"],
        "Port": ep["port"],
        "Password": ep["uuid"],
        "Network": network,
        "StreamSecurity": "reality",
        "Sni": lab["sni"],
        "Fingerprint": lab["fingerprint"],
        "PublicKey": lab["realityPublicKey"],
        "ShortId": lab["shortId"],
        "SpiderX": "/",
        "ProtoExtra": json.dumps({"Flow": flow, "VlessEncryption": "none"}, separators=(",", ":")),
        "TransportExtra": json.dumps(transport_extra, separators=(",", ":")),
        "AllowInsecure": "",
        "Alpn": "",
        "DisplayLog": 1,
    }


def group_row(child_ids: list[str]) -> dict:
    extra = {
        "MultipleLoad": 1,
        "GroupType": "PolicyGroup",
        "ChildItems": ",".join(child_ids),
        "VlessEncryption": "none",
    }
    return {
        "IndexId": "bench-fallback",
        "ConfigType": 101,
        "CoreType": 2,
        "ConfigVersion": 4,
        "Subid": "",
        "IsSub": 0,
        "Remarks": "bench-fallback",
        "Address": "",
        "Port": 0,
        "Password": "",
        "Network": "",
        "StreamSecurity": "",
        "ProtoExtra": json.dumps(extra, separators=(",", ":")),
        "TransportExtra": "{}",
        "DisplayLog": 1,
    }


def table_columns(con: sqlite3.Connection, table: str) -> set[str]:
    rows = con.execute(f"PRAGMA table_info({table})").fetchall()
    return {r[1] for r in rows}


def insert_row(con: sqlite3.Connection, table: str, row: dict) -> None:
    cols = table_columns(con, table)
    if not cols:
        raise SystemExit(f"sqlite table {table} does not exist")
    use = {k: v for k, v in row.items() if k in cols}
    keys = list(use)
    sql = f"INSERT OR REPLACE INTO {table} ({', '.join(keys)}) VALUES ({', '.join('?' for _ in keys)})"
    con.execute(sql, [use[k] for k in keys])


def cmd_v2rayn(args: argparse.Namespace) -> None:
    lab = load_json(args.lab)
    rules = load_json(args.rules)
    con = sqlite3.connect(args.db)
    try:
        con.execute("DELETE FROM ProfileItem WHERE IndexId LIKE 'bench-%' OR Remarks LIKE 'bench-%'")
        for transport in ("xhttp", "raw"):
            insert_row(con, "ProfileItem", profile_row(lab, transport))
        insert_row(con, "ProfileItem", group_row(["bench-xhttp", "bench-raw"]))
        rule_json = json.dumps(routing_rules(rules, args.probe_name), ensure_ascii=False)
        cols = table_columns(con, "RoutingItem")
        active = con.execute("SELECT Id FROM RoutingItem WHERE IsActive = 1 LIMIT 1").fetchone()
        if active is None:
            active = con.execute("SELECT Id FROM RoutingItem LIMIT 1").fetchone()
        if active is None:
            row = {"Id": "bench-routing", "Remarks": "bench", "RuleSet": rule_json, "IsActive": 1, "Enabled": 1, "Sort": 1, "RuleNum": 3}
            insert_row(con, "RoutingItem", row)
            active_id = "bench-routing"
        else:
            active_id = active[0]
            sets = ["RuleSet = ?", "IsActive = 1"]
            vals: list = [rule_json]
            if "Enabled" in cols:
                sets.append("Enabled = 1")
            if "RuleNum" in cols:
                sets.append("RuleNum = 3")
            con.execute(f"UPDATE RoutingItem SET {', '.join(sets)} WHERE Id = ?", vals + [active_id])
            con.execute("UPDATE RoutingItem SET IsActive = 0 WHERE Id != ?", (active_id,))
        con.commit()
    finally:
        con.close()
    gui = load_json(args.gui)
    selected = "bench-fallback" if args.transport == "failover" else f"bench-{args.transport}"
    gui["IndexId"] = selected
    tun = gui.get("TunModeItem") or {}
    tun["EnableTun"] = True
    tun["EnableIPv6Address"] = True
    tun["RouteExcludeAddress"] = ["127.0.0.0/8", "::1/128"]
    if "AutoRoute" not in tun:
        tun["AutoRoute"] = True
    if "StrictRoute" not in tun:
        tun["StrictRoute"] = True
    if not tun.get("Stack"):
        tun["Stack"] = "gvisor"
    if not tun.get("Mtu"):
        tun["Mtu"] = 9000
    gui["TunModeItem"] = tun
    proxy = gui.get("SystemProxyItem") or {}
    proxy["SysProxyType"] = 2
    gui["SystemProxyItem"] = proxy
    basic = gui.get("RoutingBasicItem") or {}
    basic["RoutingIndexId"] = ""
    gui["RoutingBasicItem"] = basic
    write(args.gui, gui)


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("ashgate")
    a.add_argument("--lab", required=True)
    a.add_argument("--rules", required=True)
    a.add_argument("--probe", required=True)
    a.add_argument("--out", required=True)
    a.add_argument("--kill-switch", choices=("true", "false"), default="false")
    a.add_argument("--mode", choices=("single", "failover"), default="single")
    a.add_argument("--transport", choices=("xhttp", "raw"), default="xhttp")
    a.set_defaults(func=cmd_ashgate)

    s = sub.add_parser("singbox")
    s.add_argument("--lab", required=True)
    s.add_argument("--rules", required=True)
    s.add_argument("--probe-name", required=True)
    s.add_argument("--out", required=True)
    s.add_argument("--log", required=True)
    s.add_argument("--transport", choices=("xhttp", "raw"), default="raw")
    s.set_defaults(func=cmd_singbox)

    v = sub.add_parser("v2rayn")
    v.add_argument("--lab", required=True)
    v.add_argument("--rules", required=True)
    v.add_argument("--db", required=True)
    v.add_argument("--gui", required=True)
    v.add_argument("--probe-name", required=True)
    v.add_argument("--transport", choices=("xhttp", "raw", "failover"), required=True)
    v.set_defaults(func=cmd_v2rayn)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
