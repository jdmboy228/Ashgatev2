#!/usr/bin/env python3
"""Linux-side checks for config generation and blinding."""

import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

import assemble
import configs


LAB = {
    "xhttp": {"host": "127.0.0.1", "port": 1111, "uuid": "11111111-1111-4111-8111-111111111111", "link": "vless://xhttp-link"},
    "raw": {"host": "127.0.0.1", "port": 2222, "uuid": "22222222-2222-4222-8222-222222222222", "link": "vless://raw-link"},
    "realityPublicKey": "PUBKEY",
    "realityPrivateKey": "PRIVKEY",
    "shortId": "abcd1234",
    "sni": "www.microsoft.com",
    "fingerprint": "firefox",
    "subscriptionUrl": "http://127.0.0.1:9/sub/token",
    "rawNetwork": "raw",
}


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.lab = Path(self.tmp.name) / "lab.json"
        self.lab.write_text(json.dumps(LAB), encoding="utf-8")
        self.rules = str(ROOT / "rules.json")

    def tearDown(self):
        self.tmp.cleanup()

    def test_ashgate_single_uses_link_and_probe_path(self):
        out = Path(self.tmp.name) / "config.json"
        subprocess.check_call(
            [
                sys.executable,
                str(ROOT / "configs.py"),
                "ashgate",
                "--lab",
                str(self.lab),
                "--rules",
                self.rules,
                "--probe",
                r"C:\work\compare-probe.exe",
                "--out",
                str(out),
                "--transport",
                "xhttp",
                "--kill-switch",
                "false",
            ]
        )
        doc = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(doc["proxies"][0]["link"], "vless://xhttp-link")
        self.assertEqual(doc["rules"][0]["process"], r"C:\work\compare-probe.exe")
        self.assertIn("рф", doc["directDomains"])
        self.assertIn("vk.com", doc["directDomains"])
        self.assertFalse(doc["killSwitch"])

    def test_singbox_xhttp_is_unsupported(self):
        out = Path(self.tmp.name) / "sb.json"
        proc = subprocess.run(
            [
                sys.executable,
                str(ROOT / "configs.py"),
                "singbox",
                "--lab",
                str(self.lab),
                "--rules",
                self.rules,
                "--probe-name",
                "compare-probe.exe",
                "--out",
                str(out),
                "--log",
                str(Path(self.tmp.name) / "sb.log"),
                "--transport",
                "xhttp",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 3)
        self.assertIn("unsupported", proc.stderr)

    def test_singbox_raw_routes_one_process_and_bypass(self):
        out = Path(self.tmp.name) / "sb.json"
        subprocess.check_call(
            [
                sys.executable,
                str(ROOT / "configs.py"),
                "singbox",
                "--lab",
                str(self.lab),
                "--rules",
                self.rules,
                "--probe-name",
                "compare-probe.exe",
                "--out",
                str(out),
                "--log",
                str(Path(self.tmp.name) / "sb.log"),
                "--transport",
                "raw",
            ]
        )
        doc = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(doc["outbounds"][0]["flow"], "xtls-rprx-vision")
        self.assertNotIn("transport", doc["outbounds"][0])
        names = doc["route"]["rules"][-1]["process_name"]
        self.assertIn("compare-probe.exe", names)
        suffixes = doc["route"]["rules"][-2]["domain_suffix"]
        self.assertIn(".ru", suffixes)
        self.assertIn(".vk.com", suffixes)
        self.assertEqual(doc["route"]["final"], "direct")
        self.assertIn("127.0.0.0/8", doc["inbounds"][0]["route_exclude_address"])
        self.assertEqual(doc["route"]["default_domain_resolver"], "local")

    def test_subscription_payload_has_both_links(self):
        raw = configs.subscription_payload("http://127.0.0.1/sub/t", ["vless://a", "vless://b"])
        doc = json.loads(raw)
        self.assertEqual(doc["links"], ["vless://a", "vless://b"])

    def test_v2rayn_profile_and_fallback_group(self):
        db = Path(self.tmp.name) / "guiNDB.db"
        gui = Path(self.tmp.name) / "guiNConfig.json"
        gui.write_text(json.dumps({"IndexId": "", "TunModeItem": {"EnableTun": False, "StrictRoute": True}, "SystemProxyItem": {"SysProxyType": 0}}), encoding="utf-8")
        con = sqlite3.connect(db)
        con.execute(
            """CREATE TABLE ProfileItem (
            IndexId TEXT PRIMARY KEY, ConfigType INTEGER, CoreType INTEGER, ConfigVersion INTEGER,
            Subid TEXT, IsSub INTEGER, Remarks TEXT, Address TEXT, Port INTEGER, Password TEXT,
            Network TEXT, StreamSecurity TEXT, Sni TEXT, Fingerprint TEXT, PublicKey TEXT,
            ShortId TEXT, SpiderX TEXT, ProtoExtra TEXT, TransportExtra TEXT, AllowInsecure TEXT,
            Alpn TEXT, DisplayLog INTEGER)"""
        )
        con.execute(
            """CREATE TABLE RoutingItem (
            Id TEXT PRIMARY KEY, Remarks TEXT, RuleSet TEXT, IsActive INTEGER, Enabled INTEGER,
            Sort INTEGER, RuleNum INTEGER)"""
        )
        con.execute("INSERT INTO RoutingItem (Id, Remarks, RuleSet, IsActive, Enabled, Sort, RuleNum) VALUES ('r1','preset','[]',1,1,1,0)")
        con.commit()
        con.close()
        subprocess.check_call(
            [
                sys.executable,
                str(ROOT / "configs.py"),
                "v2rayn",
                "--lab",
                str(self.lab),
                "--rules",
                self.rules,
                "--db",
                str(db),
                "--gui",
                str(gui),
                "--probe-name",
                "compare-probe.exe",
                "--transport",
                "failover",
            ]
        )
        con = sqlite3.connect(db)
        rows = {r[0]: (r[1], r[2]) for r in con.execute("SELECT IndexId, Network, ConfigType FROM ProfileItem")}
        self.assertEqual(rows["bench-xhttp"], ("xhttp", 5))
        self.assertEqual(rows["bench-raw"], ("raw", 5))
        self.assertEqual(rows["bench-fallback"][1], 101)
        rules = json.loads(con.execute("SELECT RuleSet FROM RoutingItem WHERE IsActive = 1").fetchone()[0])
        self.assertEqual(rules[1]["process"], ["compare-probe.exe"])
        self.assertEqual(rules[2]["outboundTag"], "direct")
        con.close()
        saved = json.loads(gui.read_text(encoding="utf-8"))
        self.assertEqual(saved["IndexId"], "bench-fallback")
        self.assertTrue(saved["TunModeItem"]["EnableTun"])
        self.assertIn("127.0.0.0/8", saved["TunModeItem"]["RouteExcludeAddress"])
        self.assertTrue(saved["TunModeItem"]["StrictRoute"])
        self.assertEqual(saved["SystemProxyItem"]["SysProxyType"], 2)


class AssembleTests(unittest.TestCase):
    def test_labels_hide_names_and_summarize(self):
        doc = {
            "tools": {
                "ashgate": {"version": "0.9.3"},
                "sing-box": {"version": "1.14.4"},
                "v2rayn": {"version": "7.25.6"},
            },
            "server": {"version": "v26.10.31"},
            "runner": {"cpu": "Test CPU"},
            "scenario": {"rounds": 2},
            "rounds": [
                {
                    "order": ["sing-box", "ashgate", "v2rayn"],
                    "by_tool": {
                        "ashgate": {"transports": {"xhttp": {"status": "measured", "down_mbps": 10, "ipv4_probe_ok": True}}},
                        "sing-box": {"transports": {"xhttp": {"status": "unsupported", "reason": "no XHTTP"}}},
                        "v2rayn": {"transports": {"xhttp": {"status": "measured", "down_mbps": 8, "ipv4_probe_ok": True}}},
                    },
                },
                {
                    "order": ["ashgate", "v2rayn", "sing-box"],
                    "by_tool": {
                        "ashgate": {"transports": {"xhttp": {"status": "measured", "down_mbps": 14, "ipv4_probe_ok": True}}},
                        "sing-box": {"transports": {"xhttp": {"status": "unsupported", "reason": "no XHTTP"}}},
                        "v2rayn": {"transports": {"xhttp": {"status": "measured", "down_mbps": 9, "ipv4_probe_ok": False}}},
                    },
                },
            ],
            "once": {
                "ashgate": {
                    "secrets": [{"path": r"C:\secret\config.json", "kinds": ["uuid", "reality_public"]}],
                    "ports": [{"proto": "tcp", "local": "127.0.0.1:1", "process": "ashgate.exe", "role": "client"}],
                    "actions": ["write configuration file", "start the client"],
                    "soak": {"status": "measured", "private_mb_delta": 1, "samples": [{"t_seconds": 0, "private_mb": 10, "working_set_mb": 12}]},
                    "kill_switch": {"status": "measured"},
                    "failover": {"status": "measured"},
                }
            },
        }
        results, mapping = assemble.build(doc)
        blob = json.dumps(results)
        for banned in ("ashgate", "sing-box", "v2rayn", "0.9.3", "1.14.4", "7.25.6"):
            self.assertNotIn(banned, blob.lower())
        self.assertEqual(set(results["clients"]), {"A", "B", "C"})
        ids = {item["id"] for item in mapping["labels"].values()}
        self.assertEqual(ids, {"ashgate", "sing-box", "v2rayn"})
        # The label that measured xhttp twice has a median between 10 and 14.
        medians = []
        for client in results["clients"].values():
            block = client["transports"].get("xhttp") or {}
            if block.get("status") == "measured":
                medians.append(block["summary"]["down_mbps"]["median"])
        self.assertIn(12, medians)
        self.assertIn(8.5, medians)


if __name__ == "__main__":
    unittest.main()
