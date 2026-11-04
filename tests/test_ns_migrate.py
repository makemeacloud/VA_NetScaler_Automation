"""Offline tests for scripts/ns_migrate.py. Run: python -m unittest discover -s tests"""
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import ns_migrate as m  # noqa: E402

FIX = Path(__file__).parent / "fixtures"
LINES = (FIX / "old_box.conf").read_text().splitlines()
MAP = {"interfaces": {"0/1": "0/1", "1/1": "10/1", "1/2": "10/2", "LA/1": "LA/1"},
       "ips": {"10.10.1.100": "10.50.1.100"}}


def codes(findings):
    return {f[2] for f in findings}


class Tokenize(unittest.TestCase):
    def test_quotes_kept_whole(self):
        t = m.tokenize('add cs policy p -rule "HTTP.REQ.URL.STARTSWITH(\\"/a b\\")"')
        self.assertEqual(t[-1], '"HTTP.REQ.URL.STARTSWITH(\\"/a b\\")"')
        self.assertEqual(len(t), 6)

    def test_parse_types(self):
        self.assertEqual(m.parse("add lb vserver v HTTP 1.2.3.4 80")["type"], "lb vserver")
        self.assertEqual(m.parse("add server s1 1.2.3.4")["name"], "s1")
        self.assertEqual(m.parse("set ns hostName x")["type"], "ns hostname")
        self.assertIsNone(m.parse("# comment"))


class Transform(unittest.TestCase):
    def setUp(self):
        self.kept, self.stripped, self.find, self.st = m.transform(LINES, MAP)
        self.text = "\n".join(self.kept)

    def test_node_specific_lines_stripped(self):
        for frag in ("set ns hostName", "add HA node", "set HA node", "add ns rpcNode", "set system user nsroot",
                     "fe80::", "set ns ip 10.10.0.5", "set ssl fips", "set snmp engineId"):
            self.assertNotIn(frag, self.text, frag)

    def test_ns_config_keeps_other_options(self):
        line = next(x for x in self.kept if x.startswith("set ns config"))
        self.assertNotIn("-IPAddress", line)
        self.assertNotIn("-netmask", line)
        self.assertIn("-timezone", line)
        self.assertEqual(self.st["nsip"], "10.10.0.5")

    def test_interfaces_and_ips_rewritten(self):
        self.assertIn("add channel LA/1 -ifnum 10/1 10/2", self.text)
        self.assertIn("add cs vserver cs_app SSL 10.50.1.100 443", self.text)
        self.assertEqual(self.st["iface_rewrites"], 2)
        self.assertEqual(self.st["ip_rewrites"], 1)
        self.assertNotIn("iface-unmapped", codes(self.find))

    def test_unmapped_interface_blocks(self):
        _, _, f, _ = m.transform(LINES, {"interfaces": {"1/1": "10/1"}})
        self.assertIn("iface-unmapped", codes(f))

    def test_hsm_blocks(self):
        self.assertIn("fips-hsm", codes(self.find))

    def test_user_lines_kept(self):
        self.assertIn("add system user ops", self.text)
        self.assertIn("add route 0.0.0.0 0.0.0.0 10.10.1.1", self.text)


class Lint(unittest.TestCase):
    def setUp(self):
        self.find, self.counts, self.files = m.lint(LINES, fips=True)

    def test_expected_findings(self):
        c = codes(self.find)
        for code in ("classic-feature", "classic-expr", "classic-authn", "fips-cipher", "fips-protocol",
                     "box-secret", "fips-hsm", "partition"):
            self.assertIn(code, c, code)

    def test_box_secret_only_for_kek_encrypted(self):
        lines = {f[4] for f in self.find if f[2] == "box-secret"}
        self.assertTrue(any("ldap_srv" in x for x in lines))
        self.assertFalse(any("system user ops" in x for x in lines))  # SHA512 hash, not box-encrypted

    def test_classic_rules(self):
        lines = {f[4] for f in self.find if f[2] == "classic-expr"}
        self.assertTrue(any("pol_old" in x for x in lines))      # -url CS policy
        self.assertTrue(any("sp_all" in x for x in lines))       # positional ns_true
        self.assertFalse(any("pol_new" in x for x in lines))     # advanced -rule
        self.assertFalse(any("rw_hdr" in x for x in lines))      # advanced positional

    def test_only_weak_cipher_flagged(self):
        flagged = [f[3] for f in self.find if f[2] == "fips-cipher"]
        self.assertEqual(len(flagged), 1)
        self.assertIn("SSL3-RC4-SHA", flagged[0])

    def test_protocols(self):
        msgs = " ".join(f[3] for f in self.find if f[2] == "fips-protocol")
        self.assertIn("-ssl3", msgs)
        self.assertIn("-tls1 ", msgs)
        self.assertNotIn("-tls12", msgs)

    def test_counts_and_files(self):
        self.assertEqual(self.counts["server"], 2)
        self.assertEqual(self.counts["ssl offload vserver"], 1)
        no = next(i for i, x in enumerate(LINES, 1) if x.startswith("add ssl certKey app_ck"))
        self.assertIn((no, "cert", "app.crt", LINES[no - 1]), self.files)

    def test_missing_ssl_files(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "app.crt").write_text("x")
            f, _, _ = m.lint(LINES, ssl_dir=d)
        missing = [x for x in f if x[2] == "ssl-file-missing"]
        self.assertEqual({x[0] for x in missing if "hsm.crt" in x[3]}, {m.BLOCK})
        self.assertEqual({x[0] for x in missing if "app.key" in x[3]}, {m.WARN})

    def test_non_fips_default(self):
        f, _, _ = m.lint(LINES)
        c = codes(f)
        self.assertFalse({"fips-cipher", "fips-protocol"} & c)
        self.assertIn("weak-cipher", c)
        self.assertIn("old-protocol", c)
        self.assertEqual({x[0] for x in f if x[2] in ("weak-cipher", "old-protocol")}, {m.INFO})
        self.assertIn("fips-hsm", c)  # old HSM keys cannot move to any 9200

    def test_partition_blocks(self):
        self.assertEqual({f[0] for f in self.find if f[2] == "partition"}, {m.BLOCK})

    def test_safe_target(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertIsNotNone(m.safe_target(d, Path("sub/app.crt")))
            self.assertIsNone(m.safe_target(d, Path("../../evil.crt")))

    def test_sizing(self):
        f = m.sizing({"throughput_mbps": 9000}, {"throughput_mbps": 10000, "ssl_tps": "CHANGE_ME"})
        self.assertEqual(len(f), 1)
        self.assertEqual(m.sizing({"throughput_mbps": 100}, {"throughput_mbps": 10000}), [])


class MergeCheck(unittest.TestCase):
    def test_collisions(self):
        f = m.merge_check([FIX / "old_box.conf", FIX / "old_box2.conf"])
        by = {(x[1], x[2]): x[0] for x in f}
        self.assertEqual(by[("name", "server web1")], m.INFO)       # identical line
        self.assertEqual(by[("name", "cs vserver cs_app")], m.BLOCK)  # same name
        self.assertEqual(by[("vip", "10.10.1.100 443")], m.BLOCK)
        self.assertEqual(by[("vlan", "20")], m.INFO)
        self.assertNotIn(("name", "server web3"), by)


class Cli(unittest.TestCase):
    def test_transform_writes_outputs(self):
        with tempfile.TemporaryDirectory() as d:
            mp = Path(d) / "map.yml"
            mp.write_text("interfaces: {'0/1': '0/1', '1/1': '10/1', '1/2': '10/2', 'LA/1': 'LA/1'}\n")
            rc = m.main(["transform", str(FIX / "old_box.conf"), "--map", str(mp), "--out", d])
            self.assertEqual(rc, 1)  # BLOCK findings in the sample
            for suffix in ("migrated.conf", "stripped.csv", "findings.csv", "summary.md"):
                self.assertTrue((Path(d) / f"old_box.{suffix}").is_file(), suffix)


if __name__ == "__main__":
    unittest.main()
