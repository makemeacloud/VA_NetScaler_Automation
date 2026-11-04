#!/usr/bin/env python3
"""Config migration helper: existing NetScalers -> MPX 9200 (non-FIPS; FIPS optional with --fips). Stages 1-4 only.

  export       READ-ONLY. Pull running + saved config, version, HA state, a stats snapshot and the
               SSL files that certKeys reference (private keys only with --include-keys).
  transform    Offline. Rewrite one ns.conf for the new box: interface map, optional re-IP, strip
               node-specific lines (NSIP, hostname, HA node, RPC node, nsroot, legacy HSM...). Runs lint.
  lint         Offline. Findings for the 9200 target: classic policies (run nspepi), HSM keys, box-encrypted secrets, unmapped interfaces, missing cert files,
               partitions, cluster, sizing vs. limits. Weak ciphers / old protocols are INFO by default;
               with --fips (MPX 9200 FIPS target) they are WARN against FIPS rules.
  merge-check  Offline. Name / VIP / VLAN / IP collisions when several old boxes land on one new pair.

Nothing here writes to any NetScaler. Applying, validation and cutover are later stages (not built yet).
FIPS rules (--fips only) are heuristics marked "verify": confirm against the 14.1-FIPS docs for your build.
"""
import argparse
import base64
import csv
import getpass
import json
import os
import re
import sys
from pathlib import Path
from urllib.parse import quote

try:
    import yaml
except ImportError:  # only transform/lint with --map/--limits need it
    yaml = None

BLOCK, WARN, INFO = "BLOCK", "WARN", "INFO"

# ----------------------------------------------------------------- ns.conf parsing
def tokenize(line):
    """Split an ns.conf line on whitespace, keeping "quoted \\"strings\\"" whole (quotes kept)."""
    toks, cur, i, n = [], [], 0, len(line)
    while i < n:
        c = line[i]
        if c == '"':
            j = i + 1
            while j < n and line[j] != '"':
                j += 2 if line[j] == "\\" else 1
            cur.append(line[i:j + 1])
            i = j + 1
        elif c.isspace():
            if cur:
                toks.append("".join(cur)); cur = []
            i += 1
        else:
            cur.append(c); i += 1
    if cur:
        toks.append("".join(cur))
    return toks


def unquote(t):
    return t[1:-1].replace('\\"', '"') if len(t) >= 2 and t[0] == t[-1] == '"' else t


# one-word object types; everything else is "<group> <type>" (add lb vserver, add ssl certKey, ...)
ONE_WORD = {"server", "service", "servicegroup", "vlan", "route", "route6", "channel", "interface", "location",
            "netprofile", "bridgegroup", "vrid", "vrid6", "rnat", "rnat6", "linkset", "fis", "lacp", "inat",
            "inatparam", "vxlan", "ipset", "netbridge", "l2param", "l3param", "arp", "nd6"}


def parse(line):
    """-> dict(verb, type, name, args, toks) or None for comments/blank lines."""
    s = line.strip()
    if not s or s.startswith("#"):
        return None
    t = tokenize(s)
    if len(t) < 2:
        return {"verb": t[0].lower(), "type": "", "name": "", "args": [], "toks": t}
    k = 2 if t[1].lower() in ONE_WORD else 3
    typ = " ".join(x.lower() for x in t[1:k])
    rest = t[k:]
    name = unquote(rest[0]) if rest and not rest[0].startswith("-") else ""
    return {"verb": t[0].lower(), "type": typ, "name": name, "args": rest, "toks": t}


def opt(toks, name):
    """Values after -name (case-insensitive) up to the next -option."""
    low = [x.lower() for x in toks]
    if f"-{name.lower()}" not in low:
        return None
    i = low.index(f"-{name.lower()}") + 1
    out = []
    while i < len(toks) and not (toks[i].startswith("-") and not re.match(r"^-\d", toks[i])):
        out.append(toks[i]); i += 1
    return out


def drop_opts(toks, names):
    names = {f"-{n.lower()}" for n in names}
    out, skip = [], False
    for x in toks:
        if x.startswith("-") and not re.match(r"^-\d", x):
            skip = x.lower() in names
            if skip:
                continue
        elif skip:
            continue
        out.append(x)
    return out


IP_RE = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
IFACE_RE = re.compile(r"^(\d+/\d+|LA/\d+|LR/\d+|LS/\d+)$")
IFACE_LINE = re.compile(r"interface|channel|vlan|linkset|lacp|ha monitoring|ha node|fis", re.IGNORECASE)
VSERVER_TYPES = {"lb vserver", "cs vserver", "vpn vserver", "authentication vserver", "cr vserver"}


def vip_of(p):
    """(ip, port) for add <lb|cs|vpn|...> vserver NAME TYPE IP PORT, else None."""
    if p and p["verb"] == "add" and p["type"] in VSERVER_TYPES and len(p["args"]) >= 4:
        ip, port = p["args"][2], p["args"][3]
        if IP_RE.fullmatch(ip) and ip != "0.0.0.0":
            return ip, port
    return None


# ----------------------------------------------------------------- transform
def find_nsip(lines):
    for line in lines:
        p = parse(line)
        if p and p["verb"] == "set" and p["type"] == "ns config":
            v = opt(p["toks"], "IPAddress")
            if v:
                return v[0]
    return None


def strip_reason(p, nsip):
    """Reason string if the whole line is node-specific / must not move, else None."""
    v, t, low = p["verb"], p["type"], [x.lower() for x in p["toks"]]
    if t == "ns hostname":
        return "hostname is per node (set by mpx_base)"
    if t == "ha node":
        return "HA is rebuilt by mpx_ha_pair; re-apply any HA tuning by hand"
    if t == "ns rpcnode":
        return "RPC nodes are rebuilt by mpx_ha_pair"
    if t == "system user" and p["name"].lower() == "nsroot":
        return "nsroot is set on the new box itself"
    if t in ("ns ip", "ns ip6") and (p["name"] == nsip or "nsip" in low or "-scope" in low and "link" in low):
        return "NSIP / link-local address belongs to the old box (NSIP set by mpx_bootstrap, GUI by mpx_base)"
    if t == "ns encryptionparams":
        return "box-specific encryption parameters"
    if t == "snmp engineid":
        return "SNMP engine id is per box"
    if t.startswith("ssl fips") or (v in ("create", "add") and t == "ssl fipskey"):
        return "legacy HSM (MPX/SDX 14000 FIPS); MPX 9200 has no HSM"
    if t.startswith("cluster"):
        return "cluster config; target design is an HA pair"
    return None


def transform(lines, mapping):
    """-> (kept_lines, stripped[(lineno, reason, line)], findings[], stats)."""
    ifmap = {str(k): str(v) for k, v in (mapping.get("interfaces") or {}).items()}
    ipmap = {str(k): str(v) for k, v in (mapping.get("ips") or {}).items()}
    extra = [re.compile(x) for x in (mapping.get("strip_regex") or [])]
    nsip = find_nsip(lines)
    kept, stripped, findings = [], [], []
    st = {"ip_rewrites": 0, "iface_rewrites": 0, "nsip": nsip or ""}
    for no, raw in enumerate(lines, 1):
        line = raw.rstrip("\r\n")
        p = parse(line)
        if p is None:
            kept.append(line); continue
        if any(r.search(line) for r in extra):
            stripped.append((no, "strip_regex in map file", line)); continue
        why = strip_reason(p, nsip)
        if why:
            stripped.append((no, why, line))
            if "HSM" in why:
                findings.append((BLOCK, no, "fips-hsm", "Legacy HSM command: keys inside an old HSM cannot be "
                                 "moved; issue new keys/certs on the 9200.", line))
            continue
        toks = p["toks"]
        if p["verb"] == "set" and p["type"] == "ns config":
            toks = drop_opts(toks, ["IPAddress", "netmask"])
            if len(toks) <= 3:
                stripped.append((no, "NSIP/netmask belong to the old box", line)); continue
        if IFACE_LINE.search(" ".join(toks[:3])) or opt(toks, "ifnum") is not None or opt(toks, "interface"):
            new = []
            for x in toks:
                if IFACE_RE.match(x):
                    if x in ifmap:
                        if ifmap[x] != x:
                            st["iface_rewrites"] += 1
                        x = ifmap[x]
                    elif not mapping.get("interfaces_unchanged"):
                        findings.append((BLOCK, no, "iface-unmapped",
                                         f"Interface {x} has no entry in the map file (9200 port names differ).", line))
                new.append(x)
            toks = new
        out = " ".join(toks)
        if ipmap:
            def sub(m):
                if m.group(1) in ipmap:
                    st["ip_rewrites"] += 1
                    return ipmap[m.group(1)]
                return m.group(1)
            out = IP_RE.sub(sub, out)
        kept.append(out)
    return kept, stripped, findings, st


# ----------------------------------------------------------------- lint
WEAK_CIPHER = re.compile(r"RC4|(^|[-_])(3?DES)|MD5|EXP|NULL|ADH|AECDH|SEED|IDEA|SSL3|CAMELLIA|EXPORT", re.I)
CLASSIC_EXPR = re.compile(r"(^|[\s(!&|])(REQ|RES)\.(HTTP|IP|TCP|SSL|ETHER|VLAN|INTERFACE)\b|\bns_(?!adv_)[a-z_]+\b")
CLASSIC_TYPES = {"filter policy", "filter action", "sc policy", "sc parameter", "pq policy", "spdy profile"}
CLASSIC_AUTHN = re.compile(r"^authentication (ldap|radius|cert|local|tacacs|saml|negotiate|web)policy$")
RULE_TYPES = re.compile(r"policy|expression")


def lint(lines, ssl_dir=None, stats=None, limits=None, fips=False):
    """fips=True: target is MPX 9200 FIPS -> weak ciphers / old protocols are WARN fips-*; else INFO."""
    findings, counts, files = [], {}, []
    for no, raw in enumerate(lines, 1):
        line = raw.rstrip("\r\n")
        p = parse(line)
        if p is None:
            continue
        t, toks, low = p["type"], p["toks"], " ".join(p["toks"]).lower()
        if p["verb"] == "add":
            counts[t] = counts.get(t, 0) + 1
            if t in ("lb vserver", "cs vserver") and len(p["args"]) > 1 and p["args"][1].upper().startswith("SSL"):
                counts["ssl offload vserver"] = counts.get("ssl offload vserver", 0) + 1
        if t in CLASSIC_TYPES:
            findings.append((BLOCK, no, "classic-feature", f"'{t}' was removed in 13.1+; convert (nspepi) or "
                             "redesign before loading on 14.1.", line))
        elif RULE_TYPES.search(t) and p["verb"] in ("add", "set"):
            # rule is -rule X, or positional after the name (rewrite/responder/vpn sessionPolicy/ldapPolicy...)
            pos = p["args"][1:2] if len(p["args"]) > 1 and not p["args"][1].startswith("-") else []
            r = " ".join(unquote(x) for x in (opt(toks, "rule") or pos))
            if t == "cs policy" and (opt(toks, "url") or opt(toks, "domain")):
                findings.append((BLOCK, no, "classic-expr", "Classic CS policy (-url/-domain); convert to an "
                                 "advanced -rule (nspepi) before loading on 14.1.", line))
            elif r and CLASSIC_EXPR.search(r):
                findings.append((BLOCK, no, "classic-expr", "Classic policy expression; run nspepi and review "
                                 "its output before loading on 14.1.", line))
        if CLASSIC_AUTHN.match(t):
            findings.append((WARN, no, "classic-authn", "Classic authentication policy; nspepi converts these to "
                             "advanced policies - verify support on 14.1-FIPS.", line))
        for c in (opt(toks, "cipherName") or []):
            if WEAK_CIPHER.search(unquote(c)):
                if fips:
                    findings.append((WARN, no, "fips-cipher", f"Cipher '{unquote(c)}' is likely not FIPS-approved "
                                     "(verify on 14.1-FIPS).", line))
                else:
                    findings.append((INFO, no, "weak-cipher", f"Cipher '{unquote(c)}' is weak; consider dropping "
                                     "it on the new box.", line))
        for proto in ("ssl3", "tls1", "tls11"):
            if (opt(toks, proto) or [""])[0].upper() == "ENABLED":
                if fips:
                    findings.append((WARN, no, "fips-protocol", f"-{proto} ENABLED: old protocol, likely not "
                                     "allowed in FIPS mode (verify).", line))
                else:
                    findings.append((INFO, no, "old-protocol", f"-{proto} ENABLED: old protocol; consider "
                                     "disabling it on the new box.", line))
        em = (opt(toks, "encryptmethod") or [""])[0].upper()
        if "-kek" in low.split() or em not in ("", "ENCMTHD_1"):
            findings.append((WARN, no, "box-secret", "Secret encrypted with the OLD box's key (KEK). It will not "
                             "decrypt on the 9200: re-enter it, or follow NetScaler's KEK migration steps.", line))
        if t == "ssl certkey":
            if opt(toks, "fipsKey"):
                findings.append((BLOCK, no, "fips-hsm", "certKey uses an HSM key (-fipsKey); it cannot move. "
                                 "Issue a new key/cert on the 9200.", line))
            for kind in ("cert", "key"):
                f = opt(toks, kind)
                if f:
                    files.append((no, kind, unquote(f[0]), line))
        if t == "ns partition":
            findings.append((WARN, no, "partition", f"Admin partition '{p['name']}': its config lives in "
                             "/nsconfig/partitions/<name>/ns.conf and is NOT in this file.", line))
        if t.startswith("cluster"):
            findings.append((BLOCK, no, "cluster", "Cluster config; target design is an HA pair.", line))
    if ssl_dir is not None:
        for no, kind, f, line in files:
            if not (Path(ssl_dir) / f).is_file():
                sev = WARN if kind == "key" else BLOCK
                findings.append((sev, no, "ssl-file-missing", f"{kind} file {f} not in {ssl_dir} (keys are only "
                                 "exported with --include-keys).", line))
    findings += sizing(stats, limits)
    return findings, counts, files


def sizing(stats, limits):
    """Compare an export stats snapshot with target limits (from the 9200 datasheet / your license)."""
    out = []
    if not stats or not limits:
        return out
    head = float(limits.get("headroom_pct", 70)) / 100
    have = {"throughput_mbps": stats.get("throughput_mbps"), "ssl_tps": stats.get("ssl_tps")}
    for k, v in have.items():
        lim = limits.get(k)
        if v is None or lim in (None, "", "CHANGE_ME"):
            continue
        if float(v) > float(lim) * head:
            out.append((WARN, 0, "sizing", f"{k}: snapshot {v} > {int(head * 100)}% of target limit {lim}. A "
                        "snapshot is not a peak - check ADM/SNMP history.", ""))
    return out


# ----------------------------------------------------------------- merge-check
def merge_check(files):
    names, vips, vlans, ips, findings = {}, {}, {}, {}, []
    for f in files:
        for no, raw in enumerate(Path(f).read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            p = parse(raw)
            if not p or p["verb"] != "add":
                continue
            if p["type"] in ("ns ip", "ns ip6"):
                ips.setdefault(p["name"], []).append((f, no, raw.strip()))
            elif p["type"] == "vlan":
                vlans.setdefault(p["name"], []).append((f, no, raw.strip()))
            elif p["name"] and p["type"] not in ("route", "route6"):
                names.setdefault((p["type"], p["name"]), []).append((f, no, raw.strip()))
            v = vip_of(p)
            if v:
                vips.setdefault(v, []).append((f, no, raw.strip()))
    for what, d in (("name", names), ("vip", vips), ("vlan", vlans), ("ip", ips)):
        for key, where in sorted(d.items(), key=lambda kv: str(kv[0])):
            srcs = {w[0] for w in where}
            if len(srcs) > 1:
                same = len({w[2] for w in where}) == 1
                sev = INFO if what == "vlan" or (same and what in ("name", "ip")) else BLOCK
                msg = {"name": "same object name in several sources: rename one, or use admin partitions",
                       "vip": "same VIP:port in several sources", "vlan": "same VLAN id: fine if it is the same "
                       "network, a conflict if not", "ip": "same IP added in several sources"}[what]
                if same and what in ("name", "ip"):
                    msg = "identical definition in several sources (keep one copy)"
                findings.append((sev, what, key if isinstance(key, str) else " ".join(map(str, key)), msg,
                                 "; ".join(f"{Path(a).name}:{b}" for a, b, _ in where)))
    return findings


# ----------------------------------------------------------------- export (read-only)
def text_of(obj):
    """Longest string inside a NITRO reply (field names for running/saved config text are UNVERIFIED)."""
    best = ""
    if isinstance(obj, dict):
        for v in obj.values():
            s = text_of(v)
            best = s if len(s) > len(best) else best
    elif isinstance(obj, list):
        for v in obj:
            s = text_of(v)
            best = s if len(s) > len(best) else best
    elif isinstance(obj, str):
        best = obj
    return best


def stat_snapshot(n):
    """UNVERIFIED stat field names: ns.rxmbitsrate/txmbitsrate, ssl.ssltransactionsrate."""
    out = {}
    try:
        ns = n.get("stat/ns").get("ns") or {}
        ns = ns[0] if isinstance(ns, list) and ns else ns
        rx, tx = ns.get("rxmbitsrate"), ns.get("txmbitsrate")
        if rx is not None and tx is not None:
            out["throughput_mbps"] = round(float(rx) + float(tx), 1)
        out["cpu_pct"], out["mem_pct"] = ns.get("cpuusagepcnt"), ns.get("memusagepcnt")
        ssl = n.get("stat/ssl").get("ssl") or {}
        ssl = ssl[0] if isinstance(ssl, list) and ssl else ssl
        if ssl.get("ssltransactionsrate") is not None:
            out["ssl_tps"] = float(ssl["ssltransactionsrate"])
    except Exception as e:  # stats are optional
        out["error"] = str(e)[:200]
    return out


def write_private(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def export_one(host, user, pw, a):
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import ns_discover as nd  # reuse its read-only NITRO client
    n = nd.Nitro(host, user, pw, a)
    meta = {"host": host}
    try:
        meta["version"] = (n.get("config/nsversion").get("nsversion") or {}).get("version", "")
        meta["hostname"] = (n.get("config/nshostname").get("nshostname") or [{}])[0].get("hostname", "")
        ha = n.get_all("hanode")
        meta["ha_state"] = next((h.get("state", "") for h in ha if str(h.get("id")) == "0"), "")
        if meta["ha_state"].lower() == "secondary":
            print(f"  WARNING {host} is an HA SECONDARY: export the primary (its config is the one that syncs).",
                  file=sys.stderr)
        d = Path(a.out) / re.sub(r"[^\w.-]", "_", meta["hostname"] or host)
        d.mkdir(parents=True, exist_ok=True)
        running = text_of(n.get("config/nsrunningconfig"))
        saved = text_of(n.get("config/nssavedconfig"))
        if not running:
            raise RuntimeError("nsrunningconfig returned no text (check the account's command policy)")
        (d / "ns.conf").write_text(running, encoding="utf-8")
        (d / "saved.conf").write_text(saved, encoding="utf-8")
        meta["running_differs_from_saved"] = bool(saved) and running.strip() != saved.strip()
        meta["stats"] = stat_snapshot(n)
        lines = running.splitlines()
        _, _, files = lint(lines)
        meta["ssl_files"], meta["ssl_missing"] = [], []
        for _, kind, f, _ in files:
            if kind == "key" and not a.include_keys:
                continue
            rel = Path(f)
            loc = "/nsconfig/ssl" + ("/" + rel.parent.as_posix() if str(rel.parent) != "." else "")
            if f.startswith("/"):
                loc, rel = str(Path(f).parent.as_posix()), Path(Path(f).name)
            q = f"filename:{quote(rel.name, safe='')},filelocation:{quote(loc, safe='')}"
            r = n.get(f"config/systemfile?args={q}").get("systemfile")
            r = (r[0] if isinstance(r, list) and r else r) or {}
            if not r.get("filecontent"):
                meta["ssl_missing"].append(f); continue
            data = base64.b64decode(r["filecontent"])
            target = d / "ssl" / (rel if not f.startswith("/") else rel.name)
            if kind == "key":
                write_private(target, data)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
            meta["ssl_files"].append(f)
        (d / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
        print(f"  [ok] {host}: {d} ({len(lines)} lines, {len(meta['ssl_files'])} ssl files"
              f"{', RUNNING != SAVED' if meta['running_differs_from_saved'] else ''})", file=sys.stderr)
    finally:
        n.logout()
    return meta


# ----------------------------------------------------------------- output
def write_findings(findings, path, header=("severity", "line", "code", "message", "config_line")):
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(findings)


def summary(findings, counts, stripped=None, st=None):
    by = {s: sum(1 for x in findings if x[0] == s) for s in (BLOCK, WARN, INFO)}
    out = ["# Migration lint", "", f"BLOCK {by[BLOCK]} / WARN {by[WARN]} / INFO {by[INFO]}", ""]
    if st:
        out += [f"Old NSIP: {st['nsip'] or '?'} - interface rewrites {st['iface_rewrites']}, "
                f"IP rewrites {st['ip_rewrites']}, stripped lines {len(stripped or [])}", ""]
    out += ["## Object counts", ""] + [f"- {k}: {v}" for k, v in sorted(counts.items())] + ["", "## Findings", ""]
    for code in sorted({x[2] for x in findings}):
        rows = [x for x in findings if x[2] == code]
        msgs = list(dict.fromkeys(x[3] for x in rows))
        out.append(f"- **{rows[0][0]} {code}** x{len(rows)}: {msgs[0]}"
                   + (f" (+{len(msgs) - 1} more, see findings.csv)" if len(msgs) > 1 else ""))
    return "\n".join(out) + "\n"


def load_yaml(path):
    if not path:
        return {}
    if yaml is None:
        sys.exit("pip install pyyaml")
    return yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("export", help="read-only: pull config + SSL files from old boxes")
    e.add_argument("--hosts", help="file, one host per line (# comments ok)")
    e.add_argument("--host", action="append", default=[])
    e.add_argument("--user", default="nsadmin")
    e.add_argument("--out", default="migration_out")
    e.add_argument("--include-keys", action="store_true", help="also download private keys (0600). Sensitive.")
    e.add_argument("--insecure", action="store_true")
    e.add_argument("--timeout", type=float, default=30)
    e.add_argument("--rate", type=float, default=5)
    t = sub.add_parser("transform", help="rewrite one ns.conf for the 9200 (runs lint)")
    t.add_argument("conf")
    t.add_argument("--map", required=True, help="YAML: interfaces, ips, strip_regex (see migration/example_map.yml)")
    t.add_argument("--out", required=True)
    t.add_argument("--ssl-dir")
    t.add_argument("--stats", help="meta.json from export (for sizing)")
    t.add_argument("--limits", help="YAML: throughput_mbps, ssl_tps, headroom_pct")
    t.add_argument("--fips", action="store_true", help="target is MPX 9200 FIPS: apply FIPS cipher/protocol checks")
    li = sub.add_parser("lint", help="findings for one ns.conf")
    li.add_argument("conf")
    li.add_argument("--ssl-dir")
    li.add_argument("--stats")
    li.add_argument("--limits")
    li.add_argument("--fips", action="store_true", help="target is MPX 9200 FIPS: apply FIPS cipher/protocol checks")
    li.add_argument("--out")
    m = sub.add_parser("merge-check", help="collisions between several transformed configs")
    m.add_argument("confs", nargs="+")
    m.add_argument("--out")
    a = p.parse_args(argv)

    if a.cmd == "export":
        hosts = list(a.host)
        if a.hosts:
            hosts += [ln.split("#")[0].strip() for ln in Path(a.hosts).read_text().splitlines()]
        hosts = [h for h in hosts if h]
        if not hosts:
            sys.exit("give --host or --hosts")
        pw = getpass.getpass(f"Password for {a.user}: ")
        if a.include_keys:
            print("  WARNING: private keys will be written to disk. Keep --out off shared drives; delete after "
                  "import.", file=sys.stderr)
        bad = 0
        for h in hosts:
            try:
                export_one(h, a.user, pw, a)
            except Exception as ex:  # keep going for other hosts
                bad += 1
                print(f"  [FAILED] {h}: {str(ex)[:300]}", file=sys.stderr)
        return 1 if bad else 0

    stats = (json.loads(Path(a.stats).read_text()).get("stats") if getattr(a, "stats", None) else None)
    limits = load_yaml(getattr(a, "limits", None))

    if a.cmd == "transform":
        lines = Path(a.conf).read_text(encoding="utf-8", errors="replace").splitlines()
        kept, stripped, tf, st = transform(lines, load_yaml(a.map))
        lf, counts, _ = lint(kept, a.ssl_dir, stats, limits, fips=a.fips)
        out = Path(a.out); out.mkdir(parents=True, exist_ok=True)
        base = Path(a.conf).parent.name if Path(a.conf).name == "ns.conf" else Path(a.conf).stem
        (out / f"{base}.migrated.conf").write_text("\n".join(kept) + "\n", encoding="utf-8")
        write_findings(stripped, out / f"{base}.stripped.csv", ("line", "reason", "config_line"))
        findings = tf + lf
        write_findings(findings, out / f"{base}.findings.csv")
        (out / f"{base}.summary.md").write_text(summary(findings, counts, stripped, st), encoding="utf-8")
        print(summary(findings, counts, stripped, st))
        return 1 if any(f[0] == BLOCK for f in findings) else 0

    if a.cmd == "lint":
        lines = Path(a.conf).read_text(encoding="utf-8", errors="replace").splitlines()
        findings, counts, _ = lint(lines, a.ssl_dir, stats, limits, fips=a.fips)
        if a.out:
            Path(a.out).mkdir(parents=True, exist_ok=True)
            write_findings(findings, Path(a.out) / "findings.csv")
        print(summary(findings, counts))
        return 1 if any(f[0] == BLOCK for f in findings) else 0

    if a.cmd == "merge-check":
        findings = merge_check(a.confs)
        for f in findings:
            print(f"  [{f[0]}] {f[1]} {f[2]}: {f[3]} ({f[4]})")
        if a.out:
            Path(a.out).mkdir(parents=True, exist_ok=True)
            write_findings(findings, Path(a.out) / "merge_check.csv", ("severity", "kind", "key", "message", "where"))
        print(f"{len(findings)} collision(s)")
        return 1 if any(f[0] == BLOCK for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
