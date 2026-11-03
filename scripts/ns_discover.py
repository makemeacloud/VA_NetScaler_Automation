#!/usr/bin/env python3
"""Read-only NetScaler discovery and mapping tool.

Only HTTP GETs (plus NITRO login/logout for a session). Never changes config.

  discover:  find NetScalers in CIDRs / a host file (HTTPS 443 + NITRO / login page; optional SNMP)
  inventory: pull vservers, CS policies, services, backends via NITRO v1 -> CSV, JSON, Mermaid
  --sdx:     list VPX instances from an SDX Management Service (NITRO v2 /config/ns)

User defaults to nsadmin; password via getpass (never env/args). Needs: pip install requests
"""
import argparse
import concurrent.futures as cf
import csv
import getpass
import ipaddress
import json
import os
import re
import sys
import threading
import time
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit

try:
    import requests
    import urllib3
except ImportError:
    sys.exit("pip install requests")

PAGE = 500          # NITRO pagesize for large configs
CITRIX_OID = "1.3.6.1.4.1.5951"


class RateLimiter:
    """Simple global limit: at most `rate` new requests per second across threads."""

    def __init__(self, rate):
        self.gap = 1.0 / rate if rate > 0 else 0
        self.lock = threading.Lock()
        self.next = 0.0

    def wait(self):
        if not self.gap:
            return
        with self.lock:
            now = time.monotonic()
            t = max(now, self.next)
            self.next = t + self.gap
        time.sleep(max(0, t - now))



# ----------------------------------------------------------------- bookmarks
class BookmarkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.folder, self.await_h3, self.await_a, self.items, self.buf = [], False, None, [], []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        t = tag.lower()
        if t == "h3":
            self.await_h3, self.buf = True, []
        elif t == "a" and "href" in a:
            self.await_a, self.buf = a["href"], []

    def handle_endtag(self, tag):
        t = tag.lower()
        if t == "h3" and self.await_h3:
            self.folder.append("".join(self.buf).strip()); self.await_h3 = False
        elif t == "a" and self.await_a is not None:
            self.items.append((self.await_a, "".join(self.buf).strip(), " / ".join(self.folder)))
            self.await_a = None
        elif t == "dl" and self.folder:
            self.folder.pop()

    def handle_data(self, data):
        if self.await_h3 or self.await_a is not None:
            self.buf.append(data)


_HOST_ADC = re.compile(
    r"(^ns[a-z0-9-]*\.)|(^drns)|(^dzns)|(^edcns)|(^eflbns)|(^egwcns)|(^egwsns)|(^fdcns)|(^medxcn)|"
    r"ns(dmz|dst|int|app|data|leg)|(-adc-|_adc_|\badc\d)|(^|\.)sdx", re.IGNORECASE)
_HOST_SDX = re.compile(r"sdx|svm|medxcnmp", re.IGNORECASE)
_TITLE_SDX = re.compile(r"\bSDX\b|\bSVM\b", re.IGNORECASE)
_TITLE_ADM = re.compile(r"Management and Analytics|\bADM\b|\bMAS\b", re.IGNORECASE)
_TITLE_ADC = re.compile(
    r"NetScaler|Citrix ADC|\bNSIP\b|\bPri\b|\bSec\b|DMZ (Prod|Non)|Internal (Prod|App|Data)|PROD (DMZ|INT)|DEV (Pri|Sec)",
    re.IGNORECASE)
_FOLDER_NS = re.compile(r"Netscaler|NetScaler|Citrix ADC|GWNSM", re.IGNORECASE)
_PATH_MGMT = re.compile(r"/nitro|/menu|/mgmt|/nsconfig|/admin_ui|/gui|/sdx", re.IGNORECASE)
_PATH_PORTAL = re.compile(r"logonpoint|/vpn/|/citrix/|/logon/|/cgi/login|/nf/auth", re.IGNORECASE)
_TITLE_PORTAL = re.compile(r"\b(WebTop|Storefront|VPN|Access Gateway|Logon|Portal)\b", re.IGNORECASE)
_DOC_HOST = re.compile(r"(^|\.)(citrix\.com|docs\.netscaler|developer-docs\.netscaler)", re.IGNORECASE)
_TOOL = re.compile(r"VIP Info|Out of Service|Easy Config|Reset Packet|CTX\d+", re.IGNORECASE)


def _host_of(url):
    try:
        u = urlsplit(url)
    except ValueError:
        return None, None
    if u.scheme not in ("http", "https") or not u.hostname:
        return None, None
    h = u.hostname.lower()
    if u.port and not ((u.scheme == "https" and u.port == 443) or (u.scheme == "http" and u.port == 80)):
        h = f"{h}:{u.port}"
    return h, u


def classify_bookmark(url, title, folder):
    host, u = _host_of(url)
    if not host:
        return None
    path = u.path or ""
    in_ns = bool(_FOLDER_NS.search(folder))
    if _DOC_HOST.search(host):
        return host, "unknown", "excluded", "citrix.com / docs site"
    if _PATH_PORTAL.search(path) or _TITLE_PORTAL.search(title):
        return host, "gateway-vserver", "excluded", "gateway/VPN/WebTop/Storefront user portal"
    if _TITLE_ADM.search(title) or (re.search(r"mas|medxmas", host + title, re.IGNORECASE) and in_ns):
        return host, "ADM", "included", "ADM/MAS"
    if _TITLE_SDX.search(title) or (_HOST_SDX.search(host) and in_ns and re.search(r"sdx|svm", title + host, re.IGNORECASE)):
        return host, "SDX", "included", "SDX/SVM"
    if _HOST_ADC.search(host) and (in_ns or _TITLE_ADC.search(title) or _PATH_MGMT.search(path)):
        if _TOOL.search(title):
            return host, "ADC", "excluded", "tooling/info page, not management IP"
        return host, "ADC", "included", "ADC hostname + NetScaler folder/title"
    if in_ns and (_TITLE_ADC.search(title) or _PATH_MGMT.search(path)):
        if _TOOL.search(title):
            return host, "ADC", "excluded", "tooling/info page, not management IP"
        return host, "ADC", "included", "NetScaler folder + mgmt title/path"
    if in_ns:
        return host, "unknown", "excluded", "NetScaler folder but not clearly a management IP"
    return None


def parse_bookmarks(html_path, write_review=None):
    """Return (included_hosts_with_type, all_review_rows). Types: ADC/SDX/ADM."""
    bp = BookmarkParser()
    bp.feed(Path(html_path).read_text(encoding="utf-8", errors="replace"))
    rows = []
    for url, title, folder in bp.items:
        r = classify_bookmark(url, title, folder)
        if r:
            host, typ, incl, reason = r
            rows.append({"host": host, "title": title, "folder": folder,
                         "guessed_type": typ, "included": incl, "reason": reason})
    rank = {"SDX": 0, "ADM": 1, "ADC": 2, "gateway-vserver": 3, "unknown": 4}
    final = {}
    for r in rows:
        h = r["host"]
        cur = final.get(h)
        if cur is None or (r["included"] == "included" and cur["included"] != "included") or (
            r["included"] == cur["included"] and rank.get(r["guessed_type"], 9) < rank.get(cur["guessed_type"], 9)
        ):
            if cur and r["included"] != "included" and cur["included"] == "included":
                continue
            final[h] = r
    review = sorted(final.values(), key=lambda x: x["host"])
    if write_review:
        Path(write_review).parent.mkdir(parents=True, exist_ok=True)
        with open(write_review, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["host", "title", "folder", "guessed_type", "included", "reason"])
            w.writeheader(); w.writerows(review)
    included = [(r["host"], r["guessed_type"]) for r in review if r["included"] == "included"]
    return included, review

# ----------------------------------------------------------------- discovery
def targets(cidrs, hostfile):
    out = []
    for c in cidrs or []:
        net = ipaddress.ip_network(c, strict=False)
        out += [str(h) for h in (net.hosts() if net.num_addresses > 2 else net)]
    if hostfile:
        with open(hostfile, encoding="utf-8") as f:
            out += [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    return list(dict.fromkeys(out))


def snmp_is_citrix(host, community, timeout):
    """Optional: sysObjectID under Citrix enterprise 5951. Skipped if pysnmp missing."""
    try:
        from pysnmp.hlapi import (
            CommunityData,
            ContextData,
            ObjectIdentity,
            ObjectType,
            SnmpEngine,
            UdpTransportTarget,
            getCmd,
        )
    except ImportError:
        return None
    it = getCmd(SnmpEngine(), CommunityData(community, mpModel=1),
                UdpTransportTarget((host, 161), timeout=timeout, retries=0), ContextData(),
                ObjectType(ObjectIdentity("1.3.6.1.2.1.1.2.0")))
    err, status, _, binds = next(it)
    if err or status:
        return False
    return any(str(v).startswith(CITRIX_OID) for _, v in binds)


def probe(host, a, rl):
    """Return a dict if host looks like a NetScaler, else None."""
    rl.wait()
    res = {"host": host, "nitro": False, "login_page": False, "snmp_citrix": None, "version": ""}
    base = f"https://{host}"
    try:
        r = requests.get(f"{base}/nitro/v1/config/nsversion", timeout=a.timeout, verify=not a.insecure,
                         headers={"Accept": "application/json"}, allow_redirects=False)
        try:
            j = r.json()
        except ValueError:
            j = {}
        # NITRO answers with {"errorcode":..,"message":..,"severity":..} even on 401
        if isinstance(j, dict) and "errorcode" in j and "severity" in j:
            res["nitro"] = True
            res["version"] = (j.get("nsversion") or {}).get("version", "") if r.status_code == 200 else ""
        if not res["nitro"]:
            rl.wait()
            p = requests.get(f"{base}/logon/LogonPoint/index.html", timeout=a.timeout,
                             verify=not a.insecure, allow_redirects=True)
            if re.search(r"NetScaler|Citrix ADC|ns_gui|LogonPoint", p.text, re.IGNORECASE):
                res["login_page"] = True
    except requests.RequestException as e:
        res["error"] = nitro_err(e)
        return res if a.keep_all else None
    if a.snmp_community:
        res["snmp_citrix"] = snmp_is_citrix(host, a.snmp_community, a.timeout)
    ok = res["nitro"] or res["login_page"] or res["snmp_citrix"]
    return res if (ok or a.keep_all) else None


def discover(a):
    hosts = targets(a.cidr, a.hosts)
    print(f"Probing {len(hosts)} hosts on 443 ...", file=sys.stderr)
    rl = RateLimiter(a.rate)
    found = []
    with cf.ThreadPoolExecutor(max_workers=a.workers) as ex:
        for r in ex.map(lambda h: probe(h, a, rl), hosts):
            if r:
                found.append(r)
                det = r["nitro"] or r["login_page"] or r["snmp_citrix"]
                status(r["host"], "probe", "found" if det else "no-sign", r.get("error", "") or
                       f"nitro={r['nitro']} login_page={r['login_page']} version={r['version']}")
    return found


# ----------------------------------------------------------------- NITRO client
STATUS, _SLOCK = [], threading.Lock()
DEBUG = False


def status(host, step, result, error=""):
    """Per-host console line + row for status.csv (never contains secrets)."""
    with _SLOCK:
        STATUS.append({"host": host, "step": step, "result": result, "error": error})
    print(f"  [{result:^7}] {host:<40} {step:<10} {error}", file=sys.stderr, flush=True)


def write_status(outdir):
    os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, "status.csv"), "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=["host", "step", "result", "error"])
        w.writeheader()
        w.writerows(STATUS)


def dbg(msg):
    if DEBUG:
        print(f"    debug: {msg}", file=sys.stderr, flush=True)


def nitro_err(e):
    """HTTP status, URL path and NITRO errorcode/message from body. No headers, no request body."""
    r = getattr(e, "response", None)
    if r is None:
        return f"{type(e).__name__}: {str(e)[:200]}"
    path = urlsplit(r.url or "").path
    try:
        j = r.json()
    except ValueError:
        j = {}
    code = j.get("errorcode", "") if isinstance(j, dict) else ""
    msg = (j.get("message", "") if isinstance(j, dict) else "") or (r.text or "")[:120].replace("\n", " ")
    return f"HTTP {r.status_code} {path} errorcode={code} message={msg}".strip()


class Nitro:
    """Read-only NITRO client. Auth per docs (ADC v1 and SDX v2 'login' object):
    1) POST config/login {"login": {"username","password"}} -> sessionid, sent as Cookie NITRO_AUTH_TOKEN;
    2) fallback: per-request X-NITRO-USER / X-NITRO-PASS headers (no cookie). Login/logout change no config."""

    def __init__(self, host, user, pw, a, version="v1"):
        self.host, self.version = host, version
        self.base = f"https://{host}/nitro/{version}"
        self.s = requests.Session()
        self.s.verify = not a.insecure
        self.s.headers.update({"Accept": "application/json"})
        self.timeout = a.timeout
        self.rl = RateLimiter(a.rate)
        self.auth = ""
        self._login(user, pw)

    def _req(self, method, path, **kw):
        self.rl.wait()
        t = time.monotonic()
        r = self.s.request(method, f"{self.base}/{path}", timeout=self.timeout, **kw)
        dbg(f"{method} {urlsplit(r.url).path}{'?' + urlsplit(r.url).query if urlsplit(r.url).query else ''}"
            f" -> {r.status_code} ({time.monotonic() - t:.2f}s)")
        return r

    def _login(self, user, pw):
        sess_err = ""
        try:
            r = self._req("POST", "config/login", json={"login": {"username": user, "password": pw}},
                          headers={"Content-Type": "application/json"})
            if r.status_code in (200, 201):
                j = r.json()
                lg = j.get("login")
                sid = j.get("sessionid") or ((lg[0] if isinstance(lg, list) and lg else lg or {}).get("sessionid")
                                             if isinstance(lg, (list, dict)) else None)
                if sid:
                    self.s.cookies.set("NITRO_AUTH_TOKEN", sid)
                    self.auth = "session"
                    return
            r.raise_for_status()
            sess_err = "login ok but no sessionid"
        except requests.HTTPError as e:
            sess_err = nitro_err(e)
        except ValueError:
            sess_err = "login reply not JSON"
        dbg(f"session login failed ({sess_err}); falling back to X-NITRO-USER headers")
        self.s.cookies.clear()
        self.s.headers.update({"X-NITRO-USER": user, "X-NITRO-PASS": pw})
        r = self._req("GET", "config/nsversion" if self.version == "v1" else "config/ns", params={"pagesize": 1}
                      if self.version == "v2" else None)
        if r.status_code in (401, 403):
            raise requests.HTTPError(f"login failed both ways; session: {sess_err}", response=r)
        self.auth = "headers"

    def logout(self):
        if self.auth == "session":
            try:
                self._req("POST", "config/logout", json={"logout": {}}, headers={"Content-Type": "application/json"})
            except requests.RequestException:
                pass

    def get(self, path, params=None):
        r = self._req("GET", path, params=params)
        if r.status_code == 404:
            return {}
        r.raise_for_status()
        try:
            return r.json()
        except ValueError:
            raise requests.HTTPError("reply is not NITRO JSON (redirect/GUI page?)", response=r) from None

    def get_all(self, res):
        """Paged GET of a config resource. Returns a list."""
        cnt = self.get(f"config/{res}", {"count": "yes"}).get(res, [{}])
        total = int((cnt[0] if cnt else {}).get("__count", 0) or 0)
        if total <= PAGE:
            return self.get(f"config/{res}").get(res, []) if total or not cnt else []
        out = []
        for page in range(1, total // PAGE + 2):
            out += self.get(f"config/{res}", {"pagesize": PAGE, "pageno": page}).get(res, [])
        return out

    def bindings(self, res):
        """Bulk binding read (get-all on *_binding requires bulkbindings=yes)."""
        return self.get(f"config/{res}", {"bulkbindings": "yes"}).get(res, [])


# ----------------------------------------------------------------- inventory
def inventory_one(host, user, pw, a):
    d = {"host": host, "error": ""}
    n = None
    try:
        n = Nitro(host, user, pw, a)
        status(host, "login", "ok", f"auth={n.auth}")
        d["version"] = (n.get("config/nsversion").get("nsversion") or {}).get("version", "")
        d["hostname"] = (n.get("config/nshostname").get("nshostname") or [{}])[0].get("hostname", "")
        ha = n.get_all("hanode")
        local = next((h for h in ha if str(h.get("id")) == "0"), {})
        d["ha_state"] = local.get("state", "")          # Primary / Secondary / ...
        d["ha_status"] = local.get("hastatus", "")
        d["ha_peers"] = [h.get("ipaddress") for h in ha if str(h.get("id")) != "0"]
        ips = n.get_all("nsip")
        d["ips"] = [{k: i.get(k) for k in ("ipaddress", "netmask", "type", "state", "mgmtaccess")} for i in ips]
        d["nsip"] = next((i["ipaddress"] for i in ips if i.get("type") == "NSIP"), host)
        d["role"] = "secondary-skipped" if d["ha_state"].lower() == "secondary" and not a.include_secondary else "full"
        if d["role"] != "full":
            status(host, "inventory", "skipped", "HA secondary (use --include-secondary)")
            return d
        d["lbvserver"] = [{k: v.get(k) for k in ("name", "ipv46", "port", "servicetype", "curstate", "lbmethod")}
                          for v in n.get_all("lbvserver")]
        d["csvserver"] = [{k: v.get(k) for k in ("name", "ipv46", "port", "servicetype", "curstate")}
                          for v in n.get_all("csvserver")]
        d["cs_policy_bind"] = [{k: b.get(k) for k in ("name", "policyname", "rule", "targetlbvserver", "priority",
                                                       "labelname")}
                               for b in n.bindings("csvserver_cspolicy_binding")]
        d["cs_default_lb"] = [{"name": b.get("name"), "lbvserver": b.get("lbvserver")}
                              for b in n.bindings("csvserver_lbvserver_binding") if b.get("lbvserver")]
        # rule may be empty on the binding in some builds: fill from cspolicy
        rules = {p.get("policyname"): p.get("rule") for p in n.get_all("cspolicy")}
        for b in d["cs_policy_bind"]:
            b["rule"] = b.get("rule") or rules.get(b.get("policyname"), "")
        d["lb_service_bind"] = [{k: b.get(k) for k in ("name", "servicename", "ipv46", "port", "servicetype",
                                                        "curstate")}
                                for b in n.bindings("lbvserver_service_binding")]
        d["lb_sg_bind"] = [{"name": b.get("name"), "servicegroupname": b.get("servicegroupname")}
                           for b in n.bindings("lbvserver_servicegroup_binding")]
        d["sg_members"] = [{k: b.get(k) for k in ("servicegroupname", "servername", "ip", "port", "svrstate")}
                           for b in n.bindings("servicegroup_servicegroupmember_binding")]
        d["services"] = [{k: s.get(k) for k in ("name", "servername", "ipaddress", "port", "servicetype",
                                                 "svrstate")} for s in n.get_all("service")]
        if a.gslb:
            d["gslbvserver"] = [{k: v.get(k) for k in ("name", "servicetype", "curstate", "dnsrecordtype")}
                                for v in n.get_all("gslbvserver")]
        collect_netauth(n, d)
        status(host, "inventory", "ok", f"{len(d.get('lbvserver', []))} lb, {len(d.get('csvserver', []))} cs,"
               f" unsupported={len(d.get('unsupported', []))}")
    except requests.RequestException as e:
        d["error"] = nitro_err(e)
        status(host, "login" if n is None else "inventory", "FAILED", d["error"])
    except ValueError as e:
        d["error"] = f"bad JSON: {e}"[:200]
        status(host, "inventory", "FAILED", d["error"])
    finally:
        if n:
            n.logout()
    return d


def backends(d):
    svc = {s["name"]: s for s in d.get("services", [])}
    rows = []
    for b in d.get("lb_service_bind", []):
        s = svc.get(b["servicename"], {})
        rows.append({"device": d.get("hostname") or d["host"], "lbvserver": b["name"], "via": "service",
                     "member": b["servicename"], "server": s.get("servername", ""),
                     "ip": s.get("ipaddress") or b.get("ipv46", ""), "port": s.get("port") or b.get("port", ""),
                     "state": s.get("svrstate") or b.get("curstate", "")})
    mem = {}
    for m in d.get("sg_members", []):
        mem.setdefault(m["servicegroupname"], []).append(m)
    for b in d.get("lb_sg_bind", []):
        for m in mem.get(b["servicegroupname"], []):
            rows.append({"device": d.get("hostname") or d["host"], "lbvserver": b["name"], "via": "servicegroup",
                         "member": b["servicegroupname"], "server": m.get("servername", ""), "ip": m.get("ip", ""),
                         "port": m.get("port", ""), "state": m.get("svrstate", "")})
    return rows


def mid(s):
    return "n_" + re.sub(r"\W", "_", str(s))


def mermaid(d):
    """CS vserver -> policy -> LB vserver -> backend server."""
    L = ["flowchart LR"]
    for cs in d.get("csvserver", []):
        L.append(f'  {mid("cs" + cs["name"])}["CS {cs["name"]}<br/>{cs.get("ipv46")}:{cs.get("port")}"]')
    for b in d.get("cs_policy_bind", []):
        p = mid("pol" + b["name"] + str(b["policyname"]))
        rule = str(b.get("rule") or "").replace('"', "'")[:60]
        L.append(f'  {mid("cs" + b["name"])} --> {p}["{b["policyname"]} (p{b.get("priority")})<br/>{rule}"]')
        if b.get("targetlbvserver"):
            L.append(f'  {p} --> {mid("lb" + b["targetlbvserver"])}["LB {b["targetlbvserver"]}"]')
    for b in d.get("cs_default_lb", []):
        L.append(f'  {mid("cs" + b["name"])} -. default .-> {mid("lb" + b["lbvserver"])}["LB {b["lbvserver"]}"]')
    for r in backends(d):
        L.append(f'  {mid("lb" + r["lbvserver"])} --> {mid("srv" + r["ip"] + str(r["port"]))}'
                 f'["{r["server"] or r["ip"]}<br/>{r["ip"]}:{r["port"]}"]')
    return "\n".join(dict.fromkeys(L)) + "\n"


def write_outputs(devs, outdir, sdx_rows=None):
    os.makedirs(outdir, exist_ok=True)

    def wcsv(name, rows, cols):
        with open(os.path.join(outdir, name), "w", newline="", encoding="utf-8-sig") as f:
            w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
            w.writeheader()
            w.writerows(rows)

    wcsv("devices.csv", [{**d, "ha_peers": ";".join(filter(None, d.get("ha_peers", []))),
                          "all_ips": ";".join(f'{i["ipaddress"]}({i["type"]})' for i in d.get("ips", []))}
                         for d in devs],
         ["host", "hostname", "nsip", "version", "ha_state", "ha_status", "ha_peers", "role", "all_ips", "error"])
    vips = []
    for d in devs:
        dev = d.get("hostname") or d["host"]
        vips += [{"device": dev, "type": "lb", **v} for v in d.get("lbvserver", [])]
        vips += [{"device": dev, "type": "cs", **v} for v in d.get("csvserver", [])]
        vips += [{"device": dev, "type": "gslb", **v} for v in d.get("gslbvserver", [])]
    wcsv("vips.csv", vips, ["device", "type", "name", "ipv46", "port", "servicetype", "curstate", "lbmethod"])
    cs = []
    for d in devs:
        dev = d.get("hostname") or d["host"]
        cs += [{"device": dev, "csvserver": b["name"], "policy": b["policyname"], "priority": b.get("priority"),
                "rule": b.get("rule"), "target_lbvserver": b.get("targetlbvserver")} for b in d.get("cs_policy_bind", [])]
        cs += [{"device": dev, "csvserver": b["name"], "policy": "(default)", "priority": "",
                "rule": "", "target_lbvserver": b["lbvserver"]} for b in d.get("cs_default_lb", [])]
    wcsv("cs_map.csv", cs, ["device", "csvserver", "policy", "priority", "rule", "target_lbvserver"])
    wcsv("backends.csv", [r for d in devs for r in backends(d)],
         ["device", "lbvserver", "via", "member", "server", "ip", "port", "state"])
    wcsv("network.csv", [r for d in devs for r in network_rows(d)],
         ["device", "kind", "name", "type", "subnet", "vlan", "detail"])
    wcsv("auth.csv", [r for d in devs for r in auth_rows(d)],
         ["device", "entry", "entry_type", "step", "priority", "policy", "action", "action_type", "server",
          "nextfactor", "detail"])
    with open(os.path.join(outdir, "inventory.json"), "w", encoding="utf-8") as f:
        json.dump(mask(devs), f, indent=2)
    diagrams = []

    def wmmd(fname, text):
        Path(outdir, fname).write_text(text, encoding="utf-8")
        diagrams.append((fname, text))

    wmmd("network_map.mmd", mermaid_estate(devs, sdx_rows))
    for d in devs:
        if d.get("role") == "full" and not d.get("error"):
            name = re.sub(r"[^\w.-]", "_", d.get("hostname") or d["host"])
            wmmd(f"{name}.mmd", mermaid(d))
            wmmd(f"network_{name}.mmd", mermaid_network(d))
            wmmd(f"auth_{name}.mmd", mermaid_auth(d))
    write_report(outdir, diagrams)
    print(f"Wrote outputs to {outdir}", file=sys.stderr)


# ----------------------------------------------------------------- network + auth (read-only)
SECRET_KEY = re.compile(r"pass|secret|key(?!word)|token|bindpw|sharedsecret|radkey|pwd|credential|privkey|"
                        r"clientsecret|signingcert.*pass|encrypt", re.IGNORECASE)
# keys that match the pattern but are names/refs, not secrets (kept)
SECRET_ALLOW = {"keyname", "certkeyname", "sslcertkeyname", "samlidpcertname", "samlsigningcertname",
                "signingcertname", "encryptmethod", "encryptiontype", "lacpkey"}


def mask(obj):
    """Recursively replace every secret-looking value with ***. Never emit secrets."""
    if isinstance(obj, dict):
        return {k: ("***" if (SECRET_KEY.search(k) and k.lower() not in SECRET_ALLOW and v not in (None, ""))
                    else mask(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [mask(v) for v in obj]
    return obj


def pick(rows, keys):
    return [mask({k: r.get(k) for k in keys if r.get(k) not in (None, "")}) for r in rows]


NET_RES = {
    "vlan": ("get_all", ["id", "aliasname", "sharing", "ipv6dynamicrouting"]),
    "vlan_interface_binding": ("bindings", ["id", "ifnum", "tagged"]),
    "vlan_nsip_binding": ("bindings", ["id", "ipaddress", "netmask", "td"]),
    "route": ("get_all", ["network", "netmask", "gateway", "vlan", "td", "type", "routetype"]),
    "interface": ("get_all", ["id", "devicename", "intftype", "state", "linkstate", "mtu", "vlan", "tagall",
                              "lacpmode", "lacpkey", "ifalias"]),
    "channel": ("get_all", ["id", "ifnum", "state", "mode", "conndistr", "tagall", "mtu"]),
    "nstrafficdomain": ("get_all", ["td", "aliasname", "vmac", "state"]),
    "nspartition": ("get_all", ["partitionname", "partitionid", "maxbandwidth"]),
}

AUTH_RES = {
    "authenticationvserver": ("get_all", ["name", "ipv46", "port", "servicetype", "curstate", "authentication",
                                          "authenticationdomain", "td"]),
    "authenticationvserver_authenticationpolicy_binding": ("bindings", ["name", "policy", "priority",
                                                                        "nextfactor", "gotopriorityexpression",
                                                                        "secondary", "groupextraction"]),
    "authenticationvserver_authenticationloginschemapolicy_binding": ("bindings", ["name", "policy", "priority"]),
    "authenticationvserver_authenticationsamlidppolicy_binding": ("bindings", ["name", "policy", "priority"]),
    "authenticationpolicy": ("get_all", ["name", "rule", "action"]),
    "authenticationpolicylabel": ("get_all", ["labelname", "type", "loginschema"]),
    "authenticationpolicylabel_authenticationpolicy_binding": ("bindings", ["labelname", "policyname", "priority",
                                                                            "nextfactor", "gotopriorityexpression"]),
    "authenticationloginschema": ("get_all", ["name", "authenticationschema", "ssocredentials"]),
    "authenticationloginschemapolicy": ("get_all", ["name", "rule", "action"]),
    "authenticationldapaction": ("get_all", ["name", "serverip", "servername", "serverport", "sectype",
                                             "ldapbase", "ldapbinddn", "ldaploginname", "groupattrname"]),
    "authenticationradiusaction": ("get_all", ["name", "serverip", "servername", "serverport"]),
    "authenticationsamlaction": ("get_all", ["name", "samlidpcertname", "samlredirecturl", "samlissuername",
                                             "samluserfield", "metadataurl"]),
    "authenticationoauthaction": ("get_all", ["name", "authorizationendpoint", "tokenendpoint", "clientid",
                                              "idtokendecryptendpoint", "oauthtype", "metadataurl"]),
    "authenticationcertaction": ("get_all", ["name", "usernamefield", "groupnamefield", "twofactor"]),
    "authenticationnegotiateaction": ("get_all", ["name", "domain", "domainuser", "ntlmpath"]),
    "authenticationepaaction": ("get_all", ["name", "csecexpr", "defaultepagroup", "quarantinegroup"]),
    "authenticationsamlidpprofile": ("get_all", ["name", "samlspcertname", "assertionconsumerserviceurl",
                                                 "samlissuername", "audience", "metadataurl"]),
    "authenticationauthnprofile": ("get_all", ["name", "authnvsname", "authenticationhost",
                                               "authenticationdomain"]),
    "vpnvserver": ("get_all", ["name", "ipv46", "port", "curstate", "authentication", "authnprofile",
                               "loginonce"]),
    "vpnvserver_authenticationpolicy_binding": ("bindings", ["name", "policy", "priority", "secondary",
                                                             "groupextraction"]),
    "vpnvserver_authenticationldappolicy_binding": ("bindings", ["name", "policy", "priority", "secondary"]),
    "vpnvserver_authenticationradiuspolicy_binding": ("bindings", ["name", "policy", "priority", "secondary"]),
    "vpnvserver_authenticationsamlpolicy_binding": ("bindings", ["name", "policy", "priority", "secondary"]),
    "vpnvserver_authenticationcertpolicy_binding": ("bindings", ["name", "policy", "priority", "secondary"]),
    "authenticationldappolicy": ("get_all", ["name", "rule", "reqaction"]),
    "authenticationradiuspolicy": ("get_all", ["name", "rule", "reqaction"]),
    "authenticationsamlpolicy": ("get_all", ["name", "rule", "reqaction"]),
    "authenticationcertpolicy": ("get_all", ["name", "rule", "reqaction"]),
    "tmsessionaction": ("get_all", ["name", "sso", "ssocredential", "ssodomain", "httponlycookie", "kcdaccount"]),
    "systemglobal_authenticationpolicy_binding": ("bindings", ["policyname", "priority", "nextfactor",
                                                               "gotopriorityexpression"]),
    "systemglobal_authenticationldappolicy_binding": ("bindings", ["policyname", "priority"]),
    "systemglobal_authenticationradiuspolicy_binding": ("bindings", ["policyname", "priority"]),
}
VS_AUTHN_KEYS = ["name", "ipv46", "port", "authentication", "authn401", "authnvsname", "authnprofile",
                 "authenticationhost"]


def collect(n, table, d):
    missing = []
    for res, (meth, keys) in table.items():
        try:
            rows = getattr(n, meth)(res)
        except requests.HTTPError as e:
            rows, _ = [], missing.append(res)
            dbg(f"{n.host} {res}: {nitro_err(e)}")
        d[res] = pick(rows, keys)
    d.setdefault("unsupported", []).extend(missing)


def collect_netauth(n, d):
    collect(n, NET_RES, d)
    collect(n, AUTH_RES, d)
    # lb/cs authn settings re-read with authn fields only (base read keeps VIP fields)
    for res in ("lbvserver", "csvserver"):
        try:
            d[f"{res}_authn"] = [r for r in pick(n.get_all(res), VS_AUTHN_KEYS)
                                 if r.get("authentication") == "ON" or r.get("authnprofile") or r.get("authnvsname")]
        except requests.HTTPError:
            d[f"{res}_authn"] = []


# --- network outputs
def _net(ip, mask_):
    try:
        return str(ipaddress.ip_interface(f"{ip}/{mask_}").network)
    except ValueError:
        return ""


def network_rows(d):
    dev = d.get("hostname") or d["host"]
    rows = []
    for i in d.get("ips", []):
        rows.append({"device": dev, "kind": "ip", "name": i.get("ipaddress"), "type": i.get("type"),
                     "subnet": _net(i.get("ipaddress"), i.get("netmask") or "255.255.255.255"),
                     "vlan": "", "detail": f"state={i.get('state')} mgmt={i.get('mgmtaccess')}"})
    for b in d.get("vlan_nsip_binding", []):
        rows.append({"device": dev, "kind": "vlan_ip", "name": b.get("ipaddress"), "type": "",
                     "subnet": _net(b.get("ipaddress"), b.get("netmask")), "vlan": b.get("id"), "detail": ""})
    for b in d.get("vlan_interface_binding", []):
        rows.append({"device": dev, "kind": "vlan_if", "name": b.get("ifnum"), "type": "tagged" if
                     str(b.get("tagged")).lower() in ("true", "yes") else "untagged",
                     "subnet": "", "vlan": b.get("id"), "detail": ""})
    for v in d.get("vlan", []):
        rows.append({"device": dev, "kind": "vlan", "name": v.get("aliasname", ""), "type": "",
                     "subnet": "", "vlan": v.get("id"), "detail": f"sharing={v.get('sharing', '')}"})
    for r in d.get("route", []):
        rows.append({"device": dev, "kind": "route", "name": _net(r.get("network"), r.get("netmask")),
                     "type": r.get("routetype") or r.get("type", ""), "subnet": "", "vlan": r.get("vlan", ""),
                     "detail": f"gw={r.get('gateway')}"})
    for i in d.get("interface", []):
        rows.append({"device": dev, "kind": "interface", "name": i.get("devicename") or i.get("id"),
                     "type": i.get("intftype", ""), "subnet": "", "vlan": i.get("vlan", ""),
                     "detail": f"link={i.get('linkstate')} lacpkey={i.get('lacpkey', '')}"})
    for c in d.get("channel", []):
        rows.append({"device": dev, "kind": "channel", "name": c.get("id"), "type": c.get("mode", ""),
                     "subnet": "", "vlan": "", "detail": f"members={c.get('ifnum')}"})
    for t in d.get("nstrafficdomain", []):
        rows.append({"device": dev, "kind": "trafficdomain", "name": t.get("td"), "type": "",
                     "subnet": "", "vlan": "", "detail": t.get("aliasname", "")})
    for p in d.get("nspartition", []):
        rows.append({"device": dev, "kind": "partition", "name": p.get("partitionname"), "type": "",
                     "subnet": "", "vlan": "", "detail": f"id={p.get('partitionid')}"})
    return rows


def q(s):
    return str(s).replace('"', "'")


def ip_subnets(d):
    """{subnet: vlan_id or '1'} from NSIP/SNIP list + vlan bindings."""
    out = {}
    for i in d.get("ips", []):
        if i.get("type") in ("NSIP", "SNIP", "MIP"):
            s = _net(i.get("ipaddress"), i.get("netmask") or "255.255.255.255")
            if s:
                out.setdefault(s, "1")
    for b in d.get("vlan_nsip_binding", []):
        s = _net(b.get("ipaddress"), b.get("netmask"))
        if s:
            out[s] = str(b.get("id"))
    return out


def mermaid_network(d):
    """subnet -> VLAN -> interface/channel ; routes -> gateway."""
    L = ["flowchart LR"]
    for s, v in ip_subnets(d).items():
        L.append(f'  {mid("sub" + s)}["subnet {s}"] --> {mid("vlan" + v)}{{"VLAN {v}"}}')
    for b in d.get("vlan_interface_binding", []):
        tag = "tagged" if str(b.get("tagged")).lower() in ("true", "yes") else "untagged"
        L.append(f'  {mid("vlan" + str(b.get("id")))}{{"VLAN {b.get("id")}"}} -- {tag} --> '
                 f'{mid("if" + str(b.get("ifnum")))}["if {q(b.get("ifnum"))}"]')
    for c in d.get("channel", []):
        for m in re.split(r"[ ,;]+", str(c.get("ifnum") or "")):
            if m and m != "None":
                L.append(f'  {mid("if" + str(c.get("id")))}["if {q(c.get("id"))}"] --- {mid("if" + m)}["if {q(m)}"]')
    for r in d.get("route", []):
        gw = r.get("gateway")
        if gw and gw != "0.0.0.0":
            net = _net(r.get("network"), r.get("netmask"))
            via = next((s for s in ip_subnets(d) if ipaddress.ip_address(gw) in ipaddress.ip_network(s)), None) \
                if re.match(r"^[\d.]+$", gw) else None
            src = mid("sub" + via) if via else mid("dev")
            L.append(f'  {src} --> {mid("gw" + gw)}(["gw {gw}<br/>to {net}"])')
    if len(L) == 1:
        L.append(f'  {mid("dev")}["{q(d.get("hostname") or d["host"])}<br/>no network data"]')
    return "\n".join(dict.fromkeys(L)) + "\n"


def mermaid_estate(devs, sdx_rows):
    """Devices grouped by management subnet; shared data subnets; HA pairs; SDX -> VPX."""
    L = ["flowchart TB"]
    by_ip = {}
    for d in devs:
        for i in d.get("ips", []):
            by_ip[i.get("ipaddress")] = d
    groups = {}
    for d in devs:
        nsip = d.get("nsip") or d["host"]
        m = next((i for i in d.get("ips", []) if i.get("type") == "NSIP"), None)
        g = _net(m["ipaddress"], m.get("netmask")) if m and m.get("netmask") else "unknown mgmt subnet"
        groups.setdefault(g, []).append((d, nsip))
    for g, items in groups.items():
        L.append(f'  subgraph {mid("mg" + g)}["mgmt {g}"]')
        for d, nsip in items:
            L.append(f'    {mid("d" + d["host"])}["{q(d.get("hostname") or d["host"])}<br/>{nsip}'
                     f'<br/>{q(d.get("ha_state", ""))}"]')
        L.append("  end")
    shared = {}
    for d in devs:
        for s, v in ip_subnets(d).items():
            shared.setdefault((s, v), set()).add(d["host"])
    mgmt = set(groups)
    for (s, v), hosts in shared.items():
        if s in mgmt:
            continue
        node = mid("sh" + s)
        L.append(f'  {node}[("subnet {s} / VLAN {v}")]')
        for h in sorted(hosts):
            L.append(f"  {mid('d' + h)} --- {node}")
    seen = set()
    for d in devs:
        for p in d.get("ha_peers", []):
            peer = by_ip.get(p)
            pid = mid("d" + peer["host"]) if peer else mid("d" + str(p))
            if not peer:
                L.append(f'  {pid}["HA peer {p}<br/>(not read)"]')
            key = tuple(sorted((d["host"], peer["host"] if peer else str(p))))
            if key not in seen:
                seen.add(key)
                L.append(f"  {mid('d' + d['host'])} <-. HA .-> {pid}")
    for r in sdx_rows or []:
        s = mid("sdx" + r["sdx"])
        L.append(f'  {s}[/"SDX {q(r["sdx"])}"/]')
        tgt = by_ip.get(r.get("ip_address"))
        v = mid("d" + tgt["host"]) if tgt else mid("vpx" + str(r.get("ip_address")))
        if not tgt:
            L.append(f'  {v}["VPX {q(r.get("name"))}<br/>{r.get("ip_address")}"]')
        L.append(f"  {s} ==> {v}")
    return "\n".join(dict.fromkeys(L)) + "\n"


# --- auth outputs
def _actions(d):
    """action name -> (kind, server)"""
    out = {}
    for kind, res, srv in (("LDAP", "authenticationldapaction", "serverip"),
                           ("RADIUS", "authenticationradiusaction", "serverip"),
                           ("SAML", "authenticationsamlaction", "samlredirecturl"),
                           ("OAuth", "authenticationoauthaction", "authorizationendpoint"),
                           ("CERT", "authenticationcertaction", "usernamefield"),
                           ("Negotiate", "authenticationnegotiateaction", "domain"),
                           ("EPA", "authenticationepaaction", "csecexpr")):
        for a in d.get(res, []):
            server = a.get(srv) or a.get("servername") or a.get("metadataurl") or ""
            if kind in ("LDAP", "RADIUS") and a.get("serverport"):
                server = f"{server}:{a.get('serverport')}"
            out[a["name"]] = (kind, str(server))
    return out


def _policies(d):
    pol = {p["name"]: p.get("action") for p in d.get("authenticationpolicy", [])}
    for res in ("authenticationldappolicy", "authenticationradiuspolicy", "authenticationsamlpolicy",
                "authenticationcertpolicy"):
        pol.update({p["name"]: p.get("reqaction") for p in d.get(res, [])})
    return pol


def auth_rows(d):
    dev = d.get("hostname") or d["host"]
    acts, pols = _actions(d), _policies(d)
    rows = []

    def add(entry, entry_type, step, prio, policy, nextf="", extra=""):
        act = pols.get(policy, "")
        kind, server = acts.get(act, ("", ""))
        rows.append({"device": dev, "entry": entry, "entry_type": entry_type, "step": step, "priority": prio,
                     "policy": policy, "action": act, "action_type": kind, "server": server,
                     "nextfactor": nextf, "detail": extra})

    for b in d.get("authenticationvserver_authenticationpolicy_binding", []):
        add(b["name"], "authnvserver", "factor1", b.get("priority"), b.get("policy"), b.get("nextfactor", ""))
    for b in d.get("authenticationvserver_authenticationloginschemapolicy_binding", []):
        add(b["name"], "authnvserver", "loginschema", b.get("priority"), b.get("policy"))
    for b in d.get("authenticationvserver_authenticationsamlidppolicy_binding", []):
        add(b["name"], "authnvserver", "samlidp", b.get("priority"), b.get("policy"))
    for b in d.get("authenticationpolicylabel_authenticationpolicy_binding", []):
        add(b["labelname"], "policylabel", "factorN", b.get("priority"), b.get("policyname"), b.get("nextfactor", ""))
    for b in (d.get("vpnvserver_authenticationpolicy_binding", []) +
              d.get("vpnvserver_authenticationldappolicy_binding", []) +
              d.get("vpnvserver_authenticationradiuspolicy_binding", []) +
              d.get("vpnvserver_authenticationsamlpolicy_binding", []) +
              d.get("vpnvserver_authenticationcertpolicy_binding", [])):
        add(b["name"], "vpnvserver", "secondary" if str(b.get("secondary")).lower() in ("true", "on") else "primary",
            b.get("priority"), b.get("policy"), b.get("nextfactor", ""))
    for b in (d.get("systemglobal_authenticationpolicy_binding", []) +
              d.get("systemglobal_authenticationldappolicy_binding", []) +
              d.get("systemglobal_authenticationradiuspolicy_binding", [])):
        add("systemglobal", "admin-login", "admin", b.get("priority"), b.get("policyname"), b.get("nextfactor", ""))
    for res, typ in (("vpnvserver", "vpnvserver"), ("lbvserver_authn", "lbvserver"), ("csvserver_authn", "csvserver")):
        for v in d.get(res, []):
            rows.append({"device": dev, "entry": v["name"], "entry_type": typ, "step": "vserver-settings",
                         "priority": "", "policy": "", "action": "", "action_type": "", "server":
                         f'{v.get("ipv46", "")}:{v.get("port", "")}', "nextfactor": "",
                         "detail": ";".join(f"{k}={v[k]}" for k in ("authentication", "authn401", "authnvsname",
                                                                     "authnprofile", "authenticationhost") if k in v)})
    for s in d.get("tmsessionaction", []):
        rows.append({"device": dev, "entry": s["name"], "entry_type": "tmsessionaction", "step": "sso",
                     "priority": "", "policy": "", "action": "", "action_type": "", "server": "",
                     "nextfactor": "", "detail": f"sso={s.get('sso', '')} cred={s.get('ssocredential', '')} "
                                                 f"domain={s.get('ssodomain', '')}"})
    return rows


def mermaid_auth(d):
    """client -> VIP -> authn profile/vserver -> nFactor steps by priority -> IdP/LDAP/RADIUS."""
    L = ["flowchart LR", '  client(("client"))', '  admin(("admin login"))']
    acts, pols = _actions(d), _policies(d)
    prof = {p["name"]: p.get("authnvsname") for p in d.get("authenticationauthnprofile", [])}
    avs = {v["name"]: v for v in d.get("authenticationvserver", [])}
    labels = {lb["labelname"]: lb for lb in d.get("authenticationpolicylabel", [])}

    def avs_node(name):
        v = avs.get(name, {})
        L.append(f'  {mid("avs" + name)}[["AAA {q(name)}<br/>{v.get("ipv46", "")}"]]')
        return mid("avs" + name)

    def step(src, policy, prio, nextf):
        act = pols.get(policy, "")
        kind, server = acts.get(act, ("?", ""))
        pn = mid("pol" + src + str(policy))
        L.append(f'  {src} -- "p{prio}" --> {pn}["{q(policy)}<br/>{kind} {q(act)}"]')
        if server:
            L.append(f'  {pn} --> {mid("srv" + kind + server)}[("{kind}<br/>{q(server)}")]')
        if nextf:
            ln = mid("lbl" + nextf)
            L.append(f'  {pn} -- next --> {ln}{{"label {q(nextf)}<br/>schema {q(labels.get(nextf, {}).get("loginschema", ""))}"}}')
        return pn

    for res, tag in (("vpnvserver", "VPN"), ("lbvserver_authn", "LB"), ("csvserver_authn", "CS")):
        for v in d.get(res, []):
            vn = mid(tag + v["name"])
            L.append(f'  client --> {vn}["{tag} {q(v["name"])}<br/>{v.get("ipv46", "")}:{v.get("port", "")}"]')
            target = v.get("authnvsname") or prof.get(v.get("authnprofile", ""))
            if v.get("authnprofile"):
                pnode = mid("prof" + v["authnprofile"])
                L.append(f'  {vn} --> {pnode}(["authnprofile {q(v["authnprofile"])}"])')
                vn = pnode
            if target:
                L.append(f"  {vn} --> {avs_node(target)}")
    for name in avs:
        avs_node(name)
    srt = lambda rows: sorted(rows, key=lambda b: int(b.get("priority") or 0))
    for b in srt(d.get("authenticationvserver_authenticationloginschemapolicy_binding", [])):
        L.append(f'  {mid("avs" + b["name"])} -. schema .-> {mid("ls" + b["policy"])}>"loginschema {q(b["policy"])}"]')
    for b in srt(d.get("authenticationvserver_authenticationpolicy_binding", [])):
        step(mid("avs" + b["name"]), b.get("policy"), b.get("priority"), b.get("nextfactor"))
    for b in srt(d.get("authenticationpolicylabel_authenticationpolicy_binding", [])):
        step(mid("lbl" + b["labelname"]), b.get("policyname"), b.get("priority"), b.get("nextfactor"))
    for res in ("vpnvserver_authenticationpolicy_binding", "vpnvserver_authenticationldappolicy_binding",
                "vpnvserver_authenticationradiuspolicy_binding", "vpnvserver_authenticationsamlpolicy_binding",
                "vpnvserver_authenticationcertpolicy_binding"):
        for b in srt(d.get(res, [])):
            step(mid("VPN" + b["name"]), b.get("policy"), b.get("priority"), b.get("nextfactor"))
    for res in ("systemglobal_authenticationpolicy_binding", "systemglobal_authenticationldappolicy_binding",
                "systemglobal_authenticationradiuspolicy_binding"):
        for b in srt(d.get(res, [])):
            step("admin", b.get("policyname"), b.get("priority"), b.get("nextfactor"))
    return "\n".join(dict.fromkeys(L)) + "\n"


def write_report(outdir, diagrams):
    """report.html renders every .mmd with a local mermaid.min.js (offline)."""
    src = Path(__file__).resolve().parent / "vendor" / "mermaid.min.js"
    have = src.exists()
    if have:
        import shutil
        shutil.copyfile(src, os.path.join(outdir, "mermaid.min.js"))
    import html as _h
    toc = "".join(f'<li><a href="#{mid(t)}">{_h.escape(t)}</a></li>' for t, _ in diagrams)
    body = "".join(f'<section id="{mid(t)}"><h2>{_h.escape(t)}</h2><pre class="mermaid">{_h.escape(m)}</pre>'
                   f'<details><summary>source</summary><pre>{_h.escape(m)}</pre></details></section>'
                   for t, m in diagrams)
    warn = "" if have else "<p><b>mermaid.min.js missing next to ns_discover.py (vendor/). Diagrams show as text.</b></p>"
    page = f"""<!doctype html><html><head><meta charset="utf-8"><title>NetScaler discovery report</title>
<style>body{{font-family:sans-serif;margin:2em}}section{{border-top:1px solid #ccc;padding:1em 0}}
pre.mermaid{{background:#fff}}</style></head><body><h1>NetScaler discovery report</h1>{warn}
<p>Read-only inventory. Secrets are masked (***). Generated {time.strftime("%Y-%m-%d %H:%M %Z")}.</p>
<ul>{toc}</ul>{body}
<script src="mermaid.min.js"></script>
<script>if(window.mermaid){{mermaid.initialize({{startOnLoad:true,securityLevel:'strict',maxTextSize:500000,
flowchart:{{htmlLabels:true}}}});}}</script></body></html>"""
    Path(outdir, "report.html").write_text(page, encoding="utf-8")


def sdx_list(host, user, pw, a):
    """SDX Management Service: list VPX instances (NITRO v2 /config/ns). Read-only."""
    n = Nitro(host, user, pw, a, version="v2")
    status(host, "sdx-login", "ok", f"auth={n.auth}")
    try:
        data = n.get("config/ns").get("ns", [])
    finally:
        n.logout()
    rows = [{k: i.get(k) for k in ("name", "ip_address", "ns_version", "instance_state", "vm_state",
                                   "ha_master_state", "throughput", "vm_memory_total")}
            for i in data]
    return rows

def main():
    p = argparse.ArgumentParser(description="Read-only NetScaler discovery and mapping")
    p.add_argument("--cidr", action="append", help="CIDR to scan; ignored with --bookmarks/--hosts")
    p.add_argument("--hosts", help="file with one host per line (optional # TYPE comment)")
    p.add_argument("--bookmarks", help="browser bookmarks HTML export")
    p.add_argument("--user", default="nsadmin", help="NITRO username (default: nsadmin)")
    p.add_argument("--sdx-user", help="SDX Management Service user (default: same as --user)")
    p.add_argument("--debug", action="store_true", help="log each request: method, path, HTTP code (no secrets)")
    p.add_argument("--discover-only", action="store_true", help="only probe, no login")
    p.add_argument("--sdx", action="store_true", help="treat all targets as SDX; bookmarks auto-SDX typed hosts")
    p.add_argument("--include-secondary", action="store_true")
    p.add_argument("--gslb", action="store_true")
    p.add_argument("--snmp-community", help="optional SNMP v2c (needs pysnmp)")
    p.add_argument("--out", default="ns_discovery_out")
    p.add_argument("--workers", type=int, default=32)
    p.add_argument("--rate", type=float, default=20)
    p.add_argument("--timeout", type=float, default=5)
    p.add_argument("--insecure", action="store_true")
    a = p.parse_args()
    global DEBUG
    DEBUG = a.debug
    a.keep_all = False
    if a.insecure:
        urllib3.disable_warnings()

    host_types = {}
    list_mode = bool(a.bookmarks or a.hosts)

    if a.bookmarks:
        os.makedirs(a.out, exist_ok=True)
        review_path = os.path.join(a.out, "bookmarks_hosts.csv")
        included, review = parse_bookmarks(a.bookmarks, write_review=review_path)
        host_types = {h: t for h, t in included}
        with open(os.path.join(a.out, "bookmarks_hosts.txt"), "w", encoding="utf-8") as f:
            f.write("# from --bookmarks; user=nsadmin" + "\n")
            f.writelines(f"{h}  # {t}" + "\n" for h, t in included)
        n_exc = sum(1 for r in review if r["included"] != "included")
        print(f"Bookmarks: {len(included)} included, {n_exc} excluded -> {review_path}", file=sys.stderr)
        a.hosts = a.cidr = None

    if list_mode and not a.bookmarks:
        a.cidr = None
        for line in Path(a.hosts).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            host, _, comment = line.partition("#")
            host = host.strip()
            typ = "ADC"
            for cand in ("SDX", "ADM", "ADC"):
                if re.search(r"\b" + cand + r"\b", comment, re.IGNORECASE):
                    typ = cand
                    break
            host_types[host] = typ

    if not list_mode and not a.cidr:
        p.error("give --bookmarks, --hosts, and/or --cidr")

    if list_mode:
        host_list = list(host_types.keys())
        print(f"Using host list ({len(host_list)} entries); CIDR scan disabled.", file=sys.stderr)
    else:
        host_list = targets(a.cidr, a.hosts)
        host_types = {h: "ADC" for h in host_list}

    user = a.user
    sdx_user = a.sdx_user or user
    pw = sdx_pw = None
    if not a.discover_only:
        pw = getpass.getpass(f"Password for {user} (not saved): ")
        if not pw:
            sys.exit("empty password")
        sdx_pw = pw
        if sdx_user != user and any(a.sdx or t == "SDX" for t in host_types.values()):
            sdx_pw = getpass.getpass(f"Password for SDX user {sdx_user} (not saved): ")
            if not sdx_pw:
                sys.exit("empty SDX password")

    os.makedirs(a.out, exist_ok=True)
    sdx_hosts = [h for h in host_list if a.sdx or host_types.get(h) == "SDX"]
    adm_hosts = [h for h in host_list if host_types.get(h) == "ADM" and not a.sdx]
    adc_hosts = [h for h in host_list if h not in sdx_hosts and h not in adm_hosts]
    if adm_hosts:
        print("Skipping ADM (no inventory mode): " + ", ".join(adm_hosts), file=sys.stderr)

    try:
        run(a, list_mode, sdx_hosts, adc_hosts, user, pw, sdx_user, sdx_pw)
    finally:
        write_status(a.out)
        print(f"Status per host -> {os.path.join(a.out, 'status.csv')}", file=sys.stderr)


def run(a, list_mode, sdx_hosts, adc_hosts, user, pw, sdx_user, sdx_pw):
    rows = []
    if sdx_hosts and not a.discover_only:
        for h in sdx_hosts:
            try:
                got = [{"sdx": h, **r} for r in sdx_list(h, sdx_user, sdx_pw, a)]
                rows += got
                status(h, "sdx-list", "ok", f"{len(got)} VPX")
            except requests.RequestException as e:
                status(h, "sdx-list", "FAILED", nitro_err(e))
            except ValueError as e:
                status(h, "sdx-list", "FAILED", f"bad JSON: {e}"[:200])
        with open(os.path.join(a.out, "sdx_instances.csv"), "w", newline="", encoding="utf-8-sig") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0]) if rows else ["sdx"])
            w.writeheader()
            w.writerows(rows)
        print(f"{len(rows)} VPX from {len(sdx_hosts)} SDX -> {a.out}/sdx_instances.csv", file=sys.stderr)

    if list_mode:
        probe_file = os.path.join(a.out, "_probe_hosts.txt")
        Path(probe_file).write_text(("\n".join(adc_hosts) + "\n") if adc_hosts else "", encoding="utf-8")
        a.hosts, a.cidr = probe_file, None

    # with a host list, probe is informational only: every listed host goes to NITRO login
    a.keep_all = list_mode
    found = discover(a) if (adc_hosts or not list_mode) else []
    with open(os.path.join(a.out, "discovered.csv"), "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=["host", "nitro", "login_page", "snmp_citrix", "version", "error"],
                           extrasaction="ignore")
        w.writeheader()
        w.writerows(found)
    if a.discover_only:
        return
    targets_ = adc_hosts if list_mode else [r["host"] for r in found]
    if not targets_:
        print("No ADC hosts to inventory.", file=sys.stderr)
    with cf.ThreadPoolExecutor(max_workers=min(a.workers, 8)) as ex:
        devs = list(ex.map(lambda h: inventory_one(h, user, pw, a), targets_))
    ok = sum(1 for d in devs if not d.get("error"))
    print(f"Inventory: {ok}/{len(devs)} ADC hosts read OK", file=sys.stderr)
    write_outputs(devs, a.out, rows)


if __name__ == "__main__":
    main()
