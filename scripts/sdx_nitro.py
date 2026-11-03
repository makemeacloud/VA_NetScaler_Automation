#!/usr/bin/env python3
"""SDX Management Service NITRO helper (alternative to Ansible).

Reads the same YAML vars file. Default is --dry-run: prints requests, sends nothing.
Use --apply to really call the SDX. Passwords come from env vars, never the file.
"""
import argparse
import ipaddress
import json
import os
import sys

import yaml  # pip install pyyaml

try:
    import requests  # pip install requests
except ImportError:  # dry-run still works
    requests = None

PE_GB = 4


def precheck(cfg):
    errs = []
    blob = json.dumps(cfg)
    if "CHANGE_ME" in blob:
        errs.append("placeholders (CHANGE_ME) still present")
    pairs = {}
    for i in cfg["vpx_instances"]:
        if i["memory_gb"] < i["packet_engines"] * PE_GB:
            errs.append(f"{i['name']}: memory {i['memory_gb']} < {i['packet_engines']} PE x {PE_GB} GB")
        if i.get("ha_pair"):
            pairs.setdefault(i["ha_pair"], []).append(i)
        if i.get("cpu_core_sharing") not in ("dedicated", "shared"):
            errs.append(f"{i['name']}: cpu_core_sharing must be dedicated or shared")
        for nif in i.get("interfaces", []):
            if nif.get("vlan_filtering") is not True or not nif.get("allowed_vlans"):
                errs.append(f"{i['name']}: interface {nif.get('port_name')} needs vlan_filtering true + allowed_vlans")
    reserved = cfg.get("sdx_reserved_memory_gb") or {}
    tput = cfg.get("sdx_platform_throughput_mbps") or {}
    for host, cap in cfg.get("sdx_capacity", {}).items():
        mine = [i for i in cfg["vpx_instances"] if i["sdx_host"] == host]
        res = reserved.get(host, 0) if isinstance(reserved, dict) else 0
        if not res:
            errs.append(f"{host}: sdx_reserved_memory_gb is 0/unset (model-dependent, required)")
        mem = sum(i["memory_gb"] for i in mine) + (res or 0)
        if mem > cap["memory_gb"]:
            errs.append(f"{host}: memory {mem} GB > {cap['memory_gb']} GB")
        ssl = sum(i["ssl_cores"] for i in mine)
        if ssl > cap["ssl_cores"]:
            errs.append(f"{host}: SSL cores {ssl} > pool {cap['ssl_cores']}")
        tp = sum(i["throughput_mbps"] for i in mine)
        if not tput.get(host) or tp > tput[host]:
            errs.append(f"{host}: throughput {tp} Mbps vs platform license {tput.get(host, 0)} Mbps")
    keys = ("packet_engines", "memory_gb", "ssl_cores", "throughput_mbps",
            "license_edition", "cpu_core_sharing", "ha_peer_id")
    for name, nodes in pairs.items():
        if len(nodes) != 2:
            errs.append(f"HA {name}: needs exactly 2 nodes")
            continue
        a, b = nodes
        net = [ipaddress.ip_interface(f"{n['nsip']}/{n['netmask']}").network
               if "CHANGE_ME" not in n["nsip"] + n["netmask"] else None for n in nodes]
        if net[0] != net[1] and not cfg.get("ha_inc_mode"):
            errs.append(f"HA {name}: nodes on different subnets, set ha_inc_mode true")
        if a["sdx_host"] == b["sdx_host"]:
            errs.append(f"HA {name}: both nodes on {a['sdx_host']} (must be separate SDX)")
        for k in keys:
            if a[k] != b[k]:
                errs.append(f"HA {name}: {k} differs")
    return errs


class Nitro:
    def __init__(self, host, user, pw, apply, verify=True):
        self.base = f"https://{host}/nitro/v2"
        self.h = {"X-NITRO-USER": user, "X-NITRO-PASS": pw, "Content-Type": "application/json"}
        self.apply, self.verify = apply, verify

    def post(self, path, body):
        print(f"POST {self.base}/{path}\n{json.dumps(body, indent=2)}")
        if not self.apply:
            return None
        r = requests.post(f"{self.base}/{path}", headers=self.h, json=body, verify=self.verify, timeout=1800)
        r.raise_for_status()
        return r.json()


def provision(cfg, apply):
    pw = os.environ.get("SDX_MS_PASSWORD", "<SDX_MS_PASSWORD>")
    prof_pw = os.environ.get("ADMIN_PROFILE_PASSWORD", "<ADMIN_PROFILE_PASSWORD>")
    hosts = cfg["sdx_hosts"]  # {sdx-a: mgmt_ip}
    for host, ip in hosts.items():
        n = Nitro(ip, cfg["sdx_ms_user"], pw, apply)
        n.post("config/ns_device_profile", {"ns_device_profile": {
            "name": cfg["admin_profile_name"], "username": cfg["admin_profile_user"],
            "password": prof_pw, "type": "ns"}})
        for i in [x for x in cfg["vpx_instances"] if x["sdx_host"] == host]:
            n.post("config/ns", {"ns": {
                "name": i["name"], "ip_address": i["nsip"], "netmask": i["netmask"],
                "gateway": i["gateway"], "image_name": cfg["vpx_xva_name"],
                "profile_name": cfg["admin_profile_name"],
                "vm_memory_total": i["memory_gb"] * 1024,
                "num_pes": i["packet_engines"],  # UNVERIFIED field name
                "number_of_ssl_cores": i["ssl_cores"],  # UNVERIFIED field name
                "throughput": i["throughput_mbps"],
                "license": i["license_edition"],  # UNVERIFIED field name
                "cpu_core_sharing": i["cpu_core_sharing"],  # UNVERIFIED field name (and value format)
                "network_interfaces": [{
                    "port_name": f["port_name"],
                    "vlan_filtering": f["vlan_filtering"],  # UNVERIFIED field name
                    "vlan_whitelist_array": f["allowed_vlans"],  # UNVERIFIED field name
                } for f in i["interfaces"]]}})


CHECK_FIELDS = ("license", "cpu_core_sharing", "num_pes", "number_of_ssl_cores")
CHECK_IF_FIELDS = ("vlan_filtering", "vlan_whitelist_array")


def discover(host, user, pw, verify=True):
    """Read-only: GET existing instances and print field names. Never writes."""
    if requests is None:
        sys.exit("pip install requests")
    base = f"https://{host}/nitro/v2/config"
    hdr = {"X-NITRO-USER": user, "X-NITRO-PASS": pw}
    r = requests.get(f"{base}/ns", headers=hdr, verify=verify, timeout=60)
    r.raise_for_status()
    inst = r.json().get("ns", [])
    if not inst:
        print("No instances on this SDX; provision one by hand in the lab, then re-run.")
        return
    keys = sorted({k for i in inst for k in i})
    print(f"ns fields ({len(keys)}):\n  " + "\n  ".join(keys))
    nifs = inst[0].get("network_interfaces") or []
    if not nifs and inst[0].get("id"):
        r = requests.get(f"{base}/ns/{inst[0]['id']}", headers=hdr, verify=verify, timeout=60)
        r.raise_for_status()
        nifs = (r.json().get("ns") or [{}])[0].get("network_interfaces") or []
    if_keys = sorted({k for n in nifs for k in n})
    print(f"network_interfaces fields of '{inst[0].get('name')}' ({len(if_keys)}):\n  " + "\n  ".join(if_keys))
    print("\nField check:")
    for f in CHECK_FIELDS:
        print(f"  ns.{f}: {'FOUND' if f in keys else 'MISSING'}")
    for f in CHECK_IF_FIELDS:
        print(f"  network_interfaces.{f}: {'FOUND' if f in if_keys else 'MISSING'}")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("vars_file")
    p.add_argument("--precheck-only", action="store_true")
    p.add_argument("--discover", metavar="SDX_HOST", help="read-only: GET ns fields from this SDX and exit")
    p.add_argument("--insecure", action="store_true", help="discover: skip TLS cert check (lab only)")
    p.add_argument("--apply", action="store_true", help="really call the SDX (default: dry-run)")
    a = p.parse_args()
    with open(a.vars_file, encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    if a.discover:
        discover(a.discover, cfg["sdx_ms_user"], os.environ.get("SDX_MS_PASSWORD", ""), not a.insecure)
        return
    errs = precheck(cfg)
    for e in errs:
        print("PRECHECK FAIL:", e)
    if errs and (a.apply or a.precheck_only):
        sys.exit(1)
    if a.precheck_only:
        print("PRECHECK OK")
        return
    if a.apply and requests is None:
        sys.exit("pip install requests")
    provision(cfg, a.apply)


if __name__ == "__main__":
    main()
