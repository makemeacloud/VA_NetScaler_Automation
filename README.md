# NetScaler SDX VPX automation

EXAMPLE values only. Every `CHANGE_ME` must be filled in. Nothing has touched a real box.

## What it does
1. **precheck** – stops if: placeholders remain; `sdx_reserved_memory_gb` is 0/unset (look it up for your model); memory < 4 GB per packet engine; memory, SSL core pool, or platform-license throughput on a box is exceeded (totals are printed); an interface has no VLAN filtering / allowed VLAN list; HA nodes are on one box, differ (size, throughput, edition, CPU sharing, peer id), or sit on different subnets with `ha_inc_mode: false`; image older than 14.1-51.
2. **sdx_image_upload** – uploads the VPX `.xva` to each SDX Management Service if missing.
3. **sdx_admin_profile** – makes the admin profile the VPX uses.
4. **vpx_provision** – builds each VPX: memory, packet engines, SSL cores, throughput, ports/VLANs.
5. **vpx_wait_ready** – waits for each NSIP on ports 443 and 22, then retries NITRO login until it works.
6. **vpx_las_license** – reads license state; LAS activation is a manual step for now.
7. **vpx_ha_pair** – sets the RPC node password (vault `vault_rpc_node_password`) on both nodes, then adds the HA peer with `ha_peer_id` and INC.
8. **vpx_post_config** – hostname, NTP, DNS on each standalone VPX (before HA), then save. LAS runs one SDX at a time; HA locks the first node of each pair as primary; a final save always runs.

## Step 1 on a lab box: discover field names (read-only)
Before any real run, check which NITRO field names your SDX build uses. This only does GETs:
```
SDX_MS_PASSWORD=... python3 scripts/sdx_nitro.py vars.yml --discover <lab-sdx-ip>
```
It prints every `ns` field and one instance's `network_interfaces` fields, then FOUND/MISSING for
`license`, `cpu_core_sharing`, `num_pes`, `number_of_ssl_cores`, `vlan_filtering`, `vlan_whitelist_array`.
The lab box needs at least one instance. If a field is MISSING, fix the name in `roles/vpx_provision` and the script.

## Use
```
pip install ansible-core pyyaml requests
ansible-galaxy collection install -r requirements.yml
pip install netaddr   # needed by precheck subnet check
ansible-playbook precheck.yml                 # safe, no device contact
ansible-playbook site.yml --tags precheck,image,profile,provision
ansible-playbook site.yml --tags ha,postconfig  # after LAS is done
```
Put passwords in ansible-vault (`vault_sdx_ms_password`, `vault_admin_profile_password`, `vault_rpc_node_password`).

Python option (dry-run by default, prints requests only):
```
python3 scripts/sdx_nitro.py inventories/example/group_vars/all.yml --precheck-only
SDX_MS_PASSWORD=... ADMIN_PROFILE_PASSWORD=... python3 scripts/sdx_nitro.py vars.yml --apply
```

## Upgrades
Use the SDX Single Bundle Image. Not automated here yet.

## Check before first real run
Some NITRO field names are not confirmed (see NOTES below). Test on a lab SDX first.

## Bare-metal MPX track (8-site program)
Inventory: `inventories/example/sites.yml` (8 sites, 1 HA pair each, all addresses CHANGE_ME).
Each site has `platform: mpx | sdx`. Cleveland Lab and Martinsburg are MPX 9200 (**non-FIPS**, `platform_model: mpx9200`, `fips_required: false`).
FIPS is optional everywhere: every FIPS-only check/step is skipped unless `fips_required: true` (then use `platform_model: mpx9200fips`).
NITRO certificate checks default to off (`nitro_validate_certs: false`) because new boxes have self-signed certs; set true once a trusted cert is on the NSIP.
The 6 large sites are still OPEN (SDX 17000 or MPX 17000): set `platform` when decided.
`mpx.yml` builds `mpx` sites and skips undecided ones with a warning. `sdx` sites use `site.yml`.
Cleveland Lab goes first.

```
ansible-playbook -i inventories/example/sites.yml mpx.yml --tags precheck   # safe, no device contact
ansible-playbook -i inventories/example/sites.yml mpx.yml --limit site_cle
```
Steps: precheck -> optional NSIP move (`mpx_set_nsip`) -> wait for 443/22 + NITRO login + approved
NSIP bootstrap (saved on the new IP) -> firmware check -> hostname/NTP/DNS + HTTPS-only GUI -> FIPS (only if fips_required) -> SAVE
-> license / LAS (ONE node at a time; saves first, LAS reboots, waits, checks HA) -> HA pair (secondary locked STAYSECONDARY,
primary added first, lock released after sync) -> SSL keys on the primary only -> SAVE. The primary is `ha_primary: true`
or, if unset, the first host name of the pair in sort order. Saves run on every run, whatever `--tags` you pass.

### FIPS on MPX 9200 FIPS (only for FIPS boxes; Cleveland/Martinsburg skip this)
- This model has **no HSM**. Do not use the old `reset fips` / `set fips -initHSM` steps; those are for MPX 14000 FIPS and will not work.
- It must run the separate 14.1-FIPS firmware. Check: `show system fipsStatus` says "operating in FIPS mode".
- HA works the same as non-FIPS. No FIPS key sync between nodes.
- Setting `fips_hsm_init_confirm: ERASE-FIPS-HSM` on an MPX 9200 FIPS makes precheck fail on purpose.
- Local auth is turned off only when you set `fips_disable_local_auth: true` (after LDAP works).

### Cleveland Lab test steps (local auth off)
1. Run `mpx.yml --limit site_cle` with `fips_disable_local_auth: false`.
2. Log in as nsroot from the serial/LOM console on both nodes. Then set `nsroot_console_verified: true`.
3. Set up LDAP; log in as an LDAP admin by GUI and SSH on both nodes. Then set `ldap_admin_login_verified: true`.
4. Set `fips_disable_local_auth: true` and run `--tags precheck,fips`. Without both confirmations, it stops.
5. Check LDAP admin login again, and nsroot from console, before moving on.

## Discovery and mapping tool (read-only)
From a browser bookmarks HTML export (already parsed into `inventories/bookmarks_hosts.txt`):
```
# review CSV first: inventories/bookmarks_hosts.csv (included vs excluded portals)
python3 scripts/ns_discover.py --bookmarks /path/to/bookmarks.html --out out/ --insecure
# or use the pre-built host list (same hosts; SDX typed lines auto-use SDX mode)
python3 scripts/ns_discover.py --hosts inventories/bookmarks_hosts.txt --out out/ --insecure
```
User is always `nsadmin` (override with `--user` only if needed). Password is prompted by getpass; not taken from env or args and not saved.
With `--bookmarks` or `--hosts`, CIDR scan is off — only those hosts are contacted. SDX-typed hosts use SDX inventory automatically. ADM hosts are listed then skipped (no ADM mode yet).

`scripts/ns_discover.py` finds NetScalers and maps what is on them. It only reads. Needs `pip install requests`
(and `pysnmp` only if you want the SNMP check).

```
# 1. find devices only (no login)
python3 scripts/ns_discover.py --cidr 10.0.0.0/24 --discover-only --out out/
# 2. find + inventory (read-only account)
python3 scripts/ns_discover.py --cidr 10.0.0.0/24 --cidr 10.0.1.0/24 --out out/   # prompts for nsadmin password
python3 scripts/ns_discover.py --hosts adc_list.txt --gslb --out out/
# 3. SDX: list VPX instances from Management Service
python3 scripts/ns_discover.py --sdx --hosts sdx_list.txt --out out/
```
Flags: `--insecure` (lab, skip cert check), `--rate 20` (requests/sec), `--workers 32`, `--timeout 5`,
`--include-secondary` (fully read HA secondaries too), `--snmp-community` (Citrix OID 1.3.6.1.4.1.5951).

How it finds a NetScaler: HTTPS 443 answers `/nitro/v1/config/nsversion` with NITRO JSON
(`errorcode` + `severity`, also on 401), or the login page looks like NetScaler, or SNMP says Citrix.

Outputs in `--out`: `discovered.csv`, `devices.csv` (hostname, version, HA state, NSIP, all IPs with type),
`vips.csv` (LB/CS/GSLB vservers), `cs_map.csv` (CS -> policy, rule, priority -> LB, plus default LB),
`backends.csv` (LB -> service/servicegroup -> server IP:port), `inventory.json`, and `<device>.mmd`
(Mermaid: CS -> policy -> LB -> servers). `--sdx` writes `sdx_instances.csv`.

Network placement: `network.csv` (IPs with subnet, VLANs, VLAN-interface/IP bindings, routes, interfaces,
channels, traffic domains, partitions), `network_<device>.mmd` (subnet -> VLAN -> interface/channel -> gateway),
`network_map.mmd` (whole estate: devices grouped by management subnet, shared data subnets/VLANs, HA pairs,
SDX -> VPX links when SDX hosts are in the list).

Authentication: `auth.csv` and `auth_<device>.mmd` (client -> VIP (VPN/LB/CS) -> authnprofile -> AAA vserver
-> nFactor policies by priority -> policy labels -> LDAP/RADIUS/SAML/OAuth/cert server; admin login via
systemglobal bindings; tmsessionaction SSO). Every password/secret-like field is replaced by `***`; only
named fields are kept, and `inventory.json` is masked too.

`report.html` shows every diagram in a browser, offline. It uses `mermaid.min.js` (v11.17.2) copied from
`scripts/vendor/` into the output folder - keep `vendor/` next to `ns_discover.py`.
Login: NITRO session first (POST `config/login` -> `NITRO_AUTH_TOKEN` cookie, logout at end), falling back to
X-NITRO-USER/PASS headers; both are in the docs, for ADC v1 and SDX Management Service v2. `--sdx-user NAME` uses a
different SDX account (second password prompt only if it differs from `--user`). With `--hosts`/`--bookmarks`
every listed host is logged into; the probe is informational only. Each host prints `[ok]/[FAILED]` per step
(probe, login, inventory, sdx-login, sdx-list) with HTTP code, URL path and NITRO errorcode/message, and
`status.csv` is written even if the run fails. `--debug` logs every request (method, path, HTTP code; never
headers or passwords). CSVs are UTF-8 with BOM so Excel on Windows opens them cleanly. On Windows, run from
cmd or PowerShell; getpass may not hide or read input in Git Bash/mintty or IDLE (use `winpty python ...`).
Resources a build does not support are skipped and listed per device in `inventory.json` (`unsupported`).

HA: the primary is read in full. A secondary is listed in devices.csv as `secondary-skipped`.

Account: use a read-only user. Example (check on a lab box first):
```
add system user ro_discover <password> -externalAuth DISABLED
bind system user ro_discover read-only 100
```
`read-only` is a built-in command policy (show commands only, no shell, no config changes).
Only scan networks you are allowed to scan.

## LAS licensing (automated, gated)
Roles `mpx_license` and `vpx_las_license` call `roles/las_apply`, adapted from netscaler/automation-toolkit
`Examples/Offline_LAS_Licensing/ansible_collections_netscaleradc` (module `netscaler.adc.nslaslicense_offline`).
- Off unless `las_apply: true`. **The box warm-reboots**; the role then waits until NITRO login works and reads `nslicense`.
- `las_apply_mode: offline` (request package -> LAS cloud -> blob -> apply; `las_apply_restricted_mode: true` sends only
  lsid/pubkey) or `blob` (apply a blob already in `/nsconfig/license` with `netscaler.adc.nslaslicense`).
- Firmware must be **14.1-51.80 or newer** on every LAS path (FIPS too); checked live and in precheck/upgrade.
- Per host/instance: `las_entitlement_name` exactly as in LAS (e.g. `MPX 9200 Premium` on non-FIPS, `FIPS MPX 92xx Premium` on FIPS, `VPX 10000 Premium`).
  `is_fips` defaults to false on MPX, FIPS MPX included (upstream: true only for FIPS VPX, set per VPX instance);
  override with `las_is_fips_override`. On FIPS MPX sites only, the precheck requires `las_entitlement_name` to start with
  `FIPS MPX 92` and end with `Premium`; it must **exactly match** the entitlement name in the LAS account.
- Vault only (never in repo): `vault_las_ccid` (Citrix Cloud customer ID), `vault_las_client_id`,
  `vault_las_client_secret`, `vault_mpx_nsroot_password` / `vault_vpx_nsroot_password` (module requires `nsroot`).
  The role writes a temporary 0600 `las_secrets_*.json` under `.las_blobs/` and deletes it in an `always:` block.
- Control node needs `pip install -r requirements.txt` (**paramiko** for SFTP) and `ansible-galaxy collection install -r requirements.yml`
  (netscaler.adc >= 2.17.0). Box needs SFTP/22 reachable from the control node; control node needs HTTPS to LAS.
- SDX itself: upstream has `Examples/Offline_LAS_Licensing/terraform_provider_netscalersdx`
  (`netscalersdx_nslaslicense_offline`, provider >= 0.7.4, also warm-reboots). Not wired in here yet.

## Firmware upgrade (`upgrade.yml`, gated)
Adapted from netscaler/automation-toolkit `golden_templates/upgrade-netscaler` (high-availability normal-mode,
issu-mode, standalone). Uses our `sites.yml` inventory and NITRO modules (`install`, `hafailover`, `nsmigration`
action via NITRO) instead of SSH + `nscli -U user:pass`, so no password is put on a remote command line.
```
ansible-playbook -i inventories/example/sites.yml upgrade.yml --ask-vault-pass -e upgrade_confirm=true \
  -e upgrade_target_version=14.1-51.80 -e upgrade_build_url=file:///var/nsinstall/<build>.tgz [-e upgrade_mode=issu] --limit site_cle
```
Precheck: `upgrade_confirm: true`, target >= 14.1-51.80, target on `mpx_fips_approved_builds` (FIPS sites; image name
must contain `fips`) or `mpx_non_fips_approved_builds`, live HA state = one primary + one secondary. Order: secondaries
and standalone (serial 1) -> normal: forced failover / ISSU: `nsmigration start` + poll -> old primaries -> failback
(`upgrade_failback`). Build must be pre-staged on the box (or a reachable URL). MPX only; SDX/VPX use the SDX bundle.

## HA pair
Compared with automation-toolkit `events/20230206/step1_configure_ha`: we already set hanode (same id both sides) and
RPC passwords for self + peer with secure on. Adopted: CLI prompt `%u@%s` (user@HA-state) and a post-check that the
peer shows in `hanode`. (Terraform uses `secure = "ON"`; the Ansible module's choices are `YES`/`NO`.)

## Future auth work
automation-toolkit gateway golden templates (Terraform): `golden_templates/netscaler_gateway/ldap_radius`, `/saml`,
`/oauth` (simplified gateway with nFactor). Candidates for a later gateway role; not adopted yet.

## Attribution
LAS, upgrade and HA pieces are adapted from https://github.com/netscaler/automation-toolkit (commit 45dce5d,
Jun 12 2026, NetScaler/Cloud Software Group). That repo has **no LICENSE file**; check terms with NetScaler before
redistributing outside the program. Adapted files carry a source comment.

## Upgrade safety (2026-11-03)
upgrade_node saves config and makes a full system backup before install; failover/failback wait for peer UP + sync and do not force (`upgrade_force_failover: false`); failback only if the node was really upgraded.

See REVIEW-2026-11-03.md for the full review.
