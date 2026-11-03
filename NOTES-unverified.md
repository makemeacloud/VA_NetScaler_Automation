# Doc check status
Verified (SDX NITRO docs / Terraform netscalersdx provider):
- Base URL `/nitro/v2/config/<resource>`, auth by X-NITRO-USER / X-NITRO-PASS headers.
- `ns` resource = VPX instance; fields name, ip_address, netmask, gateway, image_name, profile_name, vm_memory_total (MB), throughput, network_interfaces[].port_name.
- `ns_device_profile` = admin profile (type "ns").

NOT verified – confirm on target MS build:
- Image upload endpoint `/nitro/v2/upload/xen_nsvpx_image` and list field `file_name`.
- Field names `num_pes`, `number_of_ssl_cores`, and per-interface VLAN fields.
- ns_device_profile field `username` (docs snippet shows name/password; may be another key).
- LAS activation via NITRO: no API found; left as manual gate.
- netscaler.adc 2.17.0 modules hanode (id, ipaddress, inc), nsrpcnode (ipaddress, password, secure), nshostname, ntpserver, dnsnameserver, save_config: names and args checked with ansible-doc. Value formats (inc ENABLED/DISABLED, secure YES) follow NITRO conventions; not run against a device.
- ha_node_id was replaced by ha_peer_id: on NetScaler the local node is always id 0, so hanode `id` is the peer entry id (1-64), same on both nodes.
- `ns` fields `license` (edition), `cpu_core_sharing` (and whether it takes dedicated/shared or a numeric code), and interface fields `vlan_filtering` / `vlan_whitelist_array` (allowed VLANs) – all UNVERIFIED.
- Platform throughput license per SDX: no NITRO read implemented; value comes from vars (sdx_platform_throughput_mbps).
- vpx_wait_ready uses ADC NITRO v1 `/nitro/v1/config/login` – standard ADC endpoint, not run here.
- SDX reserved memory for MS/Dom0 per model.

- Run `scripts/sdx_nitro.py --discover <lab-sdx>` (read-only) to confirm the ns / network_interfaces field names above.

## MPX track / FIPS — only relevant when fips_required is true; Cleveland/Martinsburg are non-FIPS (checked against docs.netscaler.com, pages last published Sep 30, 2026)
Verified from docs:
- MPX 8900/9100/9200 FIPS: FIPS 140-3 Level 2, 14.1-FIPS firmware only, no third-party HSM (MPX FIPS appliances page, FIPS FAQ).
- MPX 14000 FIPS commands (reset fips, set fips -initHSM, show fips, SIM key sharing) do NOT work on 8900/9100/9200 (FAQ; CTX330685).
- Status check: `show system fipsStatus` -> "System is operating in FIPS mode"; if non FIPS mode, check license.
- Initial FIPS steps: strong passphrases, replace default TLS cert, disable HTTP GUI, later LDAP + local auth off.
- HA on MPX FIPS = same as non-FIPS. FIPS firmware can't be converted to/from non-FIPS.
- show version on 9200 FIPS ends in `.fips` / `(NS14.1-FIPS)`; platform sysid 36010 (hardware page).
- netscaler.adc modules/args used (systemparameter strongpassword/localauth, nsip gui, nsconfig ipaddress/netmask, sslcertkey, nsrpcnode, hanode inc): checked with ansible-doc 2.17.0.
NOT verified:
- NITRO resource for fipsStatus: `systemfipsstatus` is a guess; if it 404s, the FIPS gate fails closed (check by SSH).
- nsversion `version` string format on the FIPS build (used for approved-build match).
- NSIP change over NITRO via nsconfig (may drop session / need reboot) – gated off by default.
- Exact strong-password value to use for the ATO baseline (enableall assumed).
- Requested items NOT built, because docs say they don't apply to MPX 9200 FIPS: HSM init with SO/user passwords, HA FIPS key sync / secure info sharing. The netscaler.adc sslfips / sslfipssim* modules exist but are for the legacy HSM models.
- MPX 17000 vs SDX 17000 still open; MPX 17000 path uses the same roles with fips_required false.

## ns_discover.py (NITRO v1 read-only)
Verified from current NITRO docs: `csvserver_cspolicy_binding` (fields name, policyname, targetlbvserver,
priority, rule read-only, labelname) and `csvserver_lbvserver_binding` (field `lbvserver` = default LB);
get-all on *_binding needs `?bulkbindings=yes`. Paging `?pagesize=&pageno=`, count `?count=yes` (__count).
SDX: `/nitro/v2/config/ns` lists instances (SDX NITRO docs).
Standard NITRO names, not re-checked page by page: nsversion(version), nshostname(hostname),
hanode(id, ipaddress, state, hastatus; local node id 0), nsip(ipaddress, netmask, type NSIP/SNIP/VIP/MIP...),
lbvserver(name, ipv46, port, servicetype, curstate, lbmethod), csvserver, cspolicy(policyname, rule),
lbvserver_service_binding(servicename, ipv46, port, curstate), lbvserver_servicegroup_binding(servicegroupname),
servicegroup_servicegroupmember_binding(servicegroupname, servername, ip, port, svrstate),
service(name, servername, ipaddress, port, svrstate), gslbvserver.
UNVERIFIED:
- SDX ns field names in --sdx output (ns_version, instance_state, vm_state, ha_master_state); missing ones show blank.
- Whether bulkbindings responses are paged on very large configs (tool reads them in one call).
- Login page path/markers (`/logon/LogonPoint/index.html`, text match) - heuristic.
- Whether the built-in `read-only` command policy allows every GET used (it should: show-only). Test on Cleveland Lab.
- HA state value strings ("Primary"/"Secondary") - assumed.

### ns_discover.py network + auth (added 2026-10-19)
Verified: every resource below has a page in the NITRO API reference (developer-docs.netscaler.com, current
release), and every field read was found on its page: vlan, vlan_interface_binding, vlan_nsip_binding, route,
interface, channel, ns/nstrafficdomain, nspartition, authenticationvserver (+ _authenticationpolicy_,
_authenticationloginschemapolicy_, _authenticationsamlidppolicy_binding), authenticationpolicy,
authenticationpolicylabel (+ _authenticationpolicy_binding), authenticationloginschema(+policy),
authentication{ldap,radius,saml,oauth,cert,negotiate,epa}action, authenticationsamlidpprofile,
authenticationauthnprofile, vpnvserver (+ _authentication{,ldap,radius,saml,cert}policy_binding),
authentication{ldap,radius,saml,cert}policy, tmsessionaction, systemglobal_authentication{,ldap,radius}policy_binding,
lb/csvserver authentication, authn401, authnvsname, authnprofile, authenticationhost.
Removed after doc check (not on the page): vlan tagbondinterfaces/td, vpnvserver td,
vpnvserver_authenticationpolicy_binding nextfactor, negotiateaction kcdaccount.
UNVERIFIED:
- Value formats: vlan_interface_binding `tagged` (bool vs "true"), vpn binding `secondary`, lb/cs
  `authentication` "ON"; channel `ifnum` as space/comma list. Assumed from NITRO conventions.
- Whether nsadmin can read nspartition / systemglobal bindings / auth actions (nsadmin policy may block
  some system resources; the tool skips any HTTP error and lists it under `unsupported`).
- Partitions: only the default partition is read (no switchpartition, which would change session state).
- Secret masking is name-based (pass/secret/key/token/pwd/credential...); only whitelisted fields are kept, so
  unknown secret fields are never emitted. Not tested against real build output.
- nFactor via nextfactor on authenticationvserver bindings is drawn; classic vpn cascade by priority only.
- Not tested on a real device (mock data only). Mermaid render checked headless in Chrome with mock data.

### ns_discover.py auth/status fix (2026-10-19)
Verified (adc-sdx-nitro-api-reference, System/login): `login` object POST {"login":{"username","password"}}
returns `sessionid`, used as `Cookie: NITRO_AUTH_TOKEN=`; per-request X-NITRO-USER/X-NITRO-PASS also documented
(must not send cookie with them). UNVERIFIED: exact SDX v2 login reply shape (top-level `sessionid` vs
`login[0].sessionid` - both handled); logout payload `{"logout":{}}`; whether nsadmin on SDX MS exists (SDX
default admin is `nsroot`; use --sdx-user if needed).

## LAS / upgrade / HA (automation-toolkit adaptation, 2026-10-19)
Verified with ansible-doc (netscaler.adc 2.17.0): nslaslicense_offline (nsip, nitro_user must be nsroot, entitlement_name,
is_fips, las_secrets_json, restricted_mode; needs paramiko), nslaslicense (state applied, filename, filelocation),
install (url file://|https|sftp, y, enhancedupgrade, state installed), hafailover (force), systemparameter promptstring,
nsrpcnode secure YES/NO. Version-compare logic tested locally on sample strings. Lint: yamllint + ansible-lint production profile pass.
UNVERIFIED (nothing run on a device):
- is_fips: now default false on all MPX incl. FIPS MPX (upstream README: FIPS VPX only); las_is_fips_override kept.
  Not tested against LAS. Exact MPX 9200 FIPS entitlement string unknown; precheck only checks prefix 'FIPS MPX 92'
  and suffix 'Premium' - the real name must match the LAS account exactly.
- Online LAS (box talks to LAS directly): no Ansible module found; only offline + apply-existing-blob are automated.
- Module writes the blob to the control node's current working directory; reboot timing (60 s pause) assumed.
- netscaler.adc.install with file:// path: behaviour (reboot with y: true, NITRO session drop) not tested; upstream used
  `installns -Y -n` + NITRO reboot over SSH. ISSU: nsmigration started via NITRO POST ?action=start on the upgraded
  secondary, polled until migrationstatus == "Migration is completed" (string from upstream).
- nsversion string parse "NSR.r: Build B.b" assumed for FIPS builds too.
- Upstream repo has no LICENSE file.

## Added 2026-11-03 (not verified on hardware)
- nslicense fields `isstandardlic` / `isenterpriselic` / `isplatinumlic` used by las_apply to skip re-licensing.
- hanode `hasync` value used as the sync gate in upgrade.yml (accepts SUCCESS or ENABLED).
- `systembackup?action=create` body (filename, level full) in upgrade_node.
- PUT /nitro/v1/config/nsip with only {ipaddress, gui: SECUREONLY} for HTTPS-only GUI.
- SDX `config/ns` listing used by vpx_provision to skip existing VPX names.
- STAYPRIMARY/STAYSECONDARY lock + release order during pairing (doc-backed, not lab-tested).
