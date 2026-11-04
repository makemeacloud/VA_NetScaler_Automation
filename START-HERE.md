# How to Use the NetScaler Tools (Plain-Words Guide)

**For:** Jerry Sawyers, NetScaler program
**Code:** `NetScaler Automation Code.zip` (all the code) and `ns-discover-tool.zip` (just the discovery tool). Both are in the "NetScaler Automation" Drive folder.
**Where things run:** The discovery tool runs in normal Windows. The Ansible tools (`mpx.yml`, `upgrade.yml`, `site.yml`) run only in WSL (Linux on Windows) or on a Linux box.
**Important:** None of this has been run on a real box yet. Test on Cleveland Lab first.
**These boxes are normal MPX. They are not FIPS.**

---

## Part 1. What is in the zip (the short version)

Think of it as **4 tools** plus **settings files**.

| Tool | What it does | Changes the box? |
|---|---|---|
| `ns_discover.py` | Finds NetScalers on the network and makes a map of what is on them (VIPs, servers, VLANs, logins). | **No.** Read only. |
| `mpx.yml` | Builds a new **MPX** HA pair (Cleveland, Martinsburg). | **Yes.** |
| `site.yml` | Builds VPX boxes on an **SDX** (only if the large sites are SDX). | **Yes.** |
| `upgrade.yml` | Upgrades firmware on an MPX HA pair, one box at a time. | **Yes.** |

Helper files:

| File | What it is |
|---|---|
| `inventories/example/sites.yml` | **The list of all 8 sites.** IPs, names, model. You fill this in. |
| `inventories/example/group_vars/adc_sites.yml` | **Settings for every MPX box:** NTP, DNS, LDAP, firmware, license name. You fill this in. |
| `inventories/example/group_vars/all.yml` | Settings for SDX/VPX (only if SDX). |
| `precheck.yml` | Checks the SDX settings. Does not touch any box. |
| `scripts/sdx_nitro.py` | Python version of the SDX build. Also has a read-only "discover" test. |
| `upgrade_vars.yml` | Settings for upgrades. |
| `roles/` folder | The steps inside each tool. **You do not need to open these.** |
| `README.md` | The technical notes (for engineers). |
| `NOTES-unverified.md` | Things we still need to test on a real box. |

**Rule of thumb:** You only edit the files in `inventories/`. You only run the 4 tools.

---

## Part 2. Set up your computer once (the "control node")

The control node is the computer you run the tools from. It must reach the NetScaler management IPs.
On Windows, the Ansible tools run in **WSL** (free Linux inside Windows). The discovery tool runs in normal Windows.

1. **Turn on WSL (one time):** Right-click PowerShell, pick **Run as administrator**, type `wsl --install`, then restart.
   On a work laptop, IT may need to allow this.
2. Open **Ubuntu** from the Start menu. Make a username and password.
3. Install basics:
   ```
   sudo apt update && sudo apt install -y python3-pip python3-venv unzip
   ```
4. Go to the code. Your C: drive is `/mnt/c`:
   ```
   cd /mnt/c/Users/<you>/Downloads/netscaler-automation
   ```
5. Make a Python space and turn it on (do the `source` line again each time you open Ubuntu):
   ```
   python3 -m venv ~/nsenv
   source ~/nsenv/bin/activate
   ```
6. Install the tools:
   ```
   pip install ansible-core pyyaml requests netaddr -r requirements.txt
   ansible-galaxy collection install -r requirements.yml
   ```
7. Check it worked: `ansible --version` should show a version number.

---

## Part 3. Keep passwords safe (the "vault")

Passwords never go in the normal files. They go in an encrypted file called the vault.

1. Make the vault:
   ```
   mkdir -p inventories/example/group_vars/all
   ansible-vault create inventories/example/group_vars/all/vault.yml
   ```
   It asks you to make a vault password. **Do not lose it.**
2. In the file that opens, type these lines with your real values:
   ```
   vault_mpx_nsroot_password: "..."
   vault_rpc_node_password: "..."
   vault_las_ccid: "..."          # Citrix Cloud customer ID
   vault_las_client_id: "..."
   vault_las_client_secret: "..."
   # Only if you use SDX:
   vault_sdx_ms_password: "..."
   vault_admin_profile_password: "..."
   vault_vpx_nsroot_password: "..."
   ```
   The file must be in `group_vars/all/`. Anywhere else, Ansible will not read it.
3. Save and close. When you run a tool, add `--ask-vault-pass` and type the vault password.

---

## Part 4. Tool 1: `ns_discover.py` (look, don't touch)

**What it does:** Logs into your bookmarked NetScalers and writes spreadsheets and pictures of what is on them.
It **never changes anything.** Good for Phase 1 "current-state baseline."
It runs in **normal Windows** (no WSL needed).

**Steps:**
1. Unzip `ns-discover-tool.zip` (easy way), or use the `scripts` folder in the full code zip.
2. Open Command Prompt or PowerShell in that folder. Install once: `pip install requests`
3. Run (on Windows the command is `python`, not `python3`):
   ```
   python scripts\ns_discover.py --hosts scripts\bookmarks_hosts.txt --out out --insecure
   ```
4. It logs in as `nsadmin` and asks for the password. It does not save the password.
   Only the boxes in your bookmark list are checked.

**What you get** (in the `out` folder):
- `report.html`: open in a web browser. Shows all the diagrams.
- `devices.csv`: each box, version, HA state, IPs.
- `vips.csv`: every virtual server.
- `cs_map.csv`: the content switch map (which policy sends traffic to which load balancer).
- `backends.csv`: which servers sit behind each virtual server.
- `network.csv`: subnets, VLANs, routes.
- `auth.csv`: how logins work (LDAP, RADIUS, SAML).
- `status.csv`: what worked and what failed on each box.

Passwords in the output are hidden as `***`.

---

## Part 5. Tool 2: `mpx.yml` (build an MPX pair, start with Cleveland)

These boxes are **normal MPX 9200**. They are **not FIPS.** In `sites.yml` they are set as
`platform_model: "mpx9200"` and `fips_required: false`. Leave those as they are.

**What it does, in order:**
1. **Precheck:** stops if any setting is missing or wrong.
2. **Bootstrap:** only moves the management IP if you set `mpx_set_nsip: true`. **The connection drops when it does.** It now waits for the new IP and **saves it**. Leave it off if the IP is already right.
3. **Wait:** waits until each box answers and checks the firmware.
4. **Base setup:** hostname, NTP (time), DNS. It also makes the web screen HTTPS only (`mpx_gui_https_only: true`).
5. **Save.** Each box is saved before anything risky.
6. **License:** one box at a time. Box 02 goes first. Only if you turn it on.
7. **HA pair:** box 01 is the primary on purpose. Box 02 is locked as secondary first, so it can never wipe box 01.
8. **SSL keys:** loaded on the primary only. HA copies them to box 02.
9. **Save again** on both boxes.

**Save now always runs**, at the end of every run, even if you use `--tags`. (A run with only `--tags precheck` never touches the box, so it does not save.)

**First build and certs:** new boxes have a self-signed cert. The code accepts it, because `nitro_validate_certs: false` is the default. Set it to `true` later, after you put a real cert on the box.

**FIPS steps are off.** They only run if a site has `fips_required: true`. Ours do not. You can skip anything that says FIPS.

**Steps:**
1. Open `inventories/example/sites.yml`. Find **Cleveland Lab** (`site_cle`).
   Replace every `CHANGE_ME` with real values: the two management IPs, hostnames, subnet.
2. Open `inventories/example/group_vars/adc_sites.yml`. Fill in:
   - NTP (`mpx_ntp_servers`) and DNS (`mpx_dns_servers`).
   - The approved firmware: `mpx_non_fips_approved_builds`. Use standard **14.1 build 51.80 or newer**, for example `14.1-51.80`.
   - The license name: `las_entitlement_name`. Use the exact name from your LAS account, for example `MPX 9200 Premium`.
3. **Precheck** (does not touch any box):
   ```
   ansible-playbook -i inventories/example/sites.yml mpx.yml --tags precheck --ask-vault-pass
   ```
   Fix what it says. Run it again until it passes.

### The safe order (do it this way every time)
**Step A. Dry run.** Nothing changes. It only shows what it would do.
```
ansible-playbook -i inventories/example/sites.yml mpx.yml --limit cle_adc_01 --skip-tags ha --check --diff --ask-vault-pass
```
**Step B. One box only: the desk box.** No HA yet.
```
ansible-playbook -i inventories/example/sites.yml mpx.yml --limit cle_adc_01 --skip-tags ha --ask-vault-pass
```
Check the box. Log in. Look at hostname, NTP, DNS. Reboot it once and check again that nothing was lost.

**Step C. The HA pair.** Only after Step B looks good.
```
ansible-playbook -i inventories/example/sites.yml mpx.yml --limit site_cle --check --diff --ask-vault-pass
ansible-playbook -i inventories/example/sites.yml mpx.yml --limit site_cle --ask-vault-pass
```
Watch the screen. Green/yellow = OK. **Red = stopped.** Read the red message. It says what to fix.

### Turning on the license (optional switch)
Licensing only runs if you add `-e las_apply=true`. **Each box reboots.**
- Config is saved **before** the reboot, so nothing is lost.
- It does **one box at a time**. Box 02 first, then box 01.
- It waits for the box to come back and checks the HA peer.
- A box that is already licensed is skipped. It will not reboot again.
```
ansible-playbook -i inventories/example/sites.yml mpx.yml --limit site_cle --tags license -e las_apply=true --ask-vault-pass
```
Needs firmware **14.1-51.80 or newer**.

### Turning off local login
The script can do this now, but it is **off** until you turn it on. It also will not run until you mark two checks as done.
1. Log in as `nsroot` from the **console** on both boxes. If it works, set `nsroot_console_verified: true`.
2. Log in as an LDAP admin (web and SSH) on both boxes. If it works, set `ldap_admin_login_verified: true`.
3. Set `disable_local_auth: true`. All three are in `inventories/example/group_vars/adc_sites.yml`.
4. Run the build again for that site. Then test LDAP and console login one more time.

**For Martinsburg:** same steps. Use the Martinsburg box and site names from `sites.yml`.

---

## Part 6. Tool 3: `upgrade.yml` (upgrade firmware)

**What it does:** Upgrades an MPX HA pair with almost no downtime:
standby box first, then switch over, then the other box, then switch back.

**New safety steps:**
- It **saves** and makes a **full backup** on the box first (`upgrade_backup: true`). Copy the backup off the box with WinSCP.
- It checks the other box is up and in sync before each switch over.
- It does not force a switch over (`upgrade_force_failover: false`).
- It only switches back if the box was really upgraded.

**Steps:**
1. Copy the firmware file onto both boxes (folder `/var/nsinstall/`). Use the standard 14.1 build, **not** a FIPS build.
2. Add the build to `mpx_non_fips_approved_builds` in `adc_sites.yml`. If it is not on the list, the upgrade will not run.
3. Run (must include `upgrade_confirm=true` or it will not run):
   ```
   ansible-playbook -i inventories/example/sites.yml upgrade.yml --ask-vault-pass --limit site_cle \
     -e upgrade_confirm=true -e upgrade_target_version=14.1-51.80 \
     -e upgrade_build_url=file:///var/nsinstall/build-14.1-51.80_nc_64.tgz
   ```
4. Add `-e upgrade_mode=issu` to upgrade without dropping traffic (ISSU).

---

## Part 7. Tool 4: `site.yml` (SDX only, skip for now)

Only use this **if** the large sites turn out to be **SDX 17000**. It builds VPX boxes inside the SDX.
Before using it, run the read-only test on a lab SDX to confirm field names. **Run this in WSL or Linux, not plain Windows:**
```
SDX_MS_PASSWORD=... python3 scripts/sdx_nitro.py inventories/example/group_vars/all.yml --discover <sdx-ip>
```
Then:
```
ansible-playbook precheck.yml
ansible-playbook site.yml --tags precheck,image,profile,provision --ask-vault-pass
ansible-playbook site.yml --tags ha,postconfig --ask-vault-pass
```

---

## Part 8. Order of work for Cleveland

1. Set up the control node (Part 2) and vault (Part 3).
2. Run `ns_discover.py` on anything already there (Part 4).
3. Fill in `sites.yml` and `adc_sites.yml` for Cleveland.
4. Run the `mpx.yml` precheck until it passes.
5. Do the dry run (`--check`).
6. Build the one desk box: `--limit cle_adc_01 --skip-tags ha`.
7. Build the HA pair: `--limit site_cle`.
8. Apply the license (one box at a time).
9. Local login: turn it off with `disable_local_auth` after both login checks pass (see Part 5).
10. Write down anything that broke, and send it to the team.

## Part 9. Still open before a real run
- Is the large box SDX 17000 or MPX 17000?
- Real management IPs, VLANs, and subnets for each site.
- Approved standard 14.1 firmware build (51.80 or newer).
- NTP, DNS, LDAP details, and the hostname naming rule.
- Exact license name from your LAS account (for example `MPX 9200 Premium`).
- Moving the app config (VIPs, services, certs, logins) from the old boxes: `scripts/ns_migrate.py` now
  **reads** each old box and builds a cleaned-up config file for you to review (see Part 10). It does **not**
  load anything onto the new boxes yet.
- OK from NetScaler/BlueAlly to use the toolkit code (it has no license file).

## Part 10. Tool 5: `ns_migrate.py` (copy app config off an old box, look, don't touch)
1. Export (read-only, asks for the password): `python3 scripts/ns_migrate.py export --host <old box NSIP> --out migration_out`
   Export the HA **primary**. The files hold password hashes: keep `migration_out` in a protected folder.
2. Run NetScaler's `nspepi` on `migration_out/<host>/ns.conf` to convert old classic policies.
3. Copy `migration/example_map.yml`, fill in old -> new port names (from `show interface` on the 9200).
4. Transform: `python3 scripts/ns_migrate.py transform migration_out/<host>/ns.conf --map <your map> --out migration_out/<host>/new`
5. Read `<host>.summary.md`. Exit code 1 = BLOCK items to fix first (unmapped ports, classic policies, partitions,
   missing certs). Several old boxes onto one pair? Run `merge-check` on all the `.migrated.conf` files.
Loading the result onto the new pair and the cutover are **not built yet**. Never have the same VIPs live on old and new.

---

## Other ways to run it: PuTTY or VS Code

You don't have to use the scripts the way Part 2 shows. You have two other choices. Both folders are in the NetScaler Automation Drive folder.

**PuTTY - NetScaler CLI** ([open folder](https://drive.google.com/drive/folders/12BTQ3Q-5r-1qxua750UGXBn5B2hBN5Q5)): commands you type or paste on the box.
1. Run `00-check.txt` first. It only reads and changes nothing.
2. Fill in the <BLANKS> at the top of `cle_adc_01.conf` and `cle_adc_02.conf`.
3. Box 01 is the primary. Box 02 is the secondary. Run the parts in this exact order:
   01 Part A, then 02 Part A, then 01 Part B, then 02 Part B, then 01 Part C, then 02 Part C.
   Never run two boxes at the same time.
4. Run `99-verify.txt` to check your work.
- Box 02 does not get the traffic IP, route, DNS or NTP. HA copies them from box 01.
- Skip any part marked "ONLY FOR FIPS BOXES".
- You can't do licensing here. Use the web screen or the script for that.
- Risky lines have # in front, so they won't run. Take out the # only when you mean to run that line.

**VS Code** ([open folder](https://drive.google.com/drive/folders/1jst-5RO8BxpfJcB_rbzBFAH5W4iUdIOK)): the same scripts, run with buttons.
1. Set up WSL first (Part 2).
2. Unzip `VS Code setup (.vscode).zip` into the code folder.
3. In VS Code, go to Terminal, then Run Task. Go in this order:
   "2. Precheck Cleveland one box", then "2b. Dry run Cleveland one box (--check)", then "3. Build Cleveland one box", then "4. Build HA pair (Cleveland)".

None of these have been tried on a real box yet. Go slow on the first box.
