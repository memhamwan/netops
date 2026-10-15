# RouterOS convergence — declared state, stacked roles (design & plan)

**Status: design only, nothing implemented.** Written 2026-10-13 at the end of
the hand cleanup after the September 2026 compromise, to be built by another
team. Every router-touching step stays behind the
[execution gate](../ansible/roles/routeros_baseline/README.md) and Ryan's PR
review. Incident specifics (timeline, per-device evidence, which devices are
still hostile) are in the private incident record, not in this public repo —
ask Ryan.

## Problem

From 2026-09-02, RouterOS SSH authentication bypasses (CVE-2026-67279,
CVE-2026-67276; fixed in 7.24.2 stable, 7.23.4 long-term, 6.49.21) were
exploited against the fleet. Every router below 7.24.2 with SSH reachable was
taken over, most by several bot crews in turn. Upgrading afterwards did not
make a device clean: credentials and accounts the attackers already had kept
working.

The cleanup was done by hand: capture evidence, diff the live export against
the last clean Oxidized export, write a RouterOS script per device, apply,
verify. It worked, but it was slow, tripped over version differences, and left
nothing reusable — and the same steps will be needed again for every device
rebuilt after a Netinstall.

The existing automation does not cover this:

- `routeros_baseline` corrects services, logging, NTP, DNS and identity, but its
  user audit is report-only and it cannot remove anything an attacker added.
- `bootstrap_ansible_user.yml` / `onboard_device.yml` create accounts and keys,
  but never remove keys or accounts that should not be there.
- There is no notion of "this device is hostile — do not send it credentials".
  mktxp, Oxidized and the plays keep authenticating to compromised devices.
- The role README says nothing has ever run, but device history shows the
  `ansible` account changing SSH, NTP and service settings on several routers
  in late August 2026. Reconcile the docs with what actually ran.

## What the cleanup had to undo

These are the categories a remediation role must handle. All were seen on
fleet devices in September–October 2026.

| Category | Seen |
|---|---|
| Accounts | Full-group accounts added by bots (`routeradmin`, `routeradmini`, `support`, `admin_obsq`, `svcops`, `sys-admin`, `admin-sys`, `MikroTiksystem`, `xadm*`, `admin1`, `test`, `user`, `ops`); the factory `admin` account, whose default password was the way in on one device; short-lived `SystemMikrotik` |
| SSH keys | Attacker keys on attacker accounts (comments `ntp-service`, `ops@hermes`); duplicate or uncommented imports on operator accounts that cannot be told apart without fingerprints |
| Schedulers | Weekly `/tool fetch` + `/import` from a C2 host (`backup-sync`), a startup task that re-imports the attacker key (`cfg-check`), self-deleting schedulers (`autosupoutrif`) |
| Files | Downloaded C2 scripts (`cfg-sync.rsc`, `sync.rsc`, `ntp.pub`), Linux miner payloads (`redtail.*`, `setup.sh`, `clean.sh`), randomly named `/system backup` files (config theft), empty `log.0.txt` from bogus disk-logging rules |
| Services | SSH moved to 22; telnet/ftp/www/winbox/api enabled and open to `0.0.0.0/0`; SSH disabled outright to lock out rival bots; SSH password login forced on |
| Proxy / VPN kits | PPTP/L2TP servers enabled; PPP secrets, profiles and pools (`P00LTP`, `ZPPTP`, `pptp-xpool`, `l2-xpool`); masquerade NAT for the proxy pools; `/ip cloud` DDNS on; a WireGuard listener with attacker peers |
| Firewall | Dozens of duplicate input `accept` rules (`x-mgmt-*`, `x-vpn-*`) |
| Logging | Remote action target set to `0.0.0.0`, memory buffer cut to 1 line, default rules disabled, junk disabled `disk` rules |
| Other | DNS switched to public resolvers; traffic-flow toggled; devices upgraded by the attackers to keep rival bots out |

## Design

### Goals / non-goals

Goals:

1. The expected state of every router is declared in the inventory: lifecycle,
   accounts, services, per-device allowances and target version.
2. Small roles that stack, each runnable alone, each reading before it writes
   and planning before it applies.
3. One gated run converges a compromised-but-reachable router to the declared
   state, and the same run is a no-op on a clean router.
4. Credentials are never sent to a device we do not trust.
5. The same stack finishes a device rebuilt by Netinstall (with the restore
   layer, below).
6. A read-only audit runs continuously and raises alerts on drift.

Non-goals: general management of per-device network config (interfaces, IPs,
OSPF, wireless) beyond the restore layer; Linux hosts (`linux_baseline`
covers those); the edge router's containment rules (a later layer).

### Lifecycle groups

A new `quarantined` group joins the existing ones. Quarantined means "assume
hostile": keep watching it, never authenticate to it.

| Group | ICMP probes / alerts | mktxp, Oxidized | Device plays | DNS zone | OSPF router-id check |
|---|---|---|---|---|---|
| active (default) | yes / normal | yes | yes | yes | export required |
| **quarantined** (new) | yes / normal | no | never | yes | skipped |
| `expected_down` | yes / labelled, no page | no | no | yes | skipped |
| `excluded` | no | no | no | no | skipped |

Changes needed: every play's host pattern gains `:!quarantined`;
`mktxp.conf.j2` and `router.db.j2` drop the group; `check_ospf_router_ids.py`
skips it. **Trap:** `icmp-routeros.yml.j2` takes the `site` label from the first
group name that is not a lifecycle group, so `quarantined` must be added to that
reject list or quarantined hosts get `site: quarantined`. Leaving quarantine
takes a Netinstall + restore: a remediation or audit run would send the fleet
credential to a device that is still untrusted. Once rebuilt, it leaves the
group and is onboarded like a new device.

### Declared state (variables)

In `group_vars` for `routeros` unless noted:

- `management_sources` — CIDRs allowed to reach SSH and API-SSL. The public
  inventory carries only the netops host; operators' addresses are personal and
  live in sops (`management_sources_private`), merged at run time. One list
  feeds the SSH and API-SSL allow lists (and later the edge router's admin list).
- `service_accounts` — `oxidized`, `oxidized-full`, `mktxp`, `ansible`, each with
  group, auth method (key or password) and the sops variable that holds it.
- `operators` — from `files/operators/`: turnrye, seichold, ae5au.
- Allowed accounts = `service_accounts` + `operators`. Everything else is
  removed. This retires `hamwan`, `packetbard` and the factory `admin`.
- `routeros_target_version: 7.24.5` — the one place the fleet version is set.
  The audit warns when a device is behind it and raises critical below the
  security floor (7.24.2).
- Expected services: SSH on 222 and API-SSL on 8729, both restricted to
  `management_sources`; everything else disabled, including `reverse-proxy`.
  SSH password login off. `dns_allow_remote_requests: false` (existing). DDNS off.
- `routeros_allow` in `host_vars` — legitimate per-device exceptions the
  remediation must keep, by name or comment: NAT rules, PPP secrets/profiles/
  pools, SSTP/OVPN servers and clients, WireGuard interfaces and peers, extra
  firewall rules, schedulers, scripts, files. Examples: the edge router's
  firewall rules, PPP accounts and WireGuard peers; the core routers'
  masquerade for their private client subnets; FTN's SSTP client. **A device's
  allowances must be declared before remediation first runs in apply mode
  there** — plan mode shows what would be removed, which is how gaps get found.

### Roles, in stacking order

| # | Role | Purpose | Transport |
|---|---|---|---|
| 1 | `routeros_facts` (new) | Read-only snapshot, normalized, saved per host | API; SSH for keys, history, file download |
| 2 | `routeros_access` (merges bootstrap + onboard) | Service and operator accounts, keys, API cert, passwords; rotation switches | SSH |
| 3 | `routeros_remediate` (new) | Remove everything not declared; restore logging | API; SSH for keys and files |
| 4 | `routeros_baseline` (extended) | Hardening as policy | API |
| 5 | `routeros_firmware` (extended) | Target version, controller-side package fetch, safety gates | SSH |
| 6 | `routeros_audit` (new play) | Drift report, metrics, alerts | API (read-only) |

Transport decision: API first (structured data, check mode); SSH only where the
API cannot do the job — `/user ssh-keys`, reading `/system history`, and copying
files off the device.

#### `routeros_facts`

Gathers: version, architecture, board, RouterBOOT version, installed packages,
free flash; users (group, disabled, last login); SSH keys (user, type, and on
7.24+ the fingerprint); schedulers; scripts; files (type, name, size, date);
static `/ip service` entries (filter out the per-session dynamic entries 7.24
adds); `/ip ssh`; PPP/PPTP/L2TP/SSTP/OVPN servers, clients and secrets;
WireGuard; NAT/filter/mangle/raw; SOCKS, proxy, traffic-flow; `/ip cloud`;
`/ip dns`; logging actions and rules; device-mode; recent history. Writes
`ansible/build/facts/<host>.json` (gitignored) for the later roles and the audit.

#### `routeros_access`

Merges the two SSH plays and keeps their rotation switches, adding
`rotate_api_password` and `rotate_mktxp_password`. Key sync for operator and
service accounts uses replace-all semantics: import the declared keys first,
then remove the key IDs captured before the import, so a failed import never
leaves an account without a key. Never runs on quarantined hosts.

#### `routeros_remediate`

- `remediate_mode: plan` (default) prints and saves the plan and changes
  nothing; `apply` also needs `confirm_execution=true`. Apply runs `serial: 1`.
- **Evidence first, every apply:** `/export`, the facts, and a copy of every
  file, into `remediate_evidence_dir` — outside the repo, private. Exports from
  7.17 print secrets in clear (OSPF auth key, wireless keys); backups hold
  password hashes. Treat the evidence store as secret.
- Removal is allowlist-based: accounts, SSH keys (on allowed accounts keep only
  declared keys), schedulers, scripts, PPP secrets/profiles/pools, PPTP/L2TP/
  SSTP/OVPN servers, WireGuard, NAT/filter/mangle/raw rules — all removed or
  disabled unless declared in `routeros_allow` or managed by `routeros_baseline`.
  SOCKS, proxy and traffic-flow off; DDNS off; logging actions and rules
  restored.
- **Files: remove every regular file**, after the evidence copy. Safeguards:
  never touch `disk` or `directory` entries (`flash`, `skins`, `pub`); delete
  certificate/key files only after confirming the certificate is present in
  `/certificate`; before deleting, scan the export for anything that names a
  file (`file-name=`, `/import`, `public-key-file=`) and show it in the plan;
  honour `routeros_allow.files`. Checked 2026-10-13 on the reachable routers:
  nothing in use depends on a regular file — what remains is onboarding
  leftovers, old exports and scripts, crash reports, a packet capture, and old
  config backups that themselves contain secrets.
- Order: persistence first (schedulers, scripts, C2 files), then accounts and
  keys, then services, then kits and rules, then remaining files, then logging.
- Removing an account does not end its open sessions; they linger in
  `/user active` until they time out or the device reboots. Report them.
- Report `device-mode` `flagged` and do not try to clear it (that needs a
  physical button press). Expect some changes to fail while flagged and report
  each one.

#### `routeros_baseline` (additions)

SSH password login off (after `routeros_access` has ensured every remaining SSH
account has a key — the role must check this and stop otherwise); SSH service
restricted to `management_sources`; `reverse-proxy` off; DDNS off; decide on
`/ip ssh forwarding-enabled`. Property names must follow the version table
below.

#### `routeros_firmware` (additions)

- `routeros_target_version` comes from `group_vars` (7.24.5).
- **Controller-side package fetch** (`run_once`, on localhost): from the facts,
  work out each in-scope device's architecture and installed package set (e.g.
  `routeros` + `wireless` on 802.11ac radios); download
  `routeros-<ver>-<arch>.npk` and any extra packages from
  `download.mikrotik.com` into a local cache (`~/.cache/netops/routeros/<ver>/`);
  verify checksums (see open questions); skip what is already cached. The
  existing offline mode then uploads them with scp. Online mode stays available
  but will fail while the edge containment blocks routers from reaching the
  internet.
- **Safety gates**, from a remote 7.9 → 7.24.5 upgrade that left a 16 MB
  PoE-providing board unbootable and took the devices it powers down with it:
  - `upgrade_site_presence_required: true` in `host_vars` for devices with a
    single path in, PoE providers, and anything whose failure strands other
    devices; the play refuses those unless `-e site_presence=true`.
  - Pre-checks reported in the plan: free flash vs. package size, RouterBOOT
    version, PoE loads, what sits behind the device.
  - Keep the current version's packages cached for a downgrade; evidence
    snapshot before reboot; RouterBOOT upgrade as a separate, flagged step.

#### `routeros_audit`

- facts → compare with the declared state → per-device drift report: unexpected
  accounts and keys, schedulers, scripts, file count, exposed services, password
  login, version behind target / below floor, logging target, device-mode
  flagged, lifecycle.
- On demand from an operator laptop, and on a timer on the netops host. The
  scheduled run must not need write credentials: use the read-only `mktxp` API
  account (already on that host) and the read-only `oxidized` SSH key, or a
  dedicated read-only `audit` account.
- Exports node_exporter textfile metrics (e.g.
  `routeros_audit_unexpected_users{device}`,
  `routeros_audit_version_behind{device}`,
  `routeros_audit_password_login_enabled{device}`) with Prometheus alert rules
  and promtool unit tests.
- Adds RoMON discovery from the core router, which returns identity, version,
  board and uptime for devices unreachable by IP, including quarantined ones
  (see the version table for the wide-terminal trick).

#### Later layers

- `routeros_restore` — for Netinstalled devices: render a restore script from
  the device's last clean Oxidized export (before 2026-09-02), with secrets
  replaced from sops (new OSPF auth key, new point-to-point wireless keys, SSTP
  passwords); then access → remediate (no-op) → baseline → audit.
- `ospf_filters` — on clean routers adjacent to quarantined radios, accept only
  the routes each link should carry. A quarantined radio holds the OSPF key and
  could otherwise advertise a default route or another site's prefixes.
- `edge_containment` — the edge router's containment address lists and rules
  as code.

The OSPF auth key and the point-to-point wireless keys cannot be rotated while
quarantined radios sit inside the links: changing them on the clean side only
would drop the links. Rotate them as part of each site's restore.

### Entry points

- `playbooks/routeros_audit.yml` — read-only; safe any time.
- `playbooks/routeros_converge.yml` — facts → access → remediate → baseline →
  audit, tagged by stage, gated by `confirm_execution`, scoped with `-l`.
- `playbooks/rotate_credentials.yml` — generate new random passwords into sops,
  apply to active hosts via `routeros_access`, redeploy the netops host so mktxp
  picks up its password, then verify the mktxp scrape and an `ansible` API
  login. **Run only after quarantine is deployed**, or mktxp immediately sends
  the new password to the quarantined devices.
- `playbooks/routeros_firmware.yml` (existing) — with the fetch and gates above.
- Quarantine itself is an inventory edit plus a netops-host redeploy.

### Execution model

- Plays run from an operator laptop (the repo's Ansible venv). The device
  allow lists include the operator's address via `management_sources`, so no
  tunnel through the netops host is needed. Scheduled audit runs on the netops
  host.
- Secrets in sops (age), operator addresses included; `no_log` on every task
  that handles them.
- Host keys pinned through `ansible/known_hosts` and `seed_known_hosts.yml`.
- Gates: `confirm_execution`, `remediate_mode`, `site_presence`. The first run
  of any new role is `--check --diff` on one clean device.

## RouterOS version differences

Learned during the cleanup; the roles must handle each.

| Area | 7.9 / 7.12 | 7.17 | 7.24 |
|---|---|---|---|
| SSH/API allow-list property on `/ip service` | `address` | `address` | `available-from` |
| Per-session dynamic entries in `/ip service` | no (`dynamic` not filterable) | no | yes — always filter `dynamic=no` |
| SSH password-login setting | `always-allow-password-login` | `always-allow-password-login` | `password-authentication` (`yes` / `no` / `yes-if-no-key`) |
| `/ip cloud set ddns-enabled=no` | untested (boolean) | **rejected** | **rejected** — only `yes` / `auto`; `auto` is off (7.24.5 CHR) |
| `reverse-proxy` service | absent | absent | present, enabled by default |
| Remote syslog format | `bsd-syslog` | `bsd-syslog` | `remote-log-format` (7.18+, already handled) |
| Default `/export` | — | **prints secrets in clear** | hides them |
| SSH key fingerprints in `print` | no | no | yes |

Also:

- A syntax error anywhere in an imported `.rsc` aborts the whole import before
  anything runs, so a script that mixes version-specific commands fails
  everywhere. Prefer the API; where scripts are unavoidable, render per version.
- `:parse` does not check syntax (it returns `code` for anything), so it cannot
  serve as a dry run.
- Device-mode `flagged` (seen on 7.24) blocks some changes, e.g. adding
  schedulers or setting PPTP/L2TP servers.
- Wide CLI output: log in as `user+300w` to get a 300-column terminal. Needed
  for `/tool romon discover`, whose version and board columns are cut off at 80
  columns and which has no `detail` option.
- A 16 MB board keeps uploaded files in RAM (the top level) and flash in
  `flash/`; free flash is not the limit on uploading a package, but the
  installed size is.

## Testing

- Planner unit tests on facts fixtures built from the incident evidence with
  every secret stripped, covering: a heavily compromised device (rogue `admin`,
  WireGuard backdoor, `x-*` rules, miner files); a backdoor-scheduler device;
  a PPTP-proxy device; a clean device (expect only the files policy to act);
  the edge router (many legitimate filter rules, PPP accounts and WireGuard
  peers — expect nothing removed once its `routeros_allow` is declared).
- CI: existing render, lint and syntax checks; the planner tests; promtool
  tests for the audit alerts.
- Live order: audit everywhere → plan on a clean core router → apply there
  (expect no-op) → plan, then apply, on the cleaned devices → credential
  rotation.

## Rollout (PRs, each gated on Ryan's review)

1. **Lifecycle and access sources.** `quarantined` group, host patterns,
   templates, OSPF check; `management_sources` with the private part in sops;
   README reconciled with what has actually run. *Accepted when* `ci_render`
   shows quarantined hosts absent from mktxp and `router.db`, present in the
   probes with the right `site` label, and skipped by the OSPF check.
2. **Facts + audit (read-only).** Laptop and scheduled runs, metrics, alerts.
   *Accepted when* the audit reproduces the 2026-10-13 manual sweep.
3. **Remediate, plan mode only,** with the fixtures. *Accepted when* fixtures
   pass and a live plan on clean devices proposes nothing beyond the files policy.
4. **Remediate apply + baseline additions.**
5. **Access merge + `rotate_credentials.yml`,** then the rotation itself (after
   PR 1 is deployed).
6. **Firmware:** package fetch, safety gates, `routeros_target_version: 7.24.5`.
7. **Restore layer** (before the site visits), then `ospf_filters` and
   `edge_containment`.

## Decisions (2026-10-13)

- API first; SSH only for keys, history and file copies.
- Plays run from an operator laptop; operator addresses kept in sops.
- Allowlist remediation; remove all regular files, with the evidence copy and
  safeguards above.
- Retire `hamwan`, `packetbard` and the factory `admin`; keep `seichold`.
- Target RouterOS 7.24.5 through one variable; packages fetched to the
  controller automatically.

## Open questions

1. Checksum source for MikroTik packages — confirm MikroTik publishes per-file
   SHA256 sums for each release; otherwise rely on RouterOS's own package
   signature check at install.
2. Can sessions of removed accounts be ended remotely on each version (e.g.
   `/user active` request-logout), or only by reboot?
3. Keep or drop `/ip ssh forwarding-enabled` (some routers had it on before the
   incident)?
4. Evidence store location and retention — it holds secrets.
5. Scheduled audit identity: reuse `mktxp` (read-only API) + `oxidized` (read-only
   SSH), or add a dedicated read-only `audit` account?
6. Listing quarantined hosts in this public inventory reveals which devices are
   hostile. The attackers already know; confirm that is acceptable.
7. Re-census `expected_down`: some hosts in it answered in October 2026.
