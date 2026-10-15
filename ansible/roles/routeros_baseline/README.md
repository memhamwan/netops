# routeros_baseline

**Execution gate: no automation-driven router changes without Ryan's PR
review.** All three device playbooks (`bootstrap_ansible_user.yml`,
`onboard_device.yml`, `routeros_baseline.yml`) refuse to run without
`-e confirm_execution=true`; use it only for a change that has been reviewed,
and start with `--check --diff`.

**What has run.** All three plays ran fleet-wide on 2026-08-29/30 against the
devices reachable then: the `ansible` account, the backup and mktxp accounts,
operator accounts and keys, the per-device api-ssl certificates, and the
baseline itself (service lockdown with plaintext 8728 disabled, logging, NTP,
identity). The api-ssl cut-over completed that day (netops PR #12); fixes
found during the runs are in the 2026-08-29/30 history (e.g. the api-ssl
certificate usage found on sec3.sco). Device history on several routers shows
the `ansible` account making those SSH, NTP and service changes. The DNS
resolver tasks were added afterwards (PR #23) and have no recorded run. Nothing has run
since the September 2026 compromise; devices changed underneath, so treat the
first post-incident run as a first run (`--check --diff`, one clean device).
Devices in the `quarantined` lifecycle group are never targeted.

Replaces the `device-onboarding/*.sh` scripts plus accumulated hand-fixes.
Account *creation* lives in the two SSH-based plays —
`bootstrap_ansible_user.yml` (the `ansible` automation account) and
`onboard_device.yml` (`oxidized`, `oxidized-full`, `mktxp`) — while this role
runs over the RouterOS API (`api_modify`), corrects what exists and removes
what is not declared. `--check --diff` reports the drift and changes nothing.

- **declared menus** (`routeros_config` in defaults): one `api_modify` per
  menu. Schedulers, scripts, PPP accounts and profiles, WireGuard, firewall
  filter/nat/raw rules and flow-export targets default to *none*, so anything
  a device has there is removed unless its host_vars lists it (or sets the
  variable to `null` to leave that menu alone until it is declared — see
  `inventory/host_vars/er1.atl.memhamwan.net.yml`). PPTP/L2TP/SSTP servers,
  SOCKS, web proxy, traffic-flow and DDNS are off; the memory log is 1000
  lines. Pools, mangle rules and OVPN are not managed (DHCP pools and MSS
  clamping are legitimate on most devices).
- **accounts**: every account outside `routeros_allowed_accounts` (service
  accounts, `operators`, per-device `routeros_extra_accounts`) is removed —
  the factory `admin`, `hamwan` and `packetbard` included — with the SSH keys
  of removed accounts. Nothing is ever created (this role can never mint a
  passwordless account). Extra keys on a declared account are replaced by
  `onboard_device.yml -e rotate_operator_keys=true`.
- **files**: every regular file (not disks, directories or staged packages)
  is copied to `routeros_files_evidence_dir` and removed, over SSH as an
  operator (removing backups needs the `sensitive` policy the API account
  lacks); `routeros_files` keeps one by name
- service lockdown: telnet/ftp/www/www-ssl/winbox/reverse-proxy off, ssh:222
  restricted to the management sources, strong-crypto, no SSH forwarding,
  MAC-server none, bandwidth-server off; **api-ssl (8729, per-device cert)
  stays on** restricted to `api_allowed_sources`, plaintext api (8728)
  disabled (diff from old ioc-terraform role, which disabled the API outright)
- key-only SSH login (7.21+), only if every remaining SSH account holds a
  key — checked before any change; the role stops there otherwise
- remote syslog (7.18+/pre-7.18 schema fallback) + topic rules
- NTP with `time.cloudflare.com` fallback (fleet drifts when LEB is dark)
- DNS resolvers (`/ip dns servers`): internal anycast + Cloudflare fallback —
  some devices ship with none set (e.g. r2.sco), which breaks on-box name
  resolution including `/system package update`. `allow-remote-requests=false`
  (routers aren't open resolvers; override `dns_allow_remote_requests` per device
  if one truly serves local clients)
- FQDN identity enforcement

Needs community.routeros 3.22+ (`ansible-galaxy collection install -r
requirements.yml --upgrade`): 7.24 renamed the `/ip service` allow list to
`available-from`. Verified end to end on a RouterOS 7.24.5 CHR carrying the
September 2026 artifacts: one run removed them, a second run changed nothing.

## Known open questions for review

1. `api_modify` path coverage varies by collection/ROS version — the first
   `--check --diff` run (post-review) is the real validation pass.
2. **api-ssl migration (implemented in these drafts; manual, ordered run):**
   1. `onboard_device.yml` fleet-wide — creates the per-device self-signed
      cert and enables api-ssl (8729) *alongside* plaintext 8728.
   2. Flip `mktxp_use_ssl: true` in `roles/netops_host/defaults/main.yml`
      and redeploy the backup host — the collector moves to 8729.
   3. `routeros_baseline.yml` — runs over 8729 and its final `api_lockdown`
      disables plaintext 8728 and pins api-ssl to `api_allowed_sources`.
   Out of order this breaks metrics (step 2 before 1) or strands devices on
   plaintext (step 3 before 2). Remaining open: certs are self-signed and
   clients don't validate (`validate_certs: false`, mktxp
   `ssl_certificate_verify = False`) — encryption defeats passive capture but
   not an active MITM; an internal CA is the follow-up.
3. RouterOS `/user ssh-keys` cannot be managed via API — key imports stay in
   the SSH-based bootstrap/onboarding plays (service accounts *and* operator
   keys from `files/operators/`).
4. romon and OSPF auth intentionally not touched yet (`ospf_auth` will be a
   separate audit-first role; romon secret not yet in sops).
5. Old role disabled neighbor discovery fleet-wide; kept out of this draft —
   decide whether to restrict to an interface list instead.
