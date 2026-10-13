# routeros_facts

Read-only snapshot of one RouterOS device over the API (API-SSL 8729), saved
as `ansible/build/facts/<host>.json` and set as `routeros_facts` for the roles
after it (audit, remediate, firmware). First role of every RouterOS
convergence play; see [docs/routeros-convergence-design.md](../../../docs/routeros-convergence-design.md).

The reading lives in `ansible/lib/routeros_convergence` (`gather.py` lists the
menus) and runs as `python -m routeros_convergence gather`, so the netops
host's scheduled audit reads devices with exactly the same code.

- One API session per device, 45 menus: version, board, RouterBOOT, packages,
  device-mode, users, groups, SSH keys (with fingerprints from 7.24), active
  sessions, services, `/ip ssh`, certificates, schedulers, scripts, files
  (never their contents), PPP, VPN servers and clients, WireGuard, firewall
  filter/nat/mangle/raw, SOCKS, proxy, traffic-flow, `/ip cloud`, DNS, NTP,
  logging, the last 300 `/system history` entries, RoMON, PoE.
- Menus a device lacks are recorded in `errors`, not fatal.
- Secrets are redacted before anything is written: passwords, private and
  pre-shared keys, IPsec secrets, file contents, and `password=` /
  `secret=` inside scheduler, script and history text.
- Credentials: `routeros_api_user` (`ansible`) and its sops password, passed
  to the reader through the environment, never on the command line.
- `routeros_facts_required: false` records an unreadable device
  (`routeros_facts_ok: false`, `routeros_facts_error`) instead of failing it;
  the audit uses that.

What was learned about the API while building it (lab, RouterOS 7.24.5):
librouteros returns RouterOS `yes`/`no` as booleans; `/ip service` rows carry
`available-from` from 7.24 (`address` is still accepted as a write alias);
`/user ssh-keys` prints fingerprints with base64 padding; the read-only
`mktxp` account (`api,read`) can read history, users, keys, files and
sessions; RoMON discovery needs the `romon` policy.
