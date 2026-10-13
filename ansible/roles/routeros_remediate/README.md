# routeros_remediate

Converges a device back to its declared state: removes what is not declared
and restores what was tampered with. The plan comes from the same policy as
the audit (`ansible/lib/routeros_convergence/policy.py`), so whatever the
audit flags as actionable is what remediation changes, and nothing else.

```sh
ansible-playbook playbooks/routeros_remediate.yml -l r1.sco.memhamwan.net   # plan
```

**Plan mode is the default** and changes nothing: it prints the numbered
plan and saves it to `ansible/build/remediate/<host>-<time>.plan.{txt,json}`.

## What it removes or restores

Allowlist-based: everything in these categories that the declared state does
not name is removed (or disabled), unless the device's `routeros_allow`
(host_vars) keeps it.

| Step | What |
|---|---|
| 1 persistence | schedulers, scripts, and files they fetch or import (C2) or that match known payload names |
| 2 accounts | SSH keys on undeclared accounts or not declared for a declared one (needs 7.24 fingerprints; earlier versions are reported for routeros_access), undeclared accounts (the factory `admin`, `hamwan` and `packetbard` included), wrong groups |
| 3 services | every service except SSH and API-SSL disabled; those two on their declared ports, restricted to `management_sources_effective`; password login off (blocked while a declared SSH account has no key); forwarding off |
| 4 kits | VPN servers off (their default profile reset first), VPN clients, PPP accounts, profiles and pools (kept while something kept uses them), WireGuard peers, their addresses and interfaces, firewall filter/nat/mangle/raw rules, SOCKS, web proxy, traffic-flow and its targets, DDNS (`auto` from 7.17), resolvers and remote requests |
| 5 files | every other regular file (onboarding key files, exports, backups, crash reports) |
| 6 logging | the `remote` action back to the collector, the memory buffer back to 1000 lines, default rules re-enabled, disk rules removed, the remote topic rules re-added |
| 7 identity | system identity = inventory name |

The API-SSL allow list changes last of all: it can cut the session the
change is made over.

## File safeguards

- Disks and directories (`flash`, `skins`, `pub`) are never touched.
- A file named by anything that stays (a kept scheduler or script, a logging
  action, a certificate import) is kept and reported.
- Certificate and key files are kept unless their certificate is in
  `/certificate`.
- Package files (`.npk`) are left in place: they may be a staged upgrade.
- `routeros_allow.files` keeps anything else.

## Declaring legitimate extras

Start with plan mode on a device: every legitimate thing it proposes to
remove needs a `routeros_allow` entry in `inventory/host_vars/<host>.yml`
(syntax in `inventory/group_vars/routeros.yml`). Re-run until the plan
proposes only what should go. **Declare before the first apply.**
