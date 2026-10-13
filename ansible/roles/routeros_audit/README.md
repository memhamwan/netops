# routeros_audit

Read-only drift report: each device's snapshot (routeros_facts) compared with
its declared state (`routeros_declared`, built in
`inventory/group_vars/routeros.yml` from the accounts, services, logging and
version settings plus the device's `routeros_allow`). Changes nothing.

```sh
ansible-playbook playbooks/routeros_audit.yml [-l r1.sco.memhamwan.net]
```

Per device it prints the findings (yellow when there is a critical or warning
one) and writes `ansible/build/audit/<host>.json`. Once per run it adds:

- RoMON discovery from `routeros_audit_romon_core` (r1.sco): identity,
  version and board of devices the audit must not or cannot log in to.
  Needs the `romon` policy on the `ansible` account's group (in
  `service_groups`; routeros_baseline applies it).
- TCP probes of the management ports (22, 23, 80, 222, 1723, 8291, 8728,
  8729) of every device in scope, quarantined ones included: connect only.
- `fleet.txt` / `fleet.json`: one line per device with lifecycle, whether it
  was read, version (from the API or RoMON, `!` below the security floor),
  finding counts, open ports and the critical categories.
- `routeros-audit.prom`: the same metrics the netops host exports.

The checks are in `ansible/lib/routeros_convergence/policy.py`, shared with
the remediation planner: what the audit reports is what remediation would
change. Severities: **critical** for anything that gives someone else control
or hides it (undeclared accounts and keys, C2 schedulers and payloads, proxy
and VPN kits, services open to every address, input accept rules, tampered
logging, open resolvers, sessions of removed accounts, the SSH-bypass history
signature, a version below the floor); **warning** for drift that weakens the
device (password login, forwarding, extra rules, backups and exports on
flash, DDNS, wrong resolvers, version behind target, device-mode flagged);
**info** for leftovers (onboarding key files) and RouterBOOT behind.

## Scheduled

The netops host runs the same comparison every 30 minutes
(`netops-routeros-audit.timer`) as the read-only `mktxp` account, over the
active devices only (never quarantined: the account's password must not
reach them). It writes textfile metrics and a root-only
`/var/lib/netops/audit/report.json`. The metrics are counts per device,
check and severity, never names or addresses, because the anonymous Grafana
can query Prometheus. Alerts: `rules/routeros-audit.yml`.
