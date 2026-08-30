# site_services — DRAFT, not yet executed

Recursive + internal DNS (unbound), NTP (chrony), and — behind a second
switch — anycast announcement of the fleet's existing service addresses via
OSPF (frr). Design, research findings, and the monitoring strategy live in
[docs/site-services-design.md](../../../docs/site-services-design.md).

**Nothing in this role has run against a host.** It is authored for review
first, in the same spirit as `routeros_baseline`: this role does not change
router config, but with `anycast_enabled` it makes the host an OSPF speaker
on the site LAN and claims addresses the entire fleet points at.

## Two switches, not one

| | `anycast_enabled: false` (default) | `anycast_enabled: true` |
|---|---|---|
| unbound / chrony | installed, serving on the host's own address | same |
| health timer | runs, writes every metric | same, **plus** adds/removes service addresses |
| dummy interface, frr, OSPF | not installed | installed, adjacency on `site_lan_interface` |
| service IPs announced | none | the five in `anycast_services` |

Enabling also requires `-e anycast_confirm=true` (enforced by the playbook),
so announcements can never be a side effect of a routine redeploy.

```sh
# M1 — serve on the host address only, announce nothing
ansible-playbook playbooks/site_services.yml --check --diff
ansible-playbook playbooks/site_services.yml

# M2+ — announce (after review, and after the OSPF key is in sops)
ansible-playbook playbooks/site_services.yml \
  -e anycast_enabled=true -e anycast_confirm=true
```

## Before anycast can be enabled

1. **The OSPF MD5 key must be in sops** as `ospf_md5_key`. It is deliberately
   *not* committed: the fleet's key is the old shared one and nobody has
   verified which value is current on every device — read it off a router,
   then `sops secrets/secrets.sops.yaml`. The role asserts its presence
   rather than joining OSPF unauthenticated, which would reproduce the
   "type mismatch" adjacency flood already diagnosed at HIL.
2. **`site_lan_interface`** must be set for the host in the inventory
   (`eth0` on rpi.sco).
3. Confirm the legacy LEB service hosts are still dark, or that their
   announcements are disabled — see the split-brain note in the design doc.

## Notes for the reviewer

- **Health-coupled withdrawal is one-directional by design.** The DNS check
  queries an *internal* name, so an internet outage does not withdraw the
  resolvers (internal names still resolve; withdrawing everywhere would leave
  the network with none). Recursion failure is reported and alerted, never
  acted on. Likewise chrony's orphan/local mode is a normal islanded-site
  state, not a withdrawal condition.
- **`ip ospf priority 0`** — the Pi never becomes DR/BDR, so a reboot cannot
  trigger a designated-router election on the site LAN.
- **One dummy interface** (`anycast0`) carries all five /32s; each address is
  added/removed independently, so DNS can be withdrawn while NTP keeps
  serving. `redistribute connected` is filtered through a prefix-list that
  permits exactly those /32s and denies everything else, as type-1 externals.
  This is self-discipline, not containment — fleet-side in-filters are the
  real control and are M4 work.
- **`interface-automatic: yes`** in unbound is what makes anycast replies
  source from the address the query arrived on; without it answers would come
  from the host's own address and clients would drop them as off-path.
- **`/etc/resolv.conf`**: the role points the host at its own resolver and
  sets NetworkManager `dns=none`. On rpi.sco, tailscaled also rewrites
  resolv.conf when `--accept-dns` is on; if the file keeps reverting after a
  deploy, that is why (`tailscale set --accept-dns=false` is the fix, done by
  hand — it is a host-access decision, not something this role should flip).
- **unbound `local-zone ... transparent`**: locally-defined names are answered
  locally, everything else in `memhamwan.net` falls through to the public
  Cloudflare zone. Do not add public service names (grafana, prometheus,
  alertmanager) to `dns_extra_records.yml` — shadowing them would break the
  Caddy vhosts and their certificates.
- **Zone data is rendered, not transferred.** Every service host gets an
  identical file from the inventory; the health script exports its checksum so
  a host that missed a deploy surfaces as `ZoneDataSkew` instead of quietly
  answering differently.
- The `unbound-checkconf` validators run against the config *fragments* in
  `/etc/unbound/unbound.conf.d/`. If a future unbound rejects a fragment
  standalone, drop `validate:` from those two tasks rather than weakening the
  config.

## Open questions carried from the design doc

1. OSPF speaker on the Pi vs router-side `netwatch` + static routes.
2. All five legacy IPs, or start with `44.34.132.1` + `44.34.128.181`?
3. Is unbound `local-data` enough, or does anything need real zone transfers?
4. Interim: point routers at the unicast address while LEB is dark?
5. The HIL Pi's hostname/IP, and whether it can take this second duty.
