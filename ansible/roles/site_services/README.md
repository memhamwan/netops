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

# M2+ — announce (after review; requires sops access for the OSPF key)
ansible-playbook playbooks/site_services.yml \
  -e anycast_enabled=true -e anycast_confirm=true
```

## Third switch: authoritative NSD (`nsd_enabled`)

A separate, independently-gated capability: serve `memhamwan.net` (and the
reverse zones) **authoritatively** from NSD, co-located with unbound and chrony
but separated **by address**. Design and cutover plan:
[docs/dns-authority-design.md](../../../docs/dns-authority-design.md). This PR
is the **serve-in-parallel** stage — NSD is live but **not delegated**; DNSSEC
signing, the edge `:53` permit, and the registrar NS/glue/DS cutover are the
next PR.

| | `nsd_enabled: false` (default) | `nsd_enabled: true` |
|---|---|---|
| authoritative server | none — unbound answers the zone from `local-data` | NSD, on the `authdns` anycast /32s + `127.0.0.1@5353` |
| unbound internal zone | `local-data` (rendered from inventory) | **stub-zone → local NSD** (`local-data` removed) |
| unbound `:53` bind | `0.0.0.0` + `interface-automatic` | **explicit**: loopback, host IP, recursive anycast /32s only (never the `authdns` /32s) |
| `authdns` /32s (`44.34.132.53`/`.133.53`) | in `anycast_services`, never placed on the interface | placed + announced only when NSD is healthy **and** the anycast master gate is on (`anycast_enabled=true`, `anycast_confirm=true`) — health-gated like dns/ntp. With `nsd_enabled` alone the /32s stay off the interface. |

Enabling requires `-e nsd_confirm=true` **and record parity** — a stub-zone has
no fall-through, so unbound becomes authoritative for the *whole* zone via NSD;
any `memhamwan.net` name not in the rendered zone (grafana/prometheus/
alertmanager + the ~77 Cloudflare-only records) NXDOMAINs on-net until it is
added. See the design doc's D1 milestone.

```sh
# 1. Serve in parallel (after record parity + review): local NSD + unbound
#    stub-zone. The authdns /32s are NOT yet on the interface or announced —
#    the anycast master gate is still off. No sops needed yet; DNSSEC keys
#    arrive with the next PR.
ansible-playbook playbooks/site_services.yml \
  -e nsd_enabled=true -e nsd_confirm=true

# 2. Announce the authdns /32s. Reachability additionally requires the anycast
#    master gate (and sops for the OSPF key), exactly like the dns/ntp /32s —
#    nsd_enabled by itself never places or announces an address.
ansible-playbook playbooks/site_services.yml \
  -e nsd_enabled=true -e nsd_confirm=true \
  -e anycast_enabled=true -e anycast_confirm=true
```

Why co-located but separated by address: unbound and NSD both want `:53`, so
NSD binds only the `authdns` anycast pair + a `127.0.0.1@5353` loopback
listener, and unbound (in NSD mode) drops its `0.0.0.0` wildcard for explicit
binds that exclude those IPs. The loopback listener is what unbound's
stub-zone resolves the internal zone through — the split-brain safeguard: on-net
recursion always gets the fleet's own authoritative answers, never a stale copy
or a broken public delegation. The zone is rendered from the inventory
identically onto every host (no AXFR); `ip-transparent` lets both daemons bind
the anycast /32s before the health script places them on `anycast0`.

First-enable ordering matters and the role handles it: the NSD package is
installed **without auto-starting** (its stock config would grab `:53` and
collide with unbound), unbound is reconfigured and **restarted first** to free
the wildcard socket (a `flush_handlers` in `tasks/main.yml`), and only then is
NSD started onto the now-free authdns addresses. There is a sub-second window
during that hand-off where unbound's stub points at an NSD that isn't up yet, so
internal names briefly SERVFAIL — acceptable on a deliberate, gated enable. NSD
also needs `do-not-query-localhost: no` on unbound in this mode (the default
`yes` would block the stub target and SERVFAIL the whole internal zone), and the
rendered zonefiles are `nsd-checkzone`-validated (not just `nsd-checkconf`,
which never parses them) before the restart handler can fire.

## Before anycast can be enabled

1. **`site_lan_interface`** must be set for the host in the inventory
   (`eth0` on rpi.sco).
2. Confirm the legacy LEB service hosts are still dark, or that their
   announcements are disabled — see the split-brain note in the design doc.

The OSPF MD5 key ships in sops as `ospf_md5_key` (confirmed by Ryan and
verified against r1.sco on 2026-08-30). The role still asserts it is present
rather than joining OSPF unauthenticated, which would reproduce the "type
mismatch" adjacency flood already diagnosed at HIL. It is the old shared
fleet key — when the planned credential rotation happens, this value and the
`ospf_auth` role have to move together.

## OSPF parameters, verified against the fleet

Read off r1.sco's interface templates on 2026-08-30 — the router the Pi
actually peers with, on the same `bridge` segment:

| | r1.sco template | this role |
|---|---|---|
| area | `backbone-v2` → area-id `0.0.0.0` | `ip ospf area 0.0.0.0` |
| type | broadcast | `ip ospf network broadcast` |
| auth | md5, `auth-id=1` | `message-digest-key 1 md5` |
| hello / dead | 10s / 40s | 10 / 40 (`ospf_hello_interval`, `ospf_dead_interval`) |
| cost | 10 | 10 (`ospf_interface_cost`) |
| priority | 1 | **0** — the Pi must never win a DR election |

Mismatched hello/dead timers prevent an adjacency from forming at all, which
is why they are pinned here rather than left to frr's defaults. Note the
r1.sco `bridge` template *does* carry auth — unlike the `vrrp1` template at
HIL whose missing auth caused the type-mismatch flood.

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
- **Recursion vs authoritative are split in the ACL.** Recursion is fleet-only
  (`dns_recursion_cidrs`: `44.34.128.0/21` + RFC1918, *not* all of 44/8); the
  internal zone is served authoritatively to `0.0.0.0/0` via `refuse_non_local`
  (`dns_authoritative_public`, default true), which answers local-data but
  refuses recursion, so it can never be an open resolver. `ip-ratelimit` caps
  the public face. `ci_render.yml` pins that `0.0.0.0/0` is never `allow` in
  either switch position. This is what lets an off-network client resolve a
  fleet name to SSH in — but reachability also needs the gated er1 :53 permit
  (see `docs/site-services-design.md`). NTP stays fleet/AMPRNet-scoped
  (`ntp_allowed_cidrs`), not public.
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
