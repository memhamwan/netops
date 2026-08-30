# site_services — anycast DNS + NTP from site Pis (design & plan)

**Status: role implemented, DRAFT, never executed.** `ansible/roles/site_services/`
and `playbooks/site_services.yml` now exist and are validated in CI (lint,
template rendering against the real inventory, shellcheck, promtool rule unit
tests) — but nothing has been run against a host, and anycast is off by
default behind two switches. The open questions at the end are still open;
they change configuration, not the shape of the role. The
[execution gate](../ansible/roles/routeros_baseline/README.md) applies to every
router-touching step, and the staged rollout below extends the same spirit to
the Pi's routing daemon (an OSPF speaker can hurt the network as badly as a
misconfigured router).

## Problem

The network's basic services — recursive DNS, internal names, NTP — all live
at LEB, and LEB is dark. Verified from rpi.sco on 2026-08-30: **all five
service IPs are down** (44.34.132.1, 44.34.133.1, 44.34.132.3, 44.34.133.3,
44.34.128.181). Consequences already observed: fleet-wide NTP drift (sec1.sco
was 2 months behind), dead internal DNS, and routers that can't resolve
anything (`/ip dns` on 35 of 37 archived configs points solely at 44.34.132.1).

The fix direction was sketched in the README's "Distributed network services"
note: serve these from the on-network Pis (rpi.sco now, a Pi at HIL next),
**anycast on the existing service IPs via OSPF**, so no client, DHCP scope, or
router config has to change and the nearest healthy instance wins.

## Current state (research findings, 2026-08-30)

How the legacy service IPs are consumed, from the archived configs
(pre-2026 `router-config-audit` exports) and live checks:

| IP | Role today | Consumers |
|---|---|---|
| 44.34.132.1 | Recursive+internal DNS (dns.leb) | `/ip dns` on ~35 routers; DHCP `dns-server` (1st) on all scopes |
| 44.34.133.1 | Secondary DNS | DHCP `dns-server` (2nd) on most scopes |
| 44.34.128.181 | NTP (ntp.leb, has public DNS record) | ROS NTP client primary, fleet-wide; `routeros_baseline` default |
| 44.34.133.3 | NTP | ROS NTP client secondary; DHCP `ntp-server` (2nd) |
| 44.34.132.3 | NTP | DHCP `ntp-server` (1st) on sector DHCP scopes |

Other facts that shape the design:

- **No RouterOS device owns any of these IPs** and none carries a static
  route or connected subnet for 44.34.132.0/24 / 44.34.133.0/24 — the LEB
  server hosts announce themselves (or sit behind something outside the backup
  set). We cannot inspect the legacy hosts until LEB returns.
- **Site LANs already run broadcast OSPF, area 0 (backbone), MD5 auth.**
  Confirmed on r1.sco: OSPF on the main `bridge` (44.34.128.32/28) — the same
  segment rpi.sco is plugged into. A Pi can form an adjacency with zero
  router-side changes.
- Site routers use the `AMPR-default` in/out filters (accept 44/8 + default),
  and redistribute as **type-1 externals** — type-1 metrics accumulate
  internal cost, which is exactly what makes "nearest instance wins" work.
- er1.atl drops *forwarded* udp/tcp 53 to 44.34.132.1 (open-resolver
  protection at the edge). Keep an equivalent posture.
- rpi.sco has headroom (4 cores, ~2.4 GB free) but its own resolv.conf
  currently points at Tailscale MagicDNS (100.100.100.100) — a tailnet
  dependency this role should remove (see
  [no-tailnet rule](../README.md)): once unbound is local, the Pi resolves
  via 127.0.0.1.
- LEB being dark means we can claim these IPs **without colliding with a live
  service** — but LEB's return must be planned for (below).

## Design

### Goals / non-goals

Goals: recursive DNS, authoritative internal DNS, and NTP that survive the
loss of any single site; zero client-side changes; health-coupled route
withdrawal; config-as-code in this repo with the inventory as the data source.

Non-goals (for now): serving DNS/NTP to the wider 44net/internet; DHCP
service; replacing Cloudflare as public-zone host; the wg-mgmt/bastion
question (revisit after this lands, per README).

### Where services run

Native Debian packages under systemd — **not** Docker. These are the services
everything else depends on (including Docker pulls and the monitoring stack's
alert delivery); they must not share fate with the container runtime, and frr
and chrony want raw sockets/adjtime on the host anyway.

- **unbound** — recursive resolver, listening on the anycast DNS IPs +
  127.0.0.1 + the host's unicast IP (for pre-anycast testing). ACL: allow
  44.0.0.0/8 + RFC1918 (site NAT scopes hand these resolvers to 192.168/10.x
  clients today), deny the rest. qname-minimisation on; DNSSEC validation on
  for the public tree, local zones marked insecure.
- **internal zones: rendered from git, not clustered.** The "clustered auth
  DNS" idea becomes: zone data lives in the repo (device records generated
  from `ansible/inventory/hosts.yml` — realizing the README's "intended feed
  for future DNS management" — plus a small hand-maintained extras file for
  non-device records), rendered identically onto every service host at deploy
  time as unbound `local-zone`/`local-data` (internal `memhamwan.net` names +
  reverse PTR zones for 44.34.128.0/21). Shared-nothing anycast: no AXFR, no
  primaries, no runtime cluster state — the "cluster" is git. If we later
  want real zone transfers (e.g. hidden primary feeding Cloudflare, or
  serving secondaries elsewhere), promote the same rendered data into
  NSD/Knot behind unbound stub-zones; that's an additive change, not a
  redesign.
- **chrony** — replaces systemd-timesyncd. Binds/permits the anycast NTP IPs,
  `allow 44.0.0.0/8` + RFC1918. Upstreams: the numeric Cloudflare anycast
  addresses already used by `routeros_baseline` (162.159.200.1/.123) + pool
  hostnames (fine here — unbound is local). Service hosts peer with each
  other. `local stratum 10 orphan` so an islanded site keeps serving
  coherent (if free-running) time — an islanded site is precisely when
  fleet-coherent time matters for log correlation.
- **frr (ospfd)** — joins the site-LAN broadcast OSPF exactly like a router:
  area 0, MD5 auth (key from sops; note it's the legacy shared key —
  rotation is the separate `ospf_auth` work, and the Pi should be included
  when that rotates). Each anycast /32 lives on a dummy interface; frr
  redistributes **connected**, guarded by a route-map + prefix-list that
  matches *exactly* the service /32s, as type-1 external. ospfd never runs on
  the dummies and stays passive everywhere except the LAN interface.

### Health-coupled withdrawal

A systemd timer (~10 s cadence) runs per-service checks and adds/removes the
service address from the dummy interface; frr withdraws the connected route
automatically when the address disappears. No frr reconfiguration at runtime.

- DNS check: `dig @<anycast-ip> <probe-name-in-internal-zone>` — probes the
  *local* auth data, so the check answers even when upstream internet is out.
  Deliberate: internet-out is not a reason to withdraw — internal names still
  resolve, and withdrawing everywhere would leave zero resolvers. Only a
  dead or broken unbound withdraws.
- NTP check: `chronyc tracking` sanity — daemon up and either synchronized or
  legitimately in orphan/local mode. Orphan mode does **not** withdraw (that's
  its purpose).
- Checks and address state are exported to node-exporter's textfile collector
  so Prometheus sees announce/withdraw transitions per host.

### Routing trust (the honest tradeoff)

Joining area 0 with the shared MD5 key means a compromised Pi could inject
arbitrary LSAs — prefix-lists on the Pi are self-discipline, not containment.
Real containment options, in increasing order of effort:

1. **Accept + monitor (proposed for phase 1).** The Pi already holds fleet
   SSH keys and the OSPF key exists in every router; the marginal exposure is
   small. Alert on unexpected external LSAs (mktxp/route metrics).
2. **Fleet-wide external-route allowlist** (companion to the planned
   `ospf_auth` role): RouterOS `in-filter` accepting externals only for the
   five service /32s + er1's default. Touches every router → gated, but it
   also contains *every* future OSPF-attached host, not just Pis.
3. **No OSPF on the Pi at all** (conservative alternative): the site router
   carries a static /32 per service via the Pi, `netwatch` (http-get against
   a Pi `/healthz` endpoint) enables/disables it, OSPF redistributes static.
   Containment by construction; costs slower failover, per-router config, and
   health logic split across two boxes. Documented as the fallback if review
   rejects Pi-side OSPF.

Recommendation: 1 now, 2 as the follow-up hardening milestone, 3 only if the
OSPF-speaker idea is rejected outright.

### IP / anycast plan

Announce **all five legacy IPs** from every service host: DNS on 44.34.132.1
+ 44.34.133.1, NTP on 44.34.128.181 + 44.34.132.3 + 44.34.133.3. Rationale:
DHCP scopes hand out the pairs; "secondary" IPs answering from the same host
is strictly better than a dead secondary. All five live as /32s on a single
dummy interface (`anycast0`), each added and removed independently — the DNS
check gates the two DNS addresses, the NTP check the three NTP ones, so DNS
can be withdrawn while NTP keeps serving.

**LEB's return:** the legacy hosts will presumably re-announce these IPs when
LEB comes back — instant unplanned anycast. NTP tolerates that; DNS with
stale legacy zone data does not (split-brain answers). Before LEB returns (or
immediately on its return): disable the legacy announcements/hosts, and
salvage their zone data first to confirm nothing internal was missed (the 11
internal-only device names were already reconstructed into
infrastructure/dns.tf, but the legacy zones may hold more than device
records). This is a standing action item, not a blocker for deployment.

## Role sketch

Role `ansible/roles/site_services/` + playbook `playbooks/site_services.yml`,
shaped like `backup_host` (native config in `files/`/`templates/`, secrets
from sops, handlers for reloads). See the
[role README](../ansible/roles/site_services/README.md) for the runbook and
reviewer notes.

```
ansible/roles/site_services/
  defaults/main.yml        # anycast_services, ACLs, upstreams, probe name
  tasks/main.yml           # packages, NM detection, per-service includes
  tasks/{unbound,chrony,anycast,healthcheck}.yml
  templates/
    unbound-netops.conf.j2       # resolver: ACLs, DNSSEC, interface-automatic
    unbound-local-zone.conf.j2   # zone data from inventory + dns_extra_records
    chrony.conf.j2  frr.conf.j2
    netops-anycast-link.service.j2   # the anycast0 dummy
    anycast-health.sh.j2             # health → announce/withdraw → metrics
  files/netops-anycast-health.{service,timer}
  README.md                # DRAFT marker, runbook, reviewer notes
```

**Two switches, not one.** `anycast_enabled` defaults to false: unbound and
chrony serve on the host's own address, the health timer runs and exports
every metric, but frr is not installed and no address is ever touched. Turning
it on additionally requires `-e anycast_confirm=true`, enforced by the
playbook — announcing addresses the whole fleet points at can never be a side
effect of a routine redeploy. CI asserts both variants of the health script
render correctly, so the M1 guarantee is tested rather than assumed.

Inventory changes:

- new group `service_hosts`: rpi.sco now (with `site_lan_interface: eth0`);
  the HIL Pi once onboarded (static 44net IP, port-222 sshd, inventory entry —
  it needs a proper hostname; it's currently only a tailnet name, which the
  no-tailnet rule won't accept).
- `dns_extra_records.yml` next to the inventory for non-device internal
  records (the inventory `ip` fields already cover device A/PTR records).

**Secrets:** `ospf_md5_key` is in `secrets/secrets.sops.yaml` (confirmed by
Ryan, and verified on 2026-08-30 against r1.sco — the router the Pi peers
with — which has exactly one distinct auth-key, `auth=md5`, `auth-id=1`). It
is the old shared fleet key, so it moves together with the planned credential
rotation and the `ospf_auth` role. The role still asserts the key is present
rather than joining OSPF unauthenticated, which would reproduce the "type
mismatch" adjacency flood already diagnosed at HIL. No new device credentials.

The same read confirmed the rest of the adjacency parameters, which are now
pinned in the role rather than left to frr's defaults (mismatched hello/dead
timers prevent adjacency outright): area `backbone-v2` = area-id `0.0.0.0`,
type broadcast, hello 10s, dead 40s, cost 10. The Pi keeps `priority 0` against
the routers' `1`, so it can never win a DR election. Worth noting: r1.sco's
`bridge` template — the Pi's own segment — *does* carry auth, unlike the HIL
`vrrp1` template whose missing auth caused the flood.

Monitoring changes land in the existing `backup_host` role (Prometheus
config, blackbox modules, alert rules, dashboards) plus textfile collectors
in this role — full strategy in the next section.

## Monitoring & alerting strategy

Everything rides the existing stack (Prometheus + blackbox + Alertmanager →
Discord, Loki/Alloy for logs, Grafana) — no new monitoring systems. What *is*
new is that anycast breaks the usual "probe the IP" model: a probe to
44.34.132.1 from the monitoring host tells you only what the *nearest*
instance is doing, and the monitoring host is itself one of the service
hosts. The strategy is layered to keep those vantage points honest.

### Layer 1 — per-instance truth (unicast)

The ground truth is each instance probed by its unicast address,
independently of routing:

- blackbox `dns_query` modules against every service host's unicast IP:
  one module resolving a known internal name with `validate_answer_rrs`
  (correctness, answerable even when internet is out) and one resolving an
  external name (recursion health, alerted at lower severity — internet-out
  is not an instance failure).
- NTP has no blackbox prober. Each service host's health timer already runs
  `chronyc tracking`; it exports the results (sync state, offset, stratum,
  orphan-mode flag) via node-exporter's textfile collector. On rpi.sco the
  existing containerized node-exporter picks up the textfile directory; the
  HIL Pi gets a native node-exporter as part of onboarding.
- unbound stats (`unbound-control stats_noreset` → textfile: query rate,
  cache hit ratio, SERVFAIL rate) — trend data for dashboards, and a rising
  SERVFAIL rate is the early sign of upstream trouble.

### Layer 2 — announcement state (the anycast-specific part)

The health script is the single authority on what *should* be announced, and
it exports exactly that: `anycast_announced{service,ip}` 0/1, per-check
pass/fail, and a last-transition timestamp, all via textfile. This gives
Prometheus the withdraw/announce history without scraping frr.

What is implemented instead of a router-table view: `AnycastAddressUnreachable`
compares the two vantage points directly — the anycast address failing its
probe *while* at least one instance is healthy on its own address is, by
elimination, a routing or announcement problem. That needs no router access
and no new collector.

**Deferred:** the per-site route census (*does each site have a route to each
service /32, and from how many origins?*) via mktxp's route metrics or a
gated `/routing route print`. It is the only thing that distinguishes "SCO
can't reach the service" from "the announcement is missing network-wide", and
it is the natural companion to the M4 fleet-side route filters — so it lands
with them, not before.

### Layer 3 — cross-site client's-eye view (from M3)

Each service host also probes the *anycast* IPs and records which instance
answered, using unbound's `hostname.bind` CH TXT identity (set per-host by
the role). Exported as `anycast_origin_info{from, service, origin}`. With one
site this is a self-check; with two (M3) it becomes reciprocal monitoring —
HIL sees SCO's failures and vice versa — and the same mechanism does NTP by
querying the other host's unicast chrony and comparing offsets.

### Alert rules (Alertmanager → Discord, existing severity conventions)

As implemented in `rules/site-services.yml` (severity uses the existing
`page` / `warn` / `none` convention):

| Alert | Condition | Severity |
|---|---|---|
| AnycastServiceDownDNS | no instance passing the internal-zone probe | page |
| AnycastInstanceDownDNS | one instance unhealthy while another serves | warn (redundancy lost, clients fine) |
| AnycastAddressUnreachable | anycast address not answering while an instance is healthy | page (routing, not service) |
| AnycastUnexpectedOrigin | `hostname.bind` answer not an enrolled service host | page — the **LEB-came-back split-brain detector** |
| DnsRecursionFailing | internal probe OK, external probe failing | warn (upstream path, never withdraws) |
| ZoneDataSkew | `netops_zone_render_info` hash differs across hosts >30m | warn (a host missed a deploy) |
| ChronyUnsynchronised | chrony neither disciplined nor in orphan mode | warn |
| NtpServiceDownEverywhere | no healthy NTP instance anywhere | page |
| ChronyOrphanMode | serving from the local reference | none (islanded — working as designed) |
| ChronyOffsetHigh | \|offset\| > 500 ms | warn |
| AnycastStateMismatch | announced state ≠ health, while anycast is enabled | warn (script/frr inconsistency) |
| AnycastFlapping | >4 announce/withdraw transitions in 30m | warn |
| PeerServiceHostUnhealthy | one service host cannot get a healthy answer from another | warn |
| SiteServicesHealthCheckStale | health script hasn't run in >5m | page — **announcements are frozen; a dead service will not be withdrawn** |
| SiteServicesMetricsMissing | textfile metrics absent >1h | page (health/announcement alerting is blind) |

Two of these were written in the obvious way, parsed cleanly, and **could
never have fired**: `count(x == 1) == 0` yields an empty vector when nothing
matches, so "no healthy resolver/NTP anywhere" — the two most important
alerts here — were silently dead until the unit tests caught them. They now
use `sum()` with a `count() > 0` guard, and the test file pins that behaviour.

Logs need no new pipeline: unbound/chrony/frr log to journald, which Alloy
already ships to Loki. FRR adjacency changes get a dashboard query, not an
alert (Layer 2 metrics already alert on the consequence).

### Dashboards

A "Site Services" row on the Network Overview dashboard (file-managed JSON,
as ever): per-instance health + announced state timeline, origin-by-vantage
table, unbound query/SERVFAIL rates, chrony offsets per host, and the
route-presence-per-site panel. The withdraw/announce timeline doubles as the
incident-review artifact for flaps.

### The blind spot, stated plainly

The monitoring stack lives on rpi.sco, which is now also a service host: a
total SCO/rpi.sco failure takes out the DNS/NTP instance *and* the thing
that would have alerted about it (including Discord egress). M3's reciprocal
probes mean the HIL Pi at least *measures* such an outage, but nothing off-
network receives it. The always-firing Watchdog alert remains the designed
hook for a dead-man's switch; the decision on an off-network receiver was
deliberately deferred (2026-08-29) and this design doesn't reopen it — it
just notes that each service anycast to rpi.sco raises the cost of that
silent-failure mode.

### What is already wired up

Implemented alongside the role (all validated in CI, none of it running yet):

- blackbox `dns_internal` / `dns_recursion` modules; two Prometheus jobs over
  `targets/dns-services.yml`, which is rendered from the inventory with
  `kind="unicast"` per host and `kind="anycast"` for the shared addresses.
- `rules/site-services.yml` — the alert table below, 15 rules.
- a "Site Services" Grafana dashboard (file-managed like the others):
  healthy-instance counts, the announce/withdraw timeline, unicast-vs-anycast
  probe comparison, clock offsets, resolver query/SERVFAIL rates, and a
  distinct-zone-versions panel.
- textfile metrics from the health script:
  `netops_service_healthy`, `netops_anycast_announced`, `netops_anycast_since`,
  `netops_anycast_enabled`, `netops_anycast_origin_known`,
  `netops_peer_dns_healthy`, `netops_chrony_*`, `netops_unbound_*`,
  `netops_zone_render_info`, `netops_site_services_last_run_timestamp_seconds`.
- `tests/prometheus/site-services_test.yml` — promtool unit tests asserting
  the rules actually fire (and, as importantly, do *not* fire: an internet
  outage raises only the recursion warning, and orphan-mode NTP raises only
  the informational alert). Writing these caught two rules that would have
  parsed fine and never fired — see the note on `AnycastServiceDownDNS`.

### Milestone mapping

- **M1:** Layer 1 complete (unicast probes, chrony/unbound textfile metrics,
  ZoneDataSkew, ChronyUnsynced, DnsRecursionFailing). Gate to M2: all green
  for a week.
- **M2:** Layer 2 + anycast probes from SCO (AnycastServiceDown,
  RouteMissing, UnexpectedOrigin, Flapping, StateMismatch). The
  UnexpectedOrigin detector **must** be live before LEB returns.
- **M3:** Layer 3 reciprocal probes, cross-host NTP offset comparison,
  AnycastInstanceDown becomes meaningful.
- **M4:** revisit the blind spot alongside the other hardening items.

## Rollout milestones (each gated on Ryan's PR review)

1. **M1 — role PR, services on unicast only.** unbound+chrony+zone render+
   healthcheck deployed to rpi.sco; **frr not installed**; nothing announced.
   Validation: `dig @44.34.128.45`, `ntpdate -q 44.34.128.45`, monitoring
   probes green. Zero routing risk. (Routers could even be pointed at the
   unicast IP as an interim fix if LEB stays dark long — one-line `/ip dns`
   change, Ryan's call.)
2. **M2 — anycast at SCO.** frr + dummy interfaces + withdraw timer on
   rpi.sco alone. First anycast validation: resolve/sync against 44.34.132.1
   / .128.181 from another site, watch the type-1 externals appear, kill
   unbound and watch the route withdraw. Single-site anycast already ends the
   "no DNS/NTP anywhere" state.
3. **M3 — second site.** Onboard the HIL Pi (inventory, sshd, static IP),
   apply the role, chrony peering, verify per-site locality (SCO clients hit
   rpi.sco, HIL clients hit the HIL Pi) and failover by withdrawing one site.
4. **M4 — hardening + cleanup.** Fleet external-route allowlist (with
   `ospf_auth`); decommission legacy LEB service hosts on LEB's return
   (salvage zone data first); update `routeros_baseline` NTP/DNS defaults to
   note the IPs are now anycast; revisit er1's port-53 edge drops.

## Open questions for review

1. OSPF speaker on the Pi (option 1→2 above) vs router-side netwatch/static
   (option 3) — the core trust decision.
2. Announce all five legacy IPs, or start with just 44.34.132.1 + 44.34.128.181
   and let the secondaries die?
3. Is unbound local-data enough for the internal zone, or is there a known
   consumer of zone transfers / a reason to want NSD from day one?
4. Interim unicast DNS for routers during M1 (LEB dark today) — worth a
   gated one-liner to the fleet, or wait for anycast?
5. The HIL Pi is currently the meshtastic host — confirm it can take this
   second duty, and pick its hostname/IP.
