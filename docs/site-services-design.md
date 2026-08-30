# site_services — anycast DNS + NTP from site Pis (design & plan)

**Status: DESIGN — no role exists yet, nothing has been deployed.** This doc
is the review artifact for the design; the role itself comes as a follow-up PR
once the open questions below are settled. The
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
is strictly better than a dead secondary. One /32 each, five dummy
interfaces, DNS check gates the two DNS IPs, NTP check the three NTP IPs.

**LEB's return:** the legacy hosts will presumably re-announce these IPs when
LEB comes back — instant unplanned anycast. NTP tolerates that; DNS with
stale legacy zone data does not (split-brain answers). Before LEB returns (or
immediately on its return): disable the legacy announcements/hosts, and
salvage their zone data first to confirm nothing internal was missed (the 11
internal-only device names were already reconstructed into
infrastructure/dns.tf, but the legacy zones may hold more than device
records). This is a standing action item, not a blocker for deployment.

## Role sketch

New role `ansible/roles/site_services/` + playbook
`playbooks/site_services.yml`, shaped like `backup_host` (native config files
in `files/`/`templates/`, secrets from sops, handlers for reloads):

```
ansible/roles/site_services/
  defaults/main.yml        # anycast_services list, acls, upstreams, zone name
  tasks/main.yml           # packages, resolv.conf, per-service includes
  tasks/{unbound,chrony,frr,healthcheck}.yml
  templates/
    unbound-local-zone.conf.j2   # rendered from inventory + dns_extra_records
    unbound.conf.j2  chrony.conf.j2  frr.conf.j2
    anycast-health.sh.j2         # the withdraw script
  files/anycast-health.{service,timer}
  README.md                # DRAFT marker + runbook, same convention as routeros_baseline
```

Inventory changes:

- new group `service_hosts`: rpi.sco now; the HIL Pi once onboarded (static
  44net IP, port-222 sshd, inventory entry — it needs a proper hostname; it's
  currently only a tailnet name, which the no-tailnet rule won't accept).
- `group_vars/service_hosts.yml`: `anycast_services` (ip, proto, healthcheck
  group), `site_lan_interface`/`ospf_md5_key` per host vars.
- `dns_extra_records.yml` next to the inventory for non-device internal
  records (the inventory `ip` fields already cover device A/PTR records).

Secrets added to sops: the OSPF MD5 key. (No new device credentials.)

Monitoring additions (backup_host role): blackbox `dns_query` module probing
the anycast DNS IPs *and* each host's unicast IP (anycast up ≠ every instance
up); alert rules for instance-down-while-anycast-up, withdraw-flapping, and
chrony unsynchronized (via the textfile metrics); Grafana panel on the
Network Overview dashboard.

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
