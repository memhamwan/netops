# Authoritative DNS on the network (design & plan)

**Status: design only — no code yet.** This proposes moving authoritative DNS
for `memhamwan.net` off Cloudflare and onto the fleet, served by **NSD** co-located
with the existing recursive/NTP service on the site Pis. Builds on
[site-services-design.md](site-services-design.md) (the anycast DNS/NTP work).
The [execution gate](../ansible/roles/routeros_baseline/README.md) applies to the
router-touching parts (the edge `:53` change, the registrar cutover).

## Goal & rationale

Own DNS end-to-end: the inventory is already the source of truth for the fleet,
and the network now runs its own DNS. Cloudflare stays only as a comparison
reference during migration, then goes away.

The reliability objection (a self-hosted authority on the 44net edge is less
globally available than Cloudflare's anycast) was considered and **accepted**,
because:
- Nearly every record points at an **on-net-only device**; when the mesh is down
  those devices are unreachable regardless, so DNS availability that exceeds
  network availability buys nothing.
- Recovery is done **by IP** (WireGuard endpoints carry `Endpoint = <ip>`; we ssh
  by IP), so DNS being down never locks us out of getting in to fix things.
- DNS reliability grows *with* the network — more anycast instances as we add
  sites (already going from one to two).
- **No email** on `memhamwan.net`, TLS certs are **HTTP-01** (repo-controlled,
  no DNS dependency), and **CAA** lives in this zone — so there is no
  external-facing record that must resolve while the fleet is down. That removes
  the only category that would have argued for an off-net secondary.

(If that ever changes, the fallback that preserves ownership is a hidden-primary
with a **free** off-net secondary — e.g. Hurricane Electric `dns.he.net` slaving
via AXFR. Not needed now.)

## Current state

- **Authoritative today:** Cloudflare (`tate`/`joselyn.ns.cloudflare.com`),
  managed by hand in `infrastructure/dns.tf` (a `host_names` map → A records).
  **117 A records**, no other record types in Terraform.
- **On the fleet:** `unbound` (recursive + internal zone as `local-data`) on the
  anycast DNS IPs `44.34.132.1`/`44.34.133.1`; `chrony` (NTP). Rendered from the
  inventory ("git is the cluster" — no zone transfer).
- **The gap (from the Cloudflare-vs-internal diff):** the internal zone covers
  ~30 core routers/service names and **agrees perfectly where it overlaps (zero
  value conflicts)**, but Cloudflare has **86 records the fleet doesn't** — 9
  fleet hosts that lacked an `ip:` (fixed in the parity-groundwork PR), plus ~77
  end-user / camera / iLO / SSTP+WireGuard-tunnel / APRS-D-STAR / `ingress.k8s`
  records, plus `grafana`/`prometheus`/`alertmanager` (public TLS vhosts).
  Moving authority as-is would NXDOMAIN most of the zone — **record parity is the
  prerequisite.**

## Architecture

### One box, three DNS/NTP roles, separated by IP

Each service host (rpi.sco, meshtastic.hil, future sites) runs:
- **unbound** — recursive resolver + internal split-horizon, on `44.34.132.1` /
  `44.34.133.1` (+ `127.0.0.1`, host IP). On-net clients.
- **chrony** — NTP, on the NTP anycast IPs.
- **NSD** — authoritative for `memhamwan.net` + the reverse zones, on a **new
  second anycast pair** (`ns1`/`ns2`).

unbound and NSD both want `:53`, so they get **different IPs** (not different
physical interfaces). The `ns1`/`ns2` `/32`s live on the same `anycast0` dummy,
added to `anycast_services` (a new `authdns` service type for the health gate)
and the frr `ANYCAST-SERVICES` prefix-list — i.e. they ride the exact anycast
machinery the recursive/NTP IPs already use.

### Zone generation — "git is the cluster", no AXFR

NSD loads an **inventory-rendered zonefile**, deployed identically to every host,
exactly like unbound's `local-data` today — so **no primary/secondary AXFR**
between fleet NSDs. **DNSSEC**: sign **once** in the render pipeline (keys in
sops) and ship the signed zone to every host, so all NSDs serve identical signed
data. DS record goes to the registrar.

### The recursion → authoritative link (split-brain safeguard)

unbound gets a **`stub-zone`** for `memhamwan.net` (and the reverse
`in-addr.arpa` zones) pointing at the **local** NSD:
```
stub-zone:
    name: "memhamwan.net"
    stub-addr: 127.0.0.1@5353    # NSD also listens on loopback:5353
```
So on-net recursion resolves `memhamwan.net` **directly from the fleet's own
authoritative NSD — never out to the internet root**. This means:
- fast internal resolution, and it works even if the public delegation/edge is
  down;
- **split-brain-proof**: unbound always gets the fleet's authoritative data,
  never a stale legacy-LEB copy or a broken public delegation;
- unbound **drops its `local-data` zone copy** — the single source of truth
  becomes NSD's zonefile (both were generated from inventory; now rendered once).

### Split-horizon

Keep **one zone**. The internal-only anycast names (`dns`/`ntp` → `44.34.132.x`)
go in the same NSD zone; they're harmless publicly (off-net clients can't use a
44net service IP for recursion anyway). Only split them out as unbound-local if
strict split-horizon is ever wanted.

## Record parity — closing the 86

Everything must have a home in the inventory-driven pipeline before cutover:
- **Fleet devices** → inventory `ip:` (the 9 no-`ip` hosts are done in the
  parity-groundwork PR).
- **Non-fleet records** (end-user hosts, cameras, iLO, SSTP/WireGuard tunnel
  endpoints, APRS/D-STAR/AllStar, `ingress.k8s`, `esxi`, etc.) → an expanded
  `dns_extra_records`-style file (name/type/value), which already feeds the zone.
- **Public service vhosts** (`grafana`/`prometheus`/`alertmanager`) → now belong
  *in* the authoritative zone (once we own it, the "don't shadow the public
  record" reason for keeping them unbound-transparent goes away).
- **CAA** → an extra record (HTTP-01-friendly issuance policy).
- **Reverse PTRs** → already generated from inventory IPs.

**Before cutover, audit the LIVE Cloudflare zone** (Terraform is not a complete
inventory): confirm there are no dashboard-only records (MX/TXT/CAA/SRV) and
determine the actual DNSSEC state + registrar DS. No email is expected; verify.

## Public reachability & the registrar

- NS names in-zone (`ns1.memhamwan.net`, `ns2.memhamwan.net`) → the `ns1`/`ns2`
  anycast `/32`s. **Glue records** (A records for those NS names) go at the
  **registrar** to break the in-zone-nameserver chicken-and-egg.
- The fleet NS must be reachable from the global internet on `:53`: 44net public
  routing + **er1 forwards `:53` to the ns `/32`s** (gated router change; note
  `er1` is a cloud MikroTik and cannot itself run a nameserver).
- Reliability profile, accepted: the domain's public authority is reachable only
  while the edge + at least one site is up. Recovery is by IP regardless.

## Cutover (staged, reversible)

1. **Parity** — every Cloudflare record represented in inventory / extra-records;
   `dig` the rendered NSD zone and diff against the live Cloudflare zone until
   clean.
2. **Serve in parallel** — NSD live on the fleet (not yet delegated); validate
   authoritative answers + DNSSEC signing locally and from another site.
3. **unbound stub-zone** cutover — on-net resolution now via NSD; drop
   `local-data`.
4. **Edge** — open `:53` to the ns `/32`s (gated).
5. **Delegate** — registrar NS → `ns1`/`ns2.memhamwan.net` + glue; add the DS
   record for DNSSEC. Lower TTLs beforehand.
6. **Decommission Cloudflare** once resolution + DNSSEC validate from off-net.
   **Rollback** at any point: point the registrar NS back at Cloudflare.

## Milestones

- **D1** — record parity in inventory/extra-records + the CF-zone audit (no code
  risk; it's data).
- **D2** — `nsd` role: inventory-rendered signed zone, ns `/32`s on `anycast0`,
  unbound `stub-zone`, serving in parallel (not delegated). Validate.
- **D3** — edge `:53` (gated) + registrar NS/glue/DS cutover; decommission
  Cloudflare.

## Open questions

1. Where exactly the ~77 non-fleet records live — one big `dns_extra_records`
   file, or split by kind (end-user vs infra vs service)?
2. `ns1`/`ns2` as anycast `/32`s (matches the pattern, failover) vs per-host
   unicast NS IPs (simpler, no anycast for auth) — leaning anycast.
3. DNSSEC algorithm/rollover policy and where the keys live in sops.
4. Confirm the live Cloudflare zone has no MX/TXT/SRV and its current DNSSEC/DS
   state before scheduling the cutover.
</content>
