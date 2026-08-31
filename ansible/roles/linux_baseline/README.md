# linux_baseline

Base config every MemHamWAN **Linux** host wants — the counterpart to
`routeros_baseline`. Pulled in automatically as a dependency (`meta/main.yml`)
by `backup_host` and `site_services`, so it always runs first.

## Scope

**P1 (this role today):**
- **ssh** — port 222 alongside 22, key-only hardening (`PasswordAuthentication no`,
  `AllowGroups sshusers`, root login off). Users + keys are installed *before*
  the lockdown, config is `sshd -t`-validated, and applied via **reload** (not
  restart) so a mistake can't strand a host.
- **users** — operator accounts (`turnrye`, `seichold`, `ae5au`) from the keys
  committed in `routeros_baseline/files/operators/` (single source, not
  duplicated), in `sudo` + `sshusers`, password login locked. Default imaging
  accounts (`pi`, `meshtastic`) have their password login locked if present.
- **node_exporter** — native (apt) `prometheus-node-exporter`, replacing
  per-host docker exporters. Bound to a specific address (not `0.0.0.0`).
- **sysctl** — anycast-safe: **`rp_filter=2` (loose)** — strict RPF silently
  breaks anycast/OSPF asymmetric return paths — plus redirects/source-route off,
  syncookies, and anycast ARP hygiene. The role refuses to run if another
  drop-in asserts strict `rp_filter=1`.
- **sdcard** — auto-gated on `is_sdcard`: journald to RAM (`Storage=volatile`,
  no rsyslog forward), swap-to-SD disabled. The durable log copy lives in Loki.
- **dns/ntp client** — points ordinary hosts at the anycast DNS/NTP. **Yields**
  on hosts that *run* those services (`site_services` sets the toggles false).
- **updates** — security-only unattended-upgrades, no auto-reboot (routing nodes
  reboot in a window).

**P2 (separate PR):** nftables default-deny host firewall (OSPF/anycast-aware)
+ sshguard; Grafana Alloy log shipping to `logs.memhamwan.net` → Loki.

## Notes for the reviewer

- **node-exporter migration on rpi.sco** is the risk in this PR: it moves the
  exporter from the docker monitoring stack to native. The bind stays
  `172.17.0.1:9100` (docker bridge, off the public LAN) so the containerised
  Prometheus keeps scraping `host.docker.internal:9100` unchanged. On first
  apply the native exporter and the still-running docker one briefly contend for
  `:9100`; the `Restart=on-failure` override lets native bind once
  `backup_host` removes the docker service later in the same run. Deploy with
  `--check --diff` first.
- **`:9100` exposure:** on hosts scraped remotely (rpi.hil) the exporter binds
  the LAN IP and is not yet firewalled — that gap closes with the P2 firewall.
- **`rp_filter=2` is load-bearing** for anycast; do not let a CIS/hardening
  drop-in reassert `1` (effective mode is `max(all, iface)`).
</content>
