# netops

Operational tooling for the MemHamWAN network. Today this repo runs the
**router configuration backup system**; over time it is intended to grow into
the config-as-code home for the network (tooling decision deferred — see
[Future direction](#future-direction)).

**No secrets live in this repo.** SSH private keys and anything sensitive stay
on the backup host or in [netops-secrets](https://github.com/memhamwan/netops-secrets)
(sops/age).

## How backups work

Two independent tracks, both landing in
[routeros-config-audit](https://github.com/memhamwan/routeros-config-audit):

| Track | What | How | Where |
|---|---|---|---|
| Sanitized | `/export hide-sensitive`, hourly | [Oxidized](https://github.com/ytti/oxidized) daemon in Docker | `main` branch, plaintext, full-text searchable |
| Full | `/export show-sensitive`, nightly | `full-backup/full-export-backup.sh` (systemd timer) | `encrypted` branch, sops/age-encrypted |

The daemon and timer run **on-network** on the backup host
(rpi.sco.memhamwan.net, a Raspberry Pi 4 on the SCO site LAN) and
push **off-network** to GitHub. Every clone of the audit repo is a distributed
copy of the backups.

Device access uses two dedicated least-privilege accounts on every router
(created by the bootstrap/onboarding plays — see Fleet inventory & Ansible):

- `oxidized` — group `netops-backup-ro`, policy `ssh,read`, key-auth only.
  Cannot read secrets even if the tooling were misconfigured.
- `oxidized-full` — group `netops-backup-full`, policy `ssh,read,sensitive`,
  key-auth only. Used only by the nightly encrypted track.

The age private key needed to decrypt the full backups is **not** on the
backup host — encryption uses public recipients only (same recipient set as
netops-secrets). To decrypt:
`sops decrypt --input-type binary --output-type binary encrypted/<host>.rsc.sops`

The `encrypted/*.sha256` files are hashes of the timestamp-stripped plaintext,
used to skip re-encrypting unchanged configs (sops output is non-deterministic).
Accepted tradeoff: a hash permits offline confirmation of a fully-guessed
config file.

`main` and `encrypted` on routeros-config-audit are **automation-owned** — do
not commit to them by hand (pushes from the host would then fail non-fast-forward).
The 2021-era `master` branch is kept as a historical archive.

## Monitoring (Phase 2)

`monitoring/` runs Prometheus + blackbox (ICMP to every device, HTTP to our
services) + Alertmanager (→ Discord via a webhook URL kept only on the host
at `/var/lib/netops/secrets/discord-webhook-url`) + Grafana + node-exporter,
all on the same backup host. Access is via the public Caddy vhosts below;
on-host debugging via loopback (ssh -L for oxidized-web :8888).

Logs: RouterOS remote syslog + the host journal flow into Loki via Alloy
(30d retention); metrics: mktxp (RouterOS API) for the whole fleet. The
always-firing `Watchdog` alert remains the hook for an off-network dead-man's
switch if we ever want one.

**Public access** (once the `grafana`/`prometheus`/`alertmanager`
`.memhamwan.net` records in infrastructure/dns.tf resolve): Caddy on the
host's 44net address terminates TLS (automatic Let's Encrypt) and proxies
- https://grafana.memhamwan.net — anonymous read-only; `admin` login for edits
- https://prometheus.memhamwan.net, https://alertmanager.memhamwan.net —
  basic auth (user `netops`, password generated on the host at
  `/var/lib/netops/secrets/netops-basicauth-password`) because neither has
  auth of its own and Alertmanager mutations (silences) must not be public.

**Dashboards** are provisioned from
`ansible/roles/backup_host/files/monitoring/grafana/dashboards/*.json`
(folder "MemHamWAN": Network Overview, Monitoring Host). They are file-managed:
edit the JSON here and redeploy — UI edits are not persisted. To author in the
UI first, copy the dashboard, edit, then export JSON back into the repo.

## Secrets

Runtime credentials (Grafana admin, the `netops` basic-auth for
prometheus/alertmanager, the mktxp device password, the Discord webhook) live
encrypted in `secrets/secrets.sops.yaml`, readable by holders of either age
key listed in `.sops.yaml` (the shared netops key or turnrye's local key).
The backup host keeps working copies in `/var/lib/netops/secrets/`.

To read them locally:

```sh
brew install sops age direnv   # once
direnv allow                   # once per clone — .envrc sets SOPS_AGE_KEY_FILE
                               # (sops on macOS otherwise looks in
                               #  "~/Library/Application Support/sops/age")

sops decrypt secrets/secrets.sops.yaml                  # whole file
sops decrypt --extract '["grafana_admin_password"]' secrets/secrets.sops.yaml
sops secrets/secrets.sops.yaml                          # edit in $EDITOR
```

To add a recipient: add their `age1...` public key to `.sops.yaml`, then
`sops updatekeys secrets/secrets.sops.yaml`.

## Fleet inventory & Ansible

`ansible/inventory/hosts.yml` is the **single source of truth** for the fleet
(devices grouped by site, with IPs as IPAM data — the intended feed for future
DNS management). The Oxidized fleet list, blackbox targets, and mktxp config
are all templated from it at deploy time.

Deploy/refresh the backup host (rpi.sco):

```sh
cd ansible && ansible-playbook playbooks/backup_host.yml
```

(Requires sops access — see Secrets. Connects to rpi.sco.memhamwan.net as your user.)

To add a device: add it to the inventory, run the bootstrap/baseline plays
(DRAFT — pending review, see ansible/roles/routeros_baseline/README.md),
then deploy the backup host to pick up the new fleet list.

## Layout

```
ansible/             inventory (source of truth), playbooks, roles
  roles/backup_host/       deploys the whole rpi.sco stack (configs live here)
  roles/routeros_baseline/ DRAFT device baseline — never executed, see its README
secrets/             sops/age-encrypted runtime secrets
```

## Backup host bootstrap (one-time)

Done 2026-08-28 on rpi.sco; recorded here to rebuild from scratch:

```sh
sudo install -d /opt/netops /var/lib/netops/ssh /var/lib/netops/oxidized
sudo git clone https://github.com/memhamwan/netops /opt/netops

# keys (private halves never leave the host)
sudo ssh-keygen -t ed25519 -N '' -C oxidized@rpi-sco       -f /var/lib/netops/ssh/id_ed25519
sudo ssh-keygen -t ed25519 -N '' -C oxidized-full@rpi-sco  -f /var/lib/netops/ssh/oxidized_full_ed25519
sudo ssh-keygen -t ed25519 -N '' -C netops-backup@rpi-sco  -f /var/lib/netops/ssh/gh_deploy_ed25519
# → add gh_deploy_ed25519.pub as a WRITE deploy key on routeros-config-audit
# → create the device backup accounts (bootstrap/onboarding plays)

# sops (arm64 binary from upstream releases)
# https://github.com/getsops/sops/releases

# seed the oxidized output repo and the encrypted-branch clone
sudo git init --bare /var/lib/netops/oxidized/devices.git
sudo git clone -b encrypted git@github.com:memhamwan/routeros-config-audit.git /var/lib/netops/encrypted-repo

# container runs as uid 30000 (user "oxidized")
sudo chown -R 30000:30000 /var/lib/netops/oxidized /var/lib/netops/ssh

# then from a workstation: cd ansible && ansible-playbook playbooks/backup_host.yml
```

oxidized-web (browse/search/diff per device) listens on loopback only:
`ssh -L 8888:127.0.0.1:8888 rpi.sco.memhamwan.net`.

## Monitoring / alerting (next phase)

Oxidized hooks fire on every config change (`post_store`); wiring one to a
notification channel is the intended Phase 2. The GitHub commit history of
routeros-config-audit is already a change audit trail.

## Future direction

This repo is the planned home for config-as-code (device provisioning, fleet
changes). Tooling is deliberately undecided; current non-binding lean is
Ansible for device config (existing roles in `ioc-terraform` on GitLab) and
OpenTofu for cloud-side resources (DNS etc.), to be revisited once backup
history shows real drift/churn patterns. Related planned work: restrict router
SSH (port 222) reachability now that polling originates on-network, and rotate
the legacy shared credentials.
