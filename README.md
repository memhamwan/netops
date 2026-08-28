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

The daemon and timer run **on-network** on the backup host (rpi.sco, a
Raspberry Pi 4 on the SCO site LAN, reachable via Tailscale as `rpi-sco`) and
push **off-network** to GitHub. Every clone of the audit repo is a distributed
copy of the backups.

Device access uses two dedicated least-privilege accounts on every router
(created by `device-onboarding/add-backup-users.sh`):

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

## Layout

```
oxidized/            docker-compose + Oxidized config + device list (router.db)
full-backup/         nightly encrypted-export script + systemd units
device-onboarding/   create backup service accounts on a (new) router
deploy.sh            sync repo → /var/lib/netops + systemd + docker (run on host)
```

`oxidized/router.db` (`hostname:model`) is the fleet list for **both** tracks.
To add a device: run `add-backup-users.sh` against it, add a line to
`router.db`, run `deploy.sh` on the host.

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
# → run device-onboarding/add-backup-users.sh with the two device pubkeys

# sops (arm64 binary from upstream releases)
# https://github.com/getsops/sops/releases

# seed the oxidized output repo and the encrypted-branch clone
sudo git init --bare /var/lib/netops/oxidized/devices.git
sudo git clone -b encrypted git@github.com:memhamwan/routeros-config-audit.git /var/lib/netops/encrypted-repo

# container runs as uid 30000 (user "oxidized")
sudo chown -R 30000:30000 /var/lib/netops/oxidized /var/lib/netops/ssh

sudo /opt/netops/deploy.sh
```

oxidized-web (browse/search/diff per device) listens on the host's loopback
and Tailscale addresses only: `http://rpi-sco:8888`.

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
