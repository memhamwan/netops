#!/usr/bin/env bash
# Deploy/refresh the netops stack on the backup host (run ON the host, as root).
# Assumes: this repo cloned at /opt/netops, one-time bootstrap done (README).
set -euo pipefail

REPO_DIR=$(cd "$(dirname "$0")" && pwd)

install -d -m 755 /var/lib/netops/oxidized /var/lib/netops/oxidized/model
install -m 644 "$REPO_DIR/oxidized/config" /var/lib/netops/oxidized/config
install -m 644 "$REPO_DIR/oxidized/router.db" /var/lib/netops/oxidized/router.db
install -m 644 "$REPO_DIR/oxidized/model/routeros.rb" /var/lib/netops/oxidized/model/routeros.rb
chown -R "$(stat -c %u /var/lib/netops/oxidized 2>/dev/null || echo 0)" /var/lib/netops/oxidized || true

install -m 755 "$REPO_DIR/full-backup/full-export-backup.sh" /opt/netops/full-backup/full-export-backup.sh 2>/dev/null || true
install -m 644 "$REPO_DIR/full-backup/netops-full-backup.service" /etc/systemd/system/
install -m 644 "$REPO_DIR/full-backup/netops-full-backup.timer" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now netops-full-backup.timer

docker compose -f "$REPO_DIR/oxidized/docker-compose.yml" up -d
echo "deployed. oxidized-web: http://<tailscale-ip>:8888"
