#!/usr/bin/env bash
# Nightly full-config (show-sensitive) backup of the RouterOS fleet,
# sops/age-encrypted and pushed to the "encrypted" branch of
# github.com/memhamwan/routeros-config-audit.
#
# The age private key is NOT on this host: encryption needs only the public
# recipients below, so a compromise of this host cannot decrypt past backups.
# Plaintext never touches disk outside a mode-0700 tmpdir and is removed
# immediately after encryption.
#
# A sha256 of the (timestamp-stripped) plaintext is kept next to each
# ciphertext so unchanged configs are not re-encrypted every night (sops
# output is non-deterministic and would produce meaningless daily commits).
# Tradeoff: the hash allows offline confirmation of a fully-guessed config
# file; accepted, documented in README.
set -uo pipefail

ROUTER_DB=${ROUTER_DB:-/var/lib/netops/oxidized/router.db}
SSH_KEY=${SSH_KEY:-/var/lib/netops/ssh/oxidized_full_ed25519}
DEPLOY_KEY=${DEPLOY_KEY:-/var/lib/netops/ssh/gh_deploy_ed25519}
REPO=${REPO:-/var/lib/netops/encrypted-repo}
# Same recipient set as memhamwan/netops-secrets; add recipients here as needed.
AGE_RECIPIENTS=${AGE_RECIPIENTS:-age1xfngu8m7w7epw797sdnjc746ysuksxevnucr9t4alq82hgzxdagq4u2y4p}
SSH_USER=oxidized-full
SSH_PORT=222

cd "$REPO" || exit 1
export GIT_SSH_COMMAND="ssh -i $DEPLOY_KEY -o StrictHostKeyChecking=accept-new"
git pull --ff-only origin encrypted 2>/dev/null || true
mkdir -p encrypted

tmpdir=$(mktemp -d)
chmod 700 "$tmpdir"
trap 'rm -rf "$tmpdir"' EXIT

changed=0
failed=()
while IFS=: read -r host _model; do
  [ -z "$host" ] && continue
  case "$host" in "#"*) continue ;; esac
  plain="$tmpdir/$host.rsc"
  if ssh -n -i "$SSH_KEY" -p "$SSH_PORT" -o BatchMode=yes -o ConnectTimeout=20 \
      -o StrictHostKeyChecking=accept-new \
      "$SSH_USER@$host" '/export show-sensitive' 2>/dev/null \
      | tr -d '\r' > "$plain" && [ -s "$plain" ]; then
    # drop the volatile "# <date> by RouterOS x.y" header so hashes are stable
    sed -i -E '1{/^# /d}' "$plain"
    newhash=$(sha256sum "$plain" | cut -d' ' -f1)
    oldhash=$(cat "encrypted/$host.sha256" 2>/dev/null || true)
    if [ "$newhash" != "$oldhash" ]; then
      if sops encrypt --input-type binary --output-type binary \
          --age "$AGE_RECIPIENTS" "$plain" > "encrypted/$host.rsc.sops"; then
        echo "$newhash" > "encrypted/$host.sha256"
        changed=1
      else
        failed+=("$host(sops)")
      fi
    fi
  else
    failed+=("$host")
  fi
  rm -f "$plain"
done < "$ROUTER_DB"

if [ "$changed" = 1 ]; then
  git add encrypted
  git -c user.name="netops-full-backup" -c user.email="netops@memhamwan.net" \
    commit -m "encrypted full-config backup $(date -u +%Y-%m-%d)" >/dev/null
  git push origin HEAD:encrypted
fi

# Textfile metrics for node-exporter: "last completed run" (not "all hosts
# succeeded" — permanently dark sites must not mask a broken timer/script).
TEXTFILE_DIR=${TEXTFILE_DIR:-/var/lib/netops/node-exporter}
if [ -d "$TEXTFILE_DIR" ]; then
  {
    echo "# HELP netops_full_backup_last_run_timestamp_seconds Unix time the nightly full backup last completed a run."
    echo "# TYPE netops_full_backup_last_run_timestamp_seconds gauge"
    echo "netops_full_backup_last_run_timestamp_seconds $(date +%s)"
    echo "# HELP netops_full_backup_failed_hosts Hosts that failed export in the last run."
    echo "# TYPE netops_full_backup_failed_hosts gauge"
    echo "netops_full_backup_failed_hosts ${#failed[@]}"
  } > "$TEXTFILE_DIR/netops-full-backup.prom.$$" \
    && mv "$TEXTFILE_DIR/netops-full-backup.prom.$$" "$TEXTFILE_DIR/netops-full-backup.prom"
fi

if [ ${#failed[@]} -gt 0 ]; then
  echo "full-export-backup: FAILED hosts: ${failed[*]}" >&2
  exit 1
fi
echo "full-export-backup: OK (changed=$changed)"
