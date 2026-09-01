#!/bin/sh
# Freshness metrics for the hourly oxidized track, written for node-exporter's
# textfile collector. Pipeline health only: "no node has fetched recently"
# means oxidized/ssh/git is broken — individual dark devices are already
# covered by the ICMP alerts.
set -eu
TEXTFILE_DIR=${TEXTFILE_DIR:-/var/lib/netops/node-exporter}
OXIDIZED_URL=${OXIDIZED_URL:-http://127.0.0.1:8888}

REPO=${REPO:-/var/lib/netops/oxidized/devices.git}
DEPLOY_KEY=${DEPLOY_KEY:-/var/lib/netops/ssh/gh_deploy_ed25519}
REMOTE=${REMOTE:-git@github.com:memhamwan/routeros-config-audit.git}

nodes=$(curl -fsS --max-time 20 "$OXIDIZED_URL/nodes.json")
total=$(printf '%s' "$nodes" | jq 'length')
success=$(printf '%s' "$nodes" | jq '[.[] | select(.last.status == "success")] | length')
# "2026-08-29 19:06:19 UTC" sorts lexicographically, so max is the newest
newest=$(printf '%s' "$nodes" | jq -r '[.[] | select(.last.status == "success") | .last.end] | max // empty')
newest_epoch=0
[ -n "$newest" ] && newest_epoch=$(date -u -d "$newest" +%s)

# Fetch freshness alone can't see the nodes_done GitHub push hook failing —
# compare the local bare repo HEAD to the remote main to observe publication.
# ls-remote failure (github/network down) also reads as unpublished: correct,
# since the push can't be succeeding either.
local_head=$(git -C "$REPO" rev-parse HEAD 2>/dev/null || echo local-unknown)
remote_head=$(GIT_SSH_COMMAND="ssh -i $DEPLOY_KEY -o BatchMode=yes -o StrictHostKeyChecking=accept-new" \
  git ls-remote "$REMOTE" refs/heads/main 2>/dev/null | cut -f1 || true)
pushed=0
[ "$local_head" = "$remote_head" ] && pushed=1

tmp="$TEXTFILE_DIR/netops-oxidized.prom.$$"
{
  echo "# HELP netops_oxidized_nodes Total nodes oxidized is tracking."
  echo "# TYPE netops_oxidized_nodes gauge"
  echo "netops_oxidized_nodes $total"
  echo "# HELP netops_oxidized_nodes_success Nodes whose last fetch succeeded."
  echo "# TYPE netops_oxidized_nodes_success gauge"
  echo "netops_oxidized_nodes_success $success"
  echo "# HELP netops_oxidized_last_success_timestamp_seconds Newest successful fetch across all nodes."
  echo "# TYPE netops_oxidized_last_success_timestamp_seconds gauge"
  echo "netops_oxidized_last_success_timestamp_seconds $newest_epoch"
  echo "# HELP netops_oxidized_pushed 1 when the local backup repo HEAD matches the GitHub main branch."
  echo "# TYPE netops_oxidized_pushed gauge"
  echo "netops_oxidized_pushed $pushed"
} > "$tmp"
mv "$tmp" "$TEXTFILE_DIR/netops-oxidized.prom"
