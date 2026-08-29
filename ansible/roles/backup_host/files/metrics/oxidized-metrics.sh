#!/bin/sh
# Freshness metrics for the hourly oxidized track, written for node-exporter's
# textfile collector. Pipeline health only: "no node has fetched recently"
# means oxidized/ssh/git is broken — individual dark devices are already
# covered by the ICMP alerts.
set -eu
TEXTFILE_DIR=${TEXTFILE_DIR:-/var/lib/netops/node-exporter}
OXIDIZED_URL=${OXIDIZED_URL:-http://127.0.0.1:8888}

nodes=$(curl -fsS --max-time 20 "$OXIDIZED_URL/nodes.json")
total=$(printf '%s' "$nodes" | jq 'length')
success=$(printf '%s' "$nodes" | jq '[.[] | select(.last.status == "success")] | length')
# "2026-08-29 19:06:19 UTC" sorts lexicographically, so max is the newest
newest=$(printf '%s' "$nodes" | jq -r '[.[] | select(.last.status == "success") | .last.end] | max // empty')
newest_epoch=0
[ -n "$newest" ] && newest_epoch=$(date -u -d "$newest" +%s)

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
} > "$tmp"
mv "$tmp" "$TEXTFILE_DIR/netops-oxidized.prom"
