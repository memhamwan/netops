#!/usr/bin/env bash
# Create the backup service accounts on RouterOS devices:
#   oxidized       group netops-backup-ro   (policy ssh,read)          — sanitized exports
#   oxidized-full  group netops-backup-full (policy ssh,read,sensitive) — encrypted full exports
#
# Both accounts are key-auth only: each is created with a random password that
# is generated per host and never recorded anywhere.
#
# Usage: add-backup-users.sh <pubkey_ro> <pubkey_full> <host> [<host>...]
#   Runs over SSH port 222 as $ADMIN_USER (default: current user), which must
#   be an existing full-rights account with key auth (netops user).
#
# Idempotent: existing groups/users/keys are left alone, so this doubles as
# the onboarding step for new devices.
set -uo pipefail

ADMIN_USER=${ADMIN_USER:-$USER}
SSH_PORT=${SSH_PORT:-222}

PUB_RO=$1
PUB_FULL=$2
shift 2

[ -r "$PUB_RO" ] && [ -r "$PUB_FULL" ] || { echo "pubkey files not readable" >&2; exit 2; }

rc=0
for host in "$@"; do
  echo "=== $host"
  pw_ro=$(openssl rand -base64 24)
  pw_full=$(openssl rand -base64 24)
  if ! scp -q -O -P "$SSH_PORT" -o ConnectTimeout=20 -o BatchMode=yes \
      "$PUB_RO" "$ADMIN_USER@$host:oxidized.pub" ||
     ! scp -q -P "$SSH_PORT" -o ConnectTimeout=20 -o BatchMode=yes \
      "$PUB_FULL" "$ADMIN_USER@$host:oxidized-full.pub"; then
    echo "$host: FAILED (scp)" >&2; rc=1; continue
  fi
  if ! ssh -p "$SSH_PORT" -o ConnectTimeout=20 -o BatchMode=yes "$ADMIN_USER@$host" "
:if ([:len [/user group find name=netops-backup-ro]] = 0) do={/user group add name=netops-backup-ro policy=ssh,read}
:if ([:len [/user group find name=netops-backup-full]] = 0) do={/user group add name=netops-backup-full policy=ssh,read,sensitive}
:if ([:len [/user find name=oxidized]] = 0) do={/user add name=oxidized group=netops-backup-ro password=\"$pw_ro\"}
:if ([:len [/user find name=oxidized-full]] = 0) do={/user add name=oxidized-full group=netops-backup-full password=\"$pw_full\"}
:if ([:len [/user ssh-keys find user=oxidized]] = 0) do={/user ssh-keys import public-key-file=oxidized.pub user=oxidized}
:if ([:len [/user ssh-keys find user=oxidized-full]] = 0) do={/user ssh-keys import public-key-file=oxidized-full.pub user=oxidized-full}
"; then
    echo "$host: FAILED (config)" >&2; rc=1; continue
  fi
  echo "$host: OK"
done
exit $rc
