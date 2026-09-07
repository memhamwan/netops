#!/usr/bin/env python3
"""CI guard: no two fleet devices may share an OSPF router-id.

Why: on 2026-09-06 ftn.sco and leb.mno were found sharing router-id
44.34.131.140 — a duplicate-router-id LSA war that degraded reachability
network-wide for weeks while looking like a wireless problem. The Oxidized
exports carry every device's router-id; this check makes that drift a CI
failure instead of an incident.

The checked set mirrors what Oxidized actually backs up: the `routeros`
group minus the `excluded` and `expected_down` lifecycle groups. Every host
in that set MUST have an export — a missing file means the audit data is
incomplete, and a silent skip here would let a duplicate hide. Stale exports
of hosts Oxidized intentionally no longer fetches (renamed devices,
expected-down sites) are not scanned. A single device exporting several
router-ids (multiple instances, e.g. er1.atl) is fine — the rule is that no
id may appear on two different devices.

--allow-missing HOST (repeatable) exempts a host from the missing-export
failure — for the window between a host (re)joining the active set and its
first Oxidized fetch. Each use should carry a PR comment saying when it can
be removed.

Usage: check_ospf_router_ids.py [--allow-missing HOST]... <inventory-hosts.yml> <exports-dir>
"""
import argparse
import re
import sys
from collections import defaultdict
from pathlib import Path

import yaml

ROUTER_ID = re.compile(r"router-id=([0-9.]+)")


def hosts_of(group):
    """All hosts under a group node, recursing through `children`."""
    found = set()
    if not isinstance(group, dict):
        return found
    found.update(group.get("hosts") or {})
    for child in (group.get("children") or {}).values():
        found |= hosts_of(child)
    return found


def active_routeros_hosts(path):
    with open(path) as fh:
        children = yaml.safe_load(fh)["all"]["children"]
    active = hosts_of(children.get("routeros"))
    for lifecycle in ("excluded", "expected_down"):
        active -= hosts_of(children.get(lifecycle, {}))
    return active


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--allow-missing", action="append", default=[], metavar="HOST")
    parser.add_argument("inventory")
    parser.add_argument("exports_dir", type=Path)
    args = parser.parse_args()

    active = active_routeros_hosts(args.inventory)
    if not active:
        print("error: inventory yielded no active routeros hosts — parse bug?")
        return 1

    owners = defaultdict(set)
    missing = []
    scanned = 0
    for host in sorted(active):
        export = args.exports_dir / host
        if not export.is_file():
            if host in args.allow_missing:
                print(f"note: no export for {host} (allowed, pending first fetch)")
            else:
                missing.append(host)
            continue
        scanned += 1
        for rid in ROUTER_ID.findall(export.read_text(errors="replace")):
            owners[rid].add(host)

    failed = False
    duplicates = {rid: sorted(hs) for rid, hs in owners.items() if len(hs) > 1}
    for rid, hs in sorted(duplicates.items()):
        print(f"duplicate router-id {rid}: {', '.join(hs)}")
        failed = True
    for host in missing:
        print(
            f"missing export for active host {host} — audit data is "
            "incomplete (is oxidized fetching it? if it just joined the "
            "active set, use --allow-missing with a dated comment)"
        )
        failed = True
    if failed:
        return 1
    print(f"ok: {scanned} exports scanned, all router-ids unique")
    return 0


if __name__ == "__main__":
    sys.exit(main())
