#!/usr/bin/env python3
"""CI guard: no two fleet devices may share an OSPF router-id.

Why: on 2026-09-06 ftn.sco and leb.mno were found sharing router-id
44.34.131.140 — a duplicate-router-id LSA war that degraded reachability
network-wide for weeks while looking like a wireless problem. The Oxidized
exports carry every device's router-id; this check makes that drift a CI
failure instead of an incident.

Only files whose names match current inventory hosts are considered, so stale
exports (e.g. the pre-rename leb.hil file that mirrors sco.hil) don't produce
false positives. A single device exporting several router-ids (multiple
instances, e.g. er1.atl) is fine — the rule is that no id may appear on two
different devices.

Usage: check_ospf_router_ids.py <inventory-hosts.yml> <exports-dir>
"""
import re
import sys
from collections import defaultdict
from pathlib import Path

import yaml

ROUTER_ID = re.compile(r"router-id=([0-9.]+)")


def inventory_hosts(path):
    with open(path) as fh:
        data = yaml.safe_load(fh)
    hosts = set()

    def walk(node):
        if not isinstance(node, dict):
            return
        for key, value in node.items():
            if key == "hosts" and isinstance(value, dict):
                hosts.update(value)
            else:
                walk(value)

    walk(data)
    return hosts


def main():
    inv_path, exports_dir = sys.argv[1], Path(sys.argv[2])
    hosts = inventory_hosts(inv_path)
    owners = defaultdict(set)
    scanned = 0
    for host in sorted(hosts):
        export = exports_dir / host
        if not export.is_file():
            continue
        scanned += 1
        for rid in ROUTER_ID.findall(export.read_text(errors="replace")):
            owners[rid].add(host)

    duplicates = {rid: sorted(hs) for rid, hs in owners.items() if len(hs) > 1}
    if duplicates:
        for rid, hs in sorted(duplicates.items()):
            print(f"duplicate router-id {rid}: {', '.join(hs)}")
        sys.exit(1)
    if scanned == 0:
        print("error: no inventory host had an export file — wrong exports dir?")
        sys.exit(1)
    print(f"ok: {scanned} exports scanned, all router-ids unique")


if __name__ == "__main__":
    main()
