#!/usr/bin/env python3
"""CI guard: every rendered ICMP probe target must be an IP literal or a
DNS-resolvable name.

Why: a probed hostname with no DNS record (the 2026-09 ups.sco / ups.mno
defect) produces a probe that is structurally incapable of ever succeeding —
a permanent false alarm that erodes the alert channel. Hosts that cannot be
addressed belong in the inventory `excluded` group instead.

Usage: check_probe_targets.py <rendered-target-file.yml> [...]
"""
import ipaddress
import socket
import sys

import yaml

failures = []
checked = 0
for path in sys.argv[1:]:
    with open(path) as fh:
        entries = yaml.safe_load(fh) or []
    for entry in entries:
        device = (entry.get("labels") or {}).get("device", "?")
        for target in entry.get("targets", []):
            checked += 1
            try:
                ipaddress.ip_address(target)
                continue
            except ValueError:
                pass
            try:
                socket.getaddrinfo(target, None)
            except OSError:
                failures.append(
                    f"{path}: device {device!r} target {target!r} is not an "
                    "IP and does not resolve — record an `ip:` in the "
                    "inventory or move the host to the `excluded` group"
                )

if failures:
    print("\n".join(failures))
    sys.exit(1)
print(f"ok: {checked} probe targets are IP literals or resolvable names")
