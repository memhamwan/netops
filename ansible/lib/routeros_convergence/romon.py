"""RoMON discovery: identity, version and board of every device the core can
reach at layer 2, including ones we cannot or must not log in to
(quarantined, locked out). Read over the API, which returns structured rows,
so none of the CLI's column truncation applies. Needs the `romon` policy.
"""
from . import versions


def discover(api, duration=15):
    """Rows from /tool/romon/discover, newest sighting per RoMON id."""
    seen = {}
    for row in api("/tool/romon/discover", duration=f"{int(duration)}s"):
        row = dict(row)
        key = row.get("address") or row.get(".id") or str(len(seen))
        seen[key] = row
    return [normalize(r) for r in seen.values()]


def normalize(row):
    return {
        "romon_id": row.get("address", ""),
        "identity": row.get("identity", ""),
        "version": versions.number(row.get("version", "")),
        "board": row.get("board", ""),
        "hops": row.get("hops"),
        "cost": row.get("cost"),
        "path": row.get("path", ""),
        "uptime": row.get("uptime", ""),
    }


def match_inventory(rows, hosts):
    """Map RoMON identities to inventory hosts.

    hosts: inventory names. An identity matches its full name or the short
    `host.site` form. Returns {inventory_host: row} plus the unmatched rows.
    """
    by_name = {}
    for host in hosts:
        by_name[host.lower()] = host
        by_name[host.lower().replace(".memhamwan.net", "")] = host
    matched, unmatched = {}, []
    for row in rows:
        host = by_name.get(str(row.get("identity", "")).lower())
        if host:
            matched[host] = row
        else:
            unmatched.append(row)
    return matched, unmatched
