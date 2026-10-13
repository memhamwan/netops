"""Normalized snapshot of one device: summary fields plus the raw menus.

The menus keep RouterOS's own field names (and `.id`s) so the planner can
address entries; the summary pulls out what every consumer needs. Schema:

    {schema, host, gathered_at, errors: {menu: text}, menus: {menu: [row]},
     version, channel, architecture, board, routerboard, firmware_current,
     firmware_upgrade, free_hdd, total_hdd, identity, packages: [...],
     device_mode: {mode, flagged}}
"""
from . import SCHEMA, versions


def first(menus, key):
    rows = menus.get(key) or []
    return rows[0] if rows else {}


def truthy(value):
    """RouterOS booleans arrive as bool over the API, yes/no or true/false as text."""
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("yes", "true")


def static(rows):
    """Configured entries only: drops dynamic rows (sessions, UPnP, default
    routes...) that cannot and need not be managed."""
    return [r for r in rows or [] if not truthy(r.get("dynamic", False))]


def normalize(host, rows, errors, gathered_at):
    resource = first(rows, "resource")
    routerboard = first(rows, "routerboard")
    device_mode = first(rows, "device_mode")
    version = resource.get("version", "")
    return {
        "schema": SCHEMA,
        "host": host,
        "gathered_at": gathered_at,
        "errors": dict(errors),
        "menus": rows,
        "version": versions.number(version),
        "channel": versions.channel(version),
        "architecture": resource.get("architecture-name", ""),
        "board": resource.get("board-name", ""),
        "free_hdd": resource.get("free-hdd-space"),
        "total_hdd": resource.get("total-hdd-space"),
        "uptime": resource.get("uptime", ""),
        "routerboard": truthy(routerboard.get("routerboard", False)),
        "firmware_current": routerboard.get("current-firmware", ""),
        "firmware_upgrade": routerboard.get("upgrade-firmware", ""),
        "identity": first(rows, "identity").get("name", ""),
        "packages": [
            {"name": p.get("name"), "version": p.get("version"),
             "disabled": truthy(p.get("disabled", False))}
            for p in rows.get("packages", [])
        ],
        "device_mode": {
            "mode": device_mode.get("mode", ""),
            "flagged": truthy(device_mode.get("flagged", False)),
        },
    }


def gather(host, address, username, password, port=8729, tls=True, timeout=30, now=None):
    """Connect, read every menu, and return the normalized snapshot."""
    import datetime

    from . import gather as reader

    api = reader.connect(address, username, password, port=port, tls=tls, timeout=timeout)
    try:
        rows, errors = reader.read_all(api)
    finally:
        try:
            api.close()
        except Exception:  # the session may already be gone
            pass
    stamp = now or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return normalize(host, rows, errors, stamp)
