"""Drift report and Prometheus textfile metrics.

Metrics carry counts per device and check, never names or addresses: the
anonymous Grafana can query Prometheus, so anything exported is public. The
named findings stay in the report files, which are kept private.
"""
from collections import Counter

from . import policy, romon, versions
from .facts import first, static, truthy

SEVERITIES = ("critical", "warning", "info")

# Every check the policy can raise, so each device always exports a full,
# zero-filled set of series (alerts resolve instead of going stale).
CHECKS = (
    "users", "account_groups", "missing_accounts", "ssh_keys", "missing_ssh_keys",
    "foreign_sessions", "schedulers", "scripts", "services", "ssh_password_login",
    "ssh_settings", "ppp_secrets", "ppp_profiles", "ip_pools", "vpn_servers",
    "vpn_clients", "wireguard", "wireguard_peers", "ip_addresses", "fw_filter",
    "fw_nat", "fw_mangle", "fw_raw", "socks", "proxy", "traffic_flow",
    "traffic_flow_targets", "ddns", "dns", "files", "logging", "identity",
    "version_below_floor", "version_behind", "routerboot_behind",
    "device_mode_flagged", "bypass_signature", "api_certificate", "facts_incomplete",
)


def state(facts):
    """Compact inventory of the security-relevant state (the 2026-10-13 sweep's
    columns), independent of what is declared."""
    menus = facts.get("menus") or {}
    services = []
    for row in static(menus.get("services")):
        if not truthy(row.get("disabled", False)):
            key = versions.service_source_key(row, facts.get("version"))
            services.append(f"{row.get('name')}:{row.get('port')}[{row.get(key, '')}]")
    ssh = first(menus, "ssh")
    remote = next((a for a in menus.get("logging_actions") or [] if a.get("name") == "remote"), {})
    memory = next((a for a in menus.get("logging_actions") or [] if a.get("name") == "memory"), {})
    key_users = Counter(k.get("user") for k in menus.get("ssh_keys") or [])
    return {
        "identity": facts.get("identity"),
        "version": facts.get("version"),
        "uptime": facts.get("uptime"),
        "users": [u.get("name") + (" (disabled)" if truthy(u.get("disabled", False)) else "")
                  for u in menus.get("users") or []],
        "ssh_keys": dict(sorted(key_users.items())),
        "schedulers": len(menus.get("schedulers") or []),
        "scripts": len(menus.get("scripts") or []),
        "ppp_secrets": len(menus.get("ppp_secrets") or []),
        "pptp_server": truthy(first(menus, "pptp_server").get("enabled", False)),
        "l2tp_server": truthy(first(menus, "l2tp_server").get("enabled", False)),
        "wireguard": len(menus.get("wireguard") or []),
        "nat_rules": len(static(menus.get("fw_nat"))),
        "filter_rules": len(static(menus.get("fw_filter"))),
        "services": services,
        "password_login": ssh.get("password-authentication",
                                  ssh.get("always-allow-password-login", "")),
        "device_mode_flagged": (facts.get("device_mode") or {}).get("flagged", False),
        "syslog": remote.get("remote", ""),
        "memory_lines": memory.get("memory-lines"),
        "ddns": first(menus, "cloud").get("ddns-enabled", ""),
        "dns_servers": first(menus, "dns").get("servers", ""),
        "files": len([f for f in menus.get("files") or [] if f.get("type") not in ("directory", "disk")]),
    }


def report(facts, declared):
    """Drift report for one device."""
    items = policy.drift(facts, declared)
    by_severity = Counter(i["severity"] for i in items)
    by_check = Counter(i["category"] for i in items)
    worst = next((s for s in SEVERITIES if by_severity.get(s)), "ok")
    return {
        "host": facts.get("host"),
        "gathered_at": facts.get("gathered_at"),
        "version": facts.get("version"),
        "board": facts.get("board"),
        "device_mode_flagged": (facts.get("device_mode") or {}).get("flagged", False),
        "worst": worst,
        "counts": {s: by_severity.get(s, 0) for s in SEVERITIES},
        "checks": dict(sorted(by_check.items())),
        "state": state(facts),
        "findings": sorted(items, key=lambda i: (policy.SEVERITY_RANK[i["severity"]], i["category"])),
    }


def fleet(entries, romon_rows=None, probes=None):
    """Fleet view combining audited devices with what is known about the rest.

    entries: [{host, lifecycle, report?, error?}] for every inventory device;
    romon_rows: RoMON discovery from the core (identity, version, board);
    probes: [{name, open: [ports]}]. Returns {rows, romon_only, text}.
    """
    hosts = [e["host"] for e in entries]
    seen, romon_only = romon.match_inventory(romon_rows or [], hosts)
    open_ports = {p["name"]: p.get("open", []) for p in probes or []}
    rows = []
    for entry in sorted(entries, key=lambda e: e["host"]):
        rep = entry.get("report")
        ro = seen.get(entry["host"]) or {}
        if rep:
            version, source = rep.get("version") or "?", "api"
            counts = rep["counts"]
            top = [f["category"] for f in rep["findings"] if f["severity"] == "critical"]
            note = ", ".join(sorted(set(top))[:4])
        else:
            version, source = (ro.get("version") or "?"), ("romon" if ro else "")
            counts = None
            note = entry.get("error") or ("not logged in to (lifecycle)" if entry["lifecycle"] != "active" else "")
        rows.append({
            "host": entry["host"],
            "lifecycle": entry["lifecycle"],
            "read": bool(rep),
            "version": version,
            "version_source": source,
            "below_floor": bool(version and version != "?" and not versions.at_least(version, versions.SECURITY_FLOOR)),
            "romon_hops": ro.get("hops"),
            "counts": counts,
            "open_ports": open_ports.get(entry["host"]),
            "note": note,
        })
    lines = [f"{'device':<14} {'lifecycle':<13} {'read':<4} {'version':<16} {'crit':>4} {'warn':>4} "
             f"{'info':>4}  {'ports':<20} note"]
    for r in rows:
        c = r["counts"] or {}
        ver = r["version"] + (f" ({r['version_source']})" if r["version_source"] == "romon" else "")
        if r["below_floor"]:
            ver += " !"
        ports = ",".join(str(p) for p in r["open_ports"]) if r["open_ports"] is not None else "-"
        lines.append(f"{short_name(r['host']):<14} {r['lifecycle']:<13} {'yes' if r['read'] else 'no':<4} "
                     f"{ver:<16} {c.get('critical', '-'):>4} {c.get('warning', '-'):>4} {c.get('info', '-'):>4}  "
                     f"{ports:<20} {r['note']}")
    for row in romon_only:
        lines.append(f"RoMON only (not in inventory): {row['identity'] or row['romon_id']} "
                     f"{row['version']} {row['board']} hops={row['hops']}")
    lines.append("! = below the security floor " + versions.SECURITY_FLOOR)
    return {"rows": rows, "romon_only": romon_only, "text": "\n".join(lines)}


def short_name(host):
    return str(host).replace(".memhamwan.net", "")


def render_text(rep):
    """Human-readable lines for one device report."""
    lines = [f"{rep['host']}  RouterOS {rep.get('version') or '?'}  "
             f"critical={rep['counts']['critical']} warning={rep['counts']['warning']} "
             f"info={rep['counts']['info']}"]
    for f in rep["findings"]:
        action = "" if f["action"] == "report" else f" [{f['action']}]"
        blocked = f"  BLOCKED: {f['blocked']}" if f.get("blocked") else ""
        lines.append(f"  {f['severity']:<8} {f['category']:<20} {f['name']}: {f['reason']}{action}{blocked}")
    return "\n".join(lines)


def metrics(reports, unreadable, now):
    """Textfile collector content for one audit run.

    reports: device reports that were read; unreadable: hosts whose facts
    could not be read (auth failure, timeout)."""
    out = [
        "# HELP routeros_audit_last_run_timestamp_seconds When the RouterOS audit last completed.",
        "# TYPE routeros_audit_last_run_timestamp_seconds gauge",
        f"routeros_audit_last_run_timestamp_seconds {int(now)}",
        "# HELP routeros_audit_up 1 when the audit could read the device, 0 when it could not.",
        "# TYPE routeros_audit_up gauge",
    ]
    for rep in sorted(reports, key=lambda r: r["host"]):
        out.append(f'routeros_audit_up{{device="{short_name(rep["host"])}"}} 1')
    for host in sorted(unreadable):
        out.append(f'routeros_audit_up{{device="{short_name(host)}"}} 0')
    out += [
        "# HELP routeros_audit_findings Drift findings per device and severity.",
        "# TYPE routeros_audit_findings gauge",
    ]
    for rep in sorted(reports, key=lambda r: r["host"]):
        for severity in SEVERITIES:
            out.append(f'routeros_audit_findings{{device="{short_name(rep["host"])}",'
                       f'severity="{severity}"}} {rep["counts"][severity]}')
    out += [
        "# HELP routeros_audit_check_findings Drift findings per device and check.",
        "# TYPE routeros_audit_check_findings gauge",
    ]
    for rep in sorted(reports, key=lambda r: r["host"]):
        for check in CHECKS:
            out.append(f'routeros_audit_check_findings{{device="{short_name(rep["host"])}",'
                       f'check="{check}"}} {rep["checks"].get(check, 0)}')
    return "\n".join(out) + "\n"
