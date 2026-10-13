"""Remediation plan: the actionable drift, in the order it must be applied.

Order (design): persistence first (schedulers, scripts, C2 files), then
accounts and keys, then services, then proxy/VPN kits and rules, then the
remaining files, then logging, then identity. Within a step, dependants go
before what they depend on (peers before their interface, accounts before
their profile, profiles before their pool). Changes that can cut the
controller's own API session (the API-SSL allow list) go last of all.

    plan(facts, declared) -> {host, version, ops, blocked, reports, evidence,
                              summary, device_mode_flagged}
"""
import re

from . import policy

# within-step order; anything not listed keeps check order after these
_CATEGORY_ORDER = (
    # accounts: keys first, so nothing an account owns outlives it
    "ssh_keys", "users", "account_groups",
    # services
    "services", "ssh_password_login", "ssh_settings",
    # kits: servers stop using the profiles first, then accounts -> profiles
    # -> pools, peers -> addresses -> interfaces
    "vpn_servers", "vpn_clients", "ppp_secrets", "ppp_profiles", "ip_pools",
    "wireguard_peers", "ip_addresses", "wireguard",
    "fw_filter", "fw_nat", "fw_mangle", "fw_raw",
    "socks", "proxy", "traffic_flow", "traffic_flow_targets", "ddns", "dns",
)
# a server's default-profile reset must precede its disable and the profile removal
_SET_BEFORE_DISABLE = {"default-profile"}


def _order_key(item):
    category = item["category"]
    rank = _CATEGORY_ORDER.index(category) if category in _CATEGORY_ORDER else len(_CATEGORY_ORDER)
    sub = 0 if _SET_BEFORE_DISABLE & set(item["values"]) else 1
    return (1 if item["last"] else 0, item["step"] or 99, rank, sub)


def plan(facts, declared):
    items = policy.drift(facts, declared)
    actionable = [i for i in items if i["action"] != "report"]
    ops = sorted((i for i in actionable if not i["blocked"]), key=_order_key)
    blocked = [i for i in actionable if i["blocked"]]
    reports = [i for i in items if i["action"] == "report"]
    files = [f for f in (facts.get("menus") or {}).get("files") or []
             if f.get("type") not in ("directory", "disk") and f.get("name")]
    for n, op in enumerate(ops, 1):
        op["seq"] = n
    return {
        "host": facts.get("host"),
        "version": facts.get("version"),
        "gathered_at": facts.get("gathered_at"),
        "device_mode_flagged": (facts.get("device_mode") or {}).get("flagged", False),
        "ops": ops,
        "blocked": blocked,
        "reports": reports,
        # every regular file is copied off before anything is applied
        "evidence": {"files": [f["name"] for f in files]},
        "summary": {
            "ops": len(ops),
            "removals": sum(1 for o in ops if o["action"] == "remove"),
            "blocked": len(blocked),
            "critical": sum(1 for i in items if i["severity"] == "critical"),
        },
    }


# what an export line can use a file for
_EXPORT_FILE_USE = re.compile(r"(file-name|public-key-file|private-key-file|certificate-file|"
                              r"dst-path|src-path|file)=\"?([^\s\"]+)\"?|/import\s+(?:file-name=)?\"?([^\s\"]+)")


def export_references(export_text, file_names):
    """Files named by configuration in an /export (file-name=, /import,
    public-key-file=...). Returns {file: [export lines]} for the given files.

    The plan already checks the API data; this second check runs on the
    evidence export in apply mode and blocks the removal of anything the
    configuration still points at."""
    bases = {name.rsplit("/", 1)[-1]: name for name in file_names}
    found = {}
    for line in export_text.splitlines():
        if line.lstrip().startswith("#"):
            continue
        for match in _EXPORT_FILE_USE.finditer(line):
            target = (match.group(2) or match.group(3) or "").rsplit("/", 1)[-1]
            if target in bases:
                found.setdefault(bases[target], []).append(line.strip()[:200])
    return found


def render_text(p):
    """Plan as text, one op per line, numbered in application order."""
    head = (f"{p['host']}  RouterOS {p.get('version') or '?'}  {p['summary']['ops']} change(s), "
            f"{p['summary']['removals']} removal(s), {p['summary']['blocked']} blocked")
    lines = [head]
    if p["device_mode_flagged"]:
        lines.append("  NOTE device-mode is flagged: some changes will fail until the mode button is pressed")
    step = None
    for op in p["ops"]:
        if op["step"] != step:
            step = op["step"]
            lines.append(f"  -- step {step}: {_STEP_NAMES.get(step, '')}")
        what = op["action"]
        if op["values"]:
            what += " " + " ".join(f"{k}={v}" for k, v in op["values"].items())
        lines.append(f"  {op['seq']:>3}. {op['path']}: {op['name']} -> {what}   ({op['severity']}: {op['reason']})")
    for item in p["blocked"]:
        lines.append(f"  BLOCKED {item['path']}: {item['name']}: {item['blocked']}")
    for item in p["reports"]:
        if item["severity"] != "info" or item["category"] == "files":
            lines.append(f"  report  {item['category']}: {item['name']}: {item['reason']}")
    if p["evidence"]["files"]:
        lines.append(f"  evidence: {len(p['evidence']['files'])} file(s) copied off before apply")
    return "\n".join(lines)


_STEP_NAMES = {
    policy.STEP_PERSISTENCE: "persistence (schedulers, scripts, C2 files)",
    policy.STEP_ACCOUNTS: "accounts and keys",
    policy.STEP_SERVICES: "services",
    policy.STEP_KITS: "proxy/VPN kits and rules",
    policy.STEP_FILES: "remaining files",
    policy.STEP_LOGGING: "logging",
    policy.STEP_IDENTITY: "identity",
}
