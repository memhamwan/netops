"""Drift between a device snapshot and its declared state.

`drift(facts, declared)` returns a list of items; the audit counts them and
the remediation planner orders the actionable ones into operations, so both
apply the same rules. An item:

    {category, action: remove|set|add|report, menu, path, id, name,
     values, expect, severity: critical|warning|info, reason, blocked,
     step, last}

`expect` holds identifying fields the executor re-checks before touching the
entry with that `.id`; `blocked` explains why an action must not run;
`step` orders actions (persistence first, logging last); `last` marks
changes that can cut the controller's own session (API-SSL allow list).
"""
import re
from collections import defaultdict

from . import versions
from .declared import allowed_by, fingerprint
from .facts import first, static, truthy
from .gather import READ_PATHS

MENU_PATH = {key: " ".join(path) for key, path, _ in READ_PATHS}

STEP_PERSISTENCE = 1
STEP_ACCOUNTS = 2
STEP_SERVICES = 3
STEP_KITS = 4
STEP_FILES = 5
STEP_LOGGING = 6
STEP_IDENTITY = 7

SEVERITY_RANK = {"critical": 0, "warning": 1, "info": 2}

# remote code pulled in by a scheduler or script: the C2 persistence pattern
_FETCH_IMPORT = re.compile(r"(?i)(/tool\s+fetch|\bfetch\b[^\n]*\burl=|/import\b|ssh-keys\s+import)")
# file names seen on taken-over devices (miners, droppers)
_HOSTILE_FILE = re.compile(r"(?i)(redtail|xmrig|kinsing|(^|/)(setup|clean|x)\.sh$|\.sh$)")
_SECRET_BEARING_FILE = re.compile(r"(?i)\.(backup|rsc|rif|auto\.rsc)$")
_CERT_FILE = re.compile(r"(?i)\.(crt|pem|key|p12|pfx|der|cer)$")
_BYPASS_TRACE = re.compile(r":-2@")
_ABSENT = re.compile(r"(?i)no such (command|item|directory)")

_GUARD_FIELDS = ("name", "comment", "user", "chain", "action", "interface", "public-key",
                 "address", "dst-address", "src-address", "port", "topics")


def _label(row):
    for key in ("name", "comment"):
        if row.get(key):
            return str(row[key])
    if row.get("chain"):
        bits = [row.get("chain"), row.get("action")]
        for key in ("src-address", "dst-address", "dst-port", "src-address-list", "protocol"):
            if row.get(key):
                bits.append(f"{key}={row[key]}")
        return " ".join(str(b) for b in bits if b)
    return str(row.get(".id", "?"))


def _expect(row):
    """Identifying fields, as text, that must still hold when the entry with
    this .id is touched (ids can be reused after a removal)."""
    return {k: str(row[k]) for k in _GUARD_FIELDS
            if isinstance(row.get(k), (str, int)) and not isinstance(row.get(k), bool) and row.get(k) != ""}


def _item(category, action, menu, row=None, *, values=None, severity="warning",
          reason="", blocked=None, step=None, name=None, last=False):
    row = row or {}
    return {
        "category": category,
        "action": action,
        "menu": menu,
        "path": MENU_PATH.get(menu, menu),
        "id": row.get(".id"),
        "name": name if name is not None else _label(row),
        "values": values or {},
        "expect": _expect(row),
        "severity": severity,
        "reason": reason,
        "blocked": blocked,
        "step": step,
        "last": last,
    }


def _csv(value):
    if value is None or value == "":
        return []
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value]
    return [v.strip() for v in str(value).split(",") if v.strip()]


def _enabled(row):
    """Single-value servers use `enabled`; list entries use `disabled`."""
    if "enabled" in row:
        return truthy(row["enabled"])
    return not truthy(row.get("disabled", False))


def _grants(policy, right):
    return right in [p for p in _csv(policy) if not p.startswith("!")]


def _off(value):
    """yes/no values arrive as booleans over the API (librouteros casts
    them); enums such as yes-if-no-key stay strings."""
    return value is False or str(value).strip().lower() in ("no", "false", "")


class _Context:
    def __init__(self, facts, declared):
        self.facts = facts
        self.declared = declared
        self.menus = facts.get("menus") or {}
        self.errors = facts.get("errors") or {}
        self.allow = declared.get("allow") or {}
        self.version = facts.get("version", "")
        self.accounts = {a["name"]: a for a in declared.get("accounts") or []}
        self.items = []
        # (menu, .id) of every entry an item removes: references from these
        # do not protect anything
        self.removed = set()

    def read(self, menu):
        """Rows of a menu, or None when it could not be read for a reason
        other than the device not having it."""
        if menu in self.errors and not _ABSENT.search(self.errors[menu]):
            return None
        return self.menus.get(menu) or []

    def add(self, item):
        self.items.append(item)
        if item["action"] == "remove" and item["id"] is not None:
            self.removed.add((item["menu"], item["id"]))
        return item

    def allowed_user(self, name):
        return name in self.accounts or allowed_by(self.allow, "users", {"name": name})


# ── accounts ────────────────────────────────────────────────────────────


def _users(ctx):
    rows = ctx.read("users")
    if rows is None:
        return
    present = set()
    for row in rows:
        name = row.get("name")
        present.add(name)
        account = ctx.accounts.get(name)
        if account:
            want = account.get("group")
            if want and row.get("group") != want:
                ctx.add(_item("account_groups", "set", "users", row, values={"group": want},
                              reason=f"group {row.get('group')}, declared {want}",
                              step=STEP_ACCOUNTS))
            continue
        if allowed_by(ctx.allow, "users", row):
            continue
        state = "disabled" if truthy(row.get("disabled", False)) else "enabled"
        ctx.add(_item("users", "remove", "users", row, severity="critical",
                      reason=f"account not declared ({state}, group {row.get('group')})",
                      step=STEP_ACCOUNTS))
    for name in sorted(set(ctx.accounts) - present):
        ctx.add(_item("missing_accounts", "report", "users", name=name,
                      reason="declared account absent; routeros_access creates it"))


def _ssh_keys(ctx):
    rows = ctx.read("ssh_keys")
    if rows is None:
        return
    unfingerprinted = defaultdict(list)
    seen = defaultdict(set)
    fingerprints = any("fingerprint" in r for r in rows)
    for row in rows:
        user = row.get("user")
        comment = row.get("info", row.get("key-owner", ""))
        label = f"{user}: {row.get('key-type', '?')} {comment}".strip()
        if not ctx.allowed_user(user):
            ctx.add(_item("ssh_keys", "remove", "ssh_keys", row, name=label, severity="critical",
                          reason="key on an account that is not declared", step=STEP_ACCOUNTS))
            continue
        account = ctx.accounts.get(user)
        if account is None:
            continue  # extra account allowed per device: its keys are its own
        declared = {fingerprint(k["fingerprint"]) for k in account.get("keys") or []}
        if row.get("fingerprint"):
            seen[user].add(fingerprint(row["fingerprint"]))
            if fingerprint(row["fingerprint"]) not in declared:
                ctx.add(_item("ssh_keys", "remove", "ssh_keys", row, name=label,
                              severity="critical", reason="key not declared for this account",
                              step=STEP_ACCOUNTS))
        else:
            unfingerprinted[user].append(row)
    for user, keys in sorted(unfingerprinted.items()):
        declared_n = len(ctx.accounts[user].get("keys") or [])
        if len(keys) > declared_n:
            ctx.add(_item("ssh_keys", "report", "ssh_keys", name=user, severity="critical",
                          reason=(f"{len(keys)} keys, {declared_n} declared; this version shows "
                                  "no fingerprints, so routeros_access replaces the set")))
    for user, account in sorted(ctx.accounts.items()):
        declared = account.get("keys") or []
        if fingerprints or not rows:
            missing = [k for k in declared if fingerprint(k["fingerprint"]) not in seen[user]]
        else:
            missing = declared[len(unfingerprinted[user]):]
        if missing:
            ctx.add(_item("missing_ssh_keys", "report", "ssh_keys", name=user,
                          reason=f"{len(missing)} declared key(s) absent; routeros_access imports them"))


def _sessions(ctx):
    rows = ctx.read("active_users")
    if rows is None:
        return
    counts = defaultdict(int)
    for row in rows:
        if not ctx.allowed_user(row.get("name")):
            counts[row.get("name")] += 1
    for name, n in sorted(counts.items()):
        ctx.add(_item("foreign_sessions", "report", "active_users", name=name, severity="critical",
                      reason=(f"{n} open session(s) of an undeclared account; removal does not end "
                              "them, a reboot or their timeout does")))


# ── persistence ─────────────────────────────────────────────────────────


def _code(ctx, menu, category, body_field):
    rows = ctx.read(menu)
    if rows is None:
        return
    for row in rows:
        if allowed_by(ctx.allow, category, row):
            continue
        body = str(row.get(body_field, ""))
        hostile = bool(_FETCH_IMPORT.search(body))
        ctx.add(_item(category, "remove", menu, row,
                      severity="critical" if hostile else "warning",
                      reason=("not declared; fetches or imports code" if hostile else "not declared"),
                      step=STEP_PERSISTENCE))


# ── services ────────────────────────────────────────────────────────────


def _services(ctx):
    rows = ctx.read("services")
    if rows is None:
        return
    declared = ctx.declared.get("services") or {}
    sources = list(ctx.declared.get("management_sources") or [])
    for row in static(rows):
        name = row.get("name")
        key = versions.service_source_key(row, ctx.version)
        have = _csv(row.get(key))
        enabled = not truthy(row.get("disabled", False))
        if name in declared:
            want = declared[name] or {}
            values = {}
            if not enabled:
                values["disabled"] = False
            if want.get("port") and str(row.get("port")) != str(want["port"]):
                values["port"] = int(want["port"])
            if sorted(have) != sorted(sources):
                values[key] = ",".join(sources)
            if want.get("certificate") and row.get("certificate") != want["certificate"]:
                values["certificate"] = want["certificate"]
            if values:
                open_to_all = enabled and not have
                ctx.add(_item("services", "set", "services", row, values=values,
                              severity="critical" if open_to_all else "warning",
                              reason=("reachable from every address" if open_to_all
                                      else "differs from the declared service"),
                              step=STEP_SERVICES, last=(name == "api-ssl")))
        elif enabled and not allowed_by(ctx.allow, "services", row):
            ctx.add(_item("services", "set", "services", row, values={"disabled": True},
                          severity="critical" if not have else "warning",
                          reason="enabled, not declared" + ("; reachable from every address" if not have else ""),
                          step=STEP_SERVICES))


def _ssh_accounts_without_keys(ctx):
    """Declared accounts that could log in over SSH but hold no key."""
    users = ctx.read("users") or []
    groups = {g.get("name"): g.get("policy", "") for g in ctx.read("user_groups") or []}
    keys = defaultdict(int)
    for row in ctx.read("ssh_keys") or []:
        keys[row.get("user")] += 1
    keyless = []
    for row in users:
        name = row.get("name")
        if name not in ctx.accounts or truthy(row.get("disabled", False)):
            continue
        if _grants(groups.get(row.get("group"), "ssh"), "ssh") and keys[name] == 0:
            keyless.append(name)
    return keyless


def _ssh(ctx):
    rows = ctx.read("ssh")
    if not rows:
        return
    row = rows[0]
    want = ctx.declared.get("ssh") or {}
    values = {}
    if not want.get("password_login", False):
        if "password-authentication" in row:
            if not _off(row["password-authentication"]):
                values["password-authentication"] = "no"
        elif truthy(row.get("always-allow-password-login", False)):
            values["always-allow-password-login"] = False
        if "password-authentication" not in row:
            ctx.add(_item("ssh_password_login", "report", "ssh", name="ssh",
                          severity="info",
                          reason=f"password login cannot be refused before {versions.SSH_PASSWORD_AUTH_SINCE}"))
    if values:
        keyless = _ssh_accounts_without_keys(ctx)
        ctx.add(_item("ssh_password_login", "set", "ssh", name="ssh", values=values,
                      reason=f"password login on ({next(iter(values.items()))[0]})",
                      blocked=(f"SSH accounts without a key would be locked out: {', '.join(keyless)}"
                               if keyless else None),
                      step=STEP_SERVICES))
    forwarding = row.get("forwarding-enabled", False)
    if not _off(forwarding) and not want.get("forwarding", False):
        ctx.add(_item("ssh_settings", "set", "ssh", name="ssh", values={"forwarding-enabled": "no"},
                      reason=f"forwarding-enabled={forwarding}", step=STEP_SERVICES))
    if want.get("strong_crypto", True) and not truthy(row.get("strong-crypto", False)):
        ctx.add(_item("ssh_settings", "set", "ssh", name="ssh", values={"strong-crypto": True},
                      reason="strong-crypto off", step=STEP_SERVICES))


# ── proxy / VPN kits, rules ─────────────────────────────────────────────

_SERVERS = (("pptp_server", "pptp"), ("l2tp_server", "l2tp"),
            ("sstp_server", "sstp"), ("ovpn_server", "ovpn"))
_CLIENTS = ("pptp_clients", "l2tp_clients", "sstp_clients", "ovpn_clients")
_BUILTIN_PROFILES = ("default", "default-encryption")


def _kits(ctx):
    # PPP accounts first: what they reference decides which profiles stay
    kept_secret_profiles = set()
    for row in ctx.read("ppp_secrets") or []:
        if allowed_by(ctx.allow, "ppp_secrets", row):
            kept_secret_profiles.add(row.get("profile"))
            continue
        ctx.add(_item("ppp_secrets", "remove", "ppp_secrets", row, severity="critical",
                      reason="PPP account not declared", step=STEP_KITS))

    removed_profiles = set()
    kept_profiles = []
    for row in ctx.read("ppp_profiles") or []:
        name = row.get("name")
        if (truthy(row.get("default", False)) or name in _BUILTIN_PROFILES
                or allowed_by(ctx.allow, "ppp_profiles", row)):
            kept_profiles.append(row)
            continue
        if name in kept_secret_profiles:
            kept_profiles.append(row)
            ctx.add(_item("ppp_profiles", "report", "ppp_profiles", row,
                          reason="not declared, kept: a declared PPP account uses it"))
            continue
        removed_profiles.add(name)
        ctx.add(_item("ppp_profiles", "remove", "ppp_profiles", row,
                      reason="PPP profile not declared", step=STEP_KITS))

    for menu, label in _SERVERS:
        for row in ctx.read(menu) or []:
            name = row.get("name", label)
            allowed = allowed_by(ctx.allow, "vpn_servers", {"name": name}) or \
                allowed_by(ctx.allow, "vpn_servers", {"name": label})
            if row.get("default-profile") in removed_profiles:
                ctx.add(_item("vpn_servers", "set", menu, row, name=name,
                              values={"default-profile": "default-encryption"},
                              reason=f"default profile {row.get('default-profile')} is being removed",
                              step=STEP_KITS))
            if _enabled(row) and not allowed:
                values = {"enabled": False} if "enabled" in row else {"disabled": True}
                ctx.add(_item("vpn_servers", "set", menu, row, name=name, values=values,
                              severity="critical", reason="VPN server enabled, not declared",
                              step=STEP_KITS))

    referenced_pools = set()
    for row in kept_profiles:
        referenced_pools.update(_csv(row.get("local-address")) + _csv(row.get("remote-address")))
    for row in ctx.read("dhcp_servers") or []:
        referenced_pools.add(row.get("address-pool"))
    pools = ctx.read("ip_pools") or []
    kept_pools = [p for p in pools if allowed_by(ctx.allow, "ip_pools", p)
                  or p.get("name") in referenced_pools]
    for row in kept_pools:
        referenced_pools.update(_csv(row.get("next-pool")))
    for row in pools:
        if allowed_by(ctx.allow, "ip_pools", row):
            continue
        if row.get("name") in referenced_pools:
            ctx.add(_item("ip_pools", "report", "ip_pools", row,
                          reason="not declared, kept: a kept profile or DHCP server uses it"))
            continue
        ctx.add(_item("ip_pools", "remove", "ip_pools", row,
                      reason="address pool not declared", step=STEP_KITS))

    removed_interfaces = set()
    for menu in _CLIENTS:
        for row in ctx.read(menu) or []:
            if allowed_by(ctx.allow, "vpn_clients", row):
                continue
            removed_interfaces.add(row.get("name"))
            ctx.add(_item("vpn_clients", "remove", menu, row, severity="critical",
                          reason="VPN client interface not declared", step=STEP_KITS))

    wireguard = ctx.read("wireguard") or []
    for row in wireguard:
        if not allowed_by(ctx.allow, "wireguard", row):
            removed_interfaces.add(row.get("name"))
    for row in ctx.read("wireguard_peers") or []:
        if row.get("interface") in removed_interfaces or not allowed_by(ctx.allow, "wireguard_peers", row):
            ctx.add(_item("wireguard_peers", "remove", "wireguard_peers", row, severity="critical",
                          name=f"{row.get('interface')}: {_label(row)}",
                          reason="WireGuard peer not declared", step=STEP_KITS))
    for row in static(ctx.read("ip_addresses") or []):
        if row.get("interface") in removed_interfaces:
            ctx.add(_item("ip_addresses", "remove", "ip_addresses", row,
                          name=f"{row.get('address')} on {row.get('interface')}",
                          reason="address on an interface being removed", step=STEP_KITS))
    for row in wireguard:
        if row.get("name") in removed_interfaces:
            ctx.add(_item("wireguard", "remove", "wireguard", row, severity="critical",
                          reason="WireGuard interface not declared", step=STEP_KITS))

    for menu in ("fw_filter", "fw_nat", "fw_mangle", "fw_raw"):
        for row in static(ctx.read(menu) or []):
            if allowed_by(ctx.allow, menu, row):
                continue
            opens = menu == "fw_filter" and row.get("chain") == "input" and row.get("action") == "accept"
            ctx.add(_item(menu, "remove", menu, row,
                          severity="critical" if opens else "warning",
                          reason="rule not declared" + ("; accepts traffic to the router" if opens else ""),
                          step=STEP_KITS))


def _features(ctx):
    for menu, category, severity in (("socks", "socks", "critical"), ("proxy", "proxy", "critical"),
                                     ("traffic_flow", "traffic_flow", "warning")):
        rows = ctx.read(menu)
        if rows and truthy(rows[0].get("enabled", False)) and not ctx.allow.get(category, False):
            ctx.add(_item(category, "set", menu, name=menu.replace("_", "-"),
                          values={"enabled": False}, severity=severity,
                          reason="enabled, not declared", step=STEP_KITS))
    for row in ctx.read("traffic_flow_targets") or []:
        if not allowed_by(ctx.allow, "traffic_flow_targets", row):
            ctx.add(_item("traffic_flow_targets", "remove", "traffic_flow_targets", row,
                          name=f"{row.get('dst-address', row.get('address', '?'))}:{row.get('port', '')}",
                          reason="flow export target not declared", step=STEP_KITS))

    rows = ctx.read("cloud")
    if rows and versions.ddns_enabled(rows[0].get("ddns-enabled")) and not ctx.allow.get("ddns", False):
        off = versions.ddns_off_value(ctx.version)
        ctx.add(_item("ddns", "set", "cloud", name="ip cloud",
                      values={"ddns-enabled": off} if off is not None else {},
                      reason="DDNS on (publishes the router's address)",
                      blocked=(None if off is not None else
                               f"unknown RouterOS version {ctx.version!r}"),
                      step=STEP_KITS))

    rows = ctx.read("dns")
    want = ctx.declared.get("dns") or {}
    if rows:
        row = rows[0]
        values = {}
        if truthy(row.get("allow-remote-requests", False)) != bool(want.get("allow_remote_requests", False)):
            values["allow-remote-requests"] = bool(want.get("allow_remote_requests", False))
        if want.get("servers") and _csv(row.get("servers")) != list(want["servers"]):
            values["servers"] = ",".join(want["servers"])
        if values:
            open_resolver = values.get("allow-remote-requests") is False
            ctx.add(_item("dns", "set", "dns", name="ip dns", values=values,
                          severity="critical" if open_resolver else "warning",
                          reason=("answers DNS for others" if open_resolver else
                                  f"resolvers {row.get('servers') or 'none'}"),
                          step=STEP_KITS))


# ── files ───────────────────────────────────────────────────────────────


def _reference_index(ctx):
    """Every string value of every entry that stays, for 'is this named
    anywhere' checks. Entries being removed do not protect anything."""
    index = []
    for menu, rows in ctx.menus.items():
        if menu in ("files", "history", "active_users"):
            continue
        for row in rows or []:
            if (menu, row.get(".id")) in ctx.removed and row.get(".id") is not None:
                continue
            for key, value in row.items():
                if isinstance(value, str) and value and key != ".id":
                    index.append((menu, _label(row), key, value))
    return index


def _named_by_removed_code(ctx, base):
    """Undeclared schedulers/scripts (being removed) whose body names the file:
    what they fetch or import is the C2 payload."""
    names = []
    for menu, field in (("schedulers", "on-event"), ("scripts", "source")):
        for row in ctx.menus.get(menu) or []:
            if (menu, row.get(".id")) in ctx.removed and _mentions(str(row.get(field, "")), base):
                names.append(f"{menu[:-1]} {row.get('name')}")
    return names


def _mentions(text, base):
    return bool(re.search(r"(^|[\s=\"/,])" + re.escape(base) + r"($|[\s\";,])", text))


def _files(ctx):
    rows = ctx.read("files")
    if rows is None:
        return
    index = _reference_index(ctx)
    certificates = [c.get("name", "") for c in ctx.read("certificates") or []]
    for row in rows:
        kind = str(row.get("type", ""))
        name = str(row.get("name", ""))
        if kind in ("directory", "disk") or not name:
            continue
        if allowed_by(ctx.allow, "files", row):
            continue
        base = name.rsplit("/", 1)[-1]
        label = f"{name} ({kind}, {row.get('size', '?')} B)"
        if kind == "package" or name.endswith(".npk"):
            ctx.add(_item("files", "report", "files", row, name=label, severity="info",
                          reason="package file left in place (staged upgrade?)"))
            continue
        refs = [f"{menu} {entry} ({key})" for menu, entry, key, value in index if _mentions(value, base)]
        if refs:
            ctx.add(_item("files", "report", "files", row, name=label,
                          reason="not declared, kept: named by " + "; ".join(sorted(set(refs))[:3])))
            continue
        if _CERT_FILE.search(name) or ("certificate" in kind and "ssh" not in kind):
            if not any(c.startswith(base) for c in certificates):
                ctx.add(_item("files", "report", "files", row, name=label,
                              reason="certificate or key file not found in /certificate; kept"))
                continue
        hostile_refs = _named_by_removed_code(ctx, base)
        if hostile_refs:
            severity, step = "critical", STEP_PERSISTENCE
            reason = "named by " + ", ".join(hostile_refs) + " (being removed)"
        elif _HOSTILE_FILE.search(name):
            severity, reason, step = "critical", "matches a known payload name", STEP_PERSISTENCE
        elif _SECRET_BEARING_FILE.search(name) or kind == "backup":
            severity, reason, step = "warning", "config export or backup; holds secrets", STEP_FILES
        else:
            severity, reason, step = "info", "regular file", STEP_FILES
        ctx.add(_item("files", "remove", "files", row, name=label, severity=severity,
                      reason=reason, step=step))


# ── logging ─────────────────────────────────────────────────────────────


def _logging(ctx):
    want = ctx.declared.get("syslog") or {}
    actions = ctx.read("logging_actions")
    rules = ctx.read("logging")
    if actions is None or rules is None:
        return
    by_name = {a.get("name"): a for a in actions}
    remote = by_name.get("remote")
    if want.get("target"):
        values = {}
        if remote is None:
            ctx.add(_item("logging", "report", "logging_actions", name="remote",
                          severity="critical", reason="no `remote` logging action; routeros_baseline creates it"))
        else:
            if remote.get("remote") != want["target"]:
                values["remote"] = want["target"]
            if str(remote.get("remote-port", 514)) != str(want.get("port", 514)):
                values["remote-port"] = int(want.get("port", 514))
            if values:
                ctx.add(_item("logging", "set", "logging_actions", remote, values=values,
                              severity="critical",
                              reason=f"remote syslog goes to {remote.get('remote')}, declared {want['target']}",
                              step=STEP_LOGGING))
    memory = by_name.get("memory")
    lines = int(want.get("memory_lines", 1000))
    if memory is not None and int(memory.get("memory-lines", lines)) < lines:
        ctx.add(_item("logging", "set", "logging_actions", memory, values={"memory-lines": lines},
                      severity="critical" if int(memory.get("memory-lines", 0)) <= 10 else "warning",
                      reason=f"memory log cut to {memory.get('memory-lines')} lines",
                      step=STEP_LOGGING))
    for row in actions:
        if truthy(row.get("default", False)) or row.get("name") == "remote":
            continue
        if not allowed_by(ctx.allow, "logging_actions", row):
            ctx.add(_item("logging", "report", "logging_actions", row,
                          reason=f"extra logging action (target {row.get('target')} {row.get('remote', '')})".strip()))

    disk_actions = {a.get("name") for a in actions if a.get("target") == "disk"}
    remote_topics = defaultdict(list)
    for row in rules:
        topics = ",".join(_csv(row.get("topics")))
        if row.get("action") == "remote":
            remote_topics[topics].append(row)
        if truthy(row.get("default", False)):
            if truthy(row.get("disabled", False)):
                ctx.add(_item("logging", "set", "logging", row, name=f"{topics} -> {row.get('action')}",
                              values={"disabled": False}, severity="warning",
                              reason="default logging rule disabled", step=STEP_LOGGING))
            continue
        if row.get("action") in disk_actions and not allowed_by(ctx.allow, "logging_rules", row):
            ctx.add(_item("logging", "remove", "logging", row, name=f"{topics} -> {row.get('action')}",
                          reason="logging to flash, not declared", step=STEP_LOGGING))
    for topic in want.get("topics") or []:
        existing = remote_topics.get(topic, [])
        if not existing:
            ctx.add(_item("logging", "add", "logging", name=f"{topic} -> remote",
                          values={"action": "remote", "topics": topic},
                          reason="remote syslog rule missing", step=STEP_LOGGING))
        elif all(truthy(r.get("disabled", False)) for r in existing):
            ctx.add(_item("logging", "set", "logging", existing[0], name=f"{topic} -> remote",
                          values={"disabled": False}, reason="remote syslog rule disabled",
                          step=STEP_LOGGING))


# ── reports ─────────────────────────────────────────────────────────────


def _identity(ctx):
    want = ctx.declared.get("identity")
    have = ctx.facts.get("identity")
    if want and have is not None and have != want and "identity" not in ctx.errors:
        ctx.add(_item("identity", "set", "identity", name=have or "(empty)", values={"name": want},
                      reason=f"identity {have!r}, declared {want!r}", step=STEP_IDENTITY))


def _version(ctx):
    version = ctx.version
    floor = ctx.declared.get("security_floor") or versions.SECURITY_FLOOR
    target = ctx.declared.get("target_version") or ""
    if not version or versions.parse(version) is None:
        return
    if versions.parse(target) is None:
        target = ""
    if not versions.at_least(version, floor):
        ctx.add(_item("version_below_floor", "report", "resource", name=version, severity="critical",
                      reason=f"RouterOS {version} is below the security floor {floor}"))
    elif target and versions.parse(version) < versions.parse(target):
        ctx.add(_item("version_behind", "report", "resource", name=version,
                      reason=f"RouterOS {version}, fleet target {target}"))
    facts = ctx.facts
    if facts.get("routerboard") and facts.get("firmware_current") and \
            facts.get("firmware_current") != facts.get("firmware_upgrade"):
        ctx.add(_item("routerboot_behind", "report", "routerboard", name=facts["firmware_current"],
                      severity="info",
                      reason=f"RouterBOOT {facts['firmware_current']}, available {facts.get('firmware_upgrade')}"))


def _device_mode(ctx):
    if (ctx.facts.get("device_mode") or {}).get("flagged"):
        ctx.add(_item("device_mode_flagged", "report", "device_mode", name="device-mode",
                      reason=("device-mode flagged: some changes (schedulers, PPTP/L2TP) fail until "
                              "the mode button is pressed on site")))


def _history(ctx):
    rows = ctx.read("history") or []
    hits = [r for r in rows if _BYPASS_TRACE.search(str(r.get("trace", "")))]
    if hits:
        times = sorted(str(r.get("time", "")) for r in hits)
        ctx.add(_item("bypass_signature", "report", "history", name=f"{len(hits)} entries",
                      severity="critical",
                      reason=(f"{len(hits)} history entries made through the SSH auth bypass "
                              f"(trace ssh:-2@), {times[0]} .. {times[-1]}")))


def _certificate(ctx):
    declared = ctx.declared.get("services") or {}
    cert = (declared.get("api-ssl") or {}).get("certificate")
    rows = ctx.read("certificates")
    if cert and rows is not None:
        if not any(c.get("name") == cert and truthy(c.get("private-key", False)) for c in rows):
            ctx.add(_item("api_certificate", "report", "certificates", name=cert,
                          reason="api-ssl certificate missing; routeros_access creates it"))


def _incomplete(ctx):
    failed = sorted(k for k, v in ctx.errors.items() if not _ABSENT.search(v))
    if failed:
        ctx.add(_item("facts_incomplete", "report", "resource", name=", ".join(failed),
                      reason="menus that could not be read; their checks were skipped"))


CHECKS = (_users, _ssh_keys, _sessions,
          lambda c: _code(c, "schedulers", "schedulers", "on-event"),
          lambda c: _code(c, "scripts", "scripts", "source"),
          _services, _ssh, _kits, _features, _logging, _identity,
          # files last: references from entries being removed do not count
          _files,
          _version, _device_mode, _history, _certificate, _incomplete)


def drift(facts, declared):
    """All drift items for one device, in check order."""
    ctx = _Context(facts, declared)
    for check in CHECKS:
        check(ctx)
    return ctx.items
