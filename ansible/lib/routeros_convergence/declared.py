"""Declared state helpers: key fingerprints and allowance matching.

The declared state is built in Ansible (inventory group_vars/host_vars) and
handed over as a dict:

    {host, identity, lifecycle,
     accounts: [{name, group, kind, keys: [{type, fingerprint, comment}]}],
     services: {name: {port, certificate?}},   # the ONLY services enabled
     management_sources: [cidr],
     ssh: {password_login: bool, forwarding: bool, strong_crypto: bool},
     dns: {servers: [ip], allow_remote_requests: bool},
     ddns: bool,
     syslog: {target, port, topics: [..], memory_lines: int},
     target_version, security_floor,
     allow: {category: [allowance]}}

An allowance is a string (exact name, else exact comment), '~regex'
(searched in name and comment), '*' (everything in the category), or a dict
of field values that must all match the entry.
"""
import base64
import hashlib
import re

ALLOW_CATEGORIES = (
    "users", "schedulers", "scripts", "files", "services",
    "ppp_secrets", "ppp_profiles", "ip_pools",
    "vpn_servers", "vpn_clients", "wireguard", "wireguard_peers",
    "fw_filter", "fw_nat", "fw_mangle", "fw_raw",
    "logging_actions", "logging_rules", "traffic_flow_targets",
    # booleans: features a device may legitimately run
    "socks", "proxy", "traffic_flow", "ddns",
)
BOOLEAN_ALLOWANCES = ("socks", "proxy", "traffic_flow", "ddns")


def pubkey_fingerprint(line):
    """OpenSSH public key line -> {type, fingerprint: 'SHA256:...', comment}.

    Same value `ssh-keygen -lf` prints and RouterOS 7.24+ shows in
    /user ssh-keys: unpadded base64 of SHA-256 over the decoded key blob.
    """
    parts = line.strip().split(None, 2)
    if len(parts) < 2:
        raise ValueError("not an OpenSSH public key line")
    blob = base64.b64decode(parts[1])
    digest = base64.b64encode(hashlib.sha256(blob).digest()).decode()
    return {
        "type": parts[0],
        "fingerprint": fingerprint("SHA256:" + digest),
        "comment": parts[2].strip() if len(parts) > 2 else "",
    }


def fingerprint(value):
    """Comparable form of a key fingerprint: RouterOS prints the base64 with
    its `=` padding, ssh-keygen without."""
    return str(value or "").strip().rstrip("=")


def _keys_from(paths):
    keys = []
    for path in paths:
        with open(path) as fh:
            for line in fh:
                if line.strip() and not line.startswith("#"):
                    keys.append(pubkey_fingerprint(line))
    return keys


def declare_accounts(service_accounts, operators, keys_dir):
    """Accounts every device may have, with the fingerprints of their keys.

    Service account keys are files named in the entry (`keys: [ansible.pub]`)
    under keys_dir; operators' keys are keys_dir/operators/<name>_*.pub, all
    of them. Operators are group `full`. Raises ValueError on a missing key
    file or a name declared twice.
    """
    import glob
    import os

    accounts = []
    for entry in service_accounts or []:
        paths = [os.path.join(keys_dir, k) for k in entry.get("keys") or []]
        missing = [p for p in paths if not os.path.isfile(p)]
        if missing:
            raise ValueError(f"key file(s) for {entry['name']} not found: {', '.join(missing)}")
        accounts.append({"name": entry["name"], "group": entry["group"], "kind": "service",
                         "keys": _keys_from(paths)})
    for name in operators or []:
        paths = sorted(glob.glob(os.path.join(keys_dir, "operators", f"{name}_*.pub")))
        accounts.append({"name": name, "group": "full", "kind": "operator",
                         "keys": _keys_from(paths)})
    names = [a["name"] for a in accounts]
    duplicates = sorted({n for n in names if names.count(n) > 1})
    if duplicates:
        raise ValueError(f"accounts declared twice: {', '.join(duplicates)}")
    return accounts


def _field(row, key):
    value = row.get(key)
    if isinstance(value, bool):
        return "true" if value else "false"
    return "" if value is None else str(value)


def allowance_matches(allowance, row):
    """True when one allowance admits the row (see module docstring)."""
    if isinstance(allowance, dict):
        return all(_field(row, k) == (str(v).lower() if isinstance(v, bool) else str(v))
                   for k, v in allowance.items())
    text = str(allowance)
    if text == "*":
        return True
    name, comment = _field(row, "name"), _field(row, "comment")
    if text.startswith("~"):
        pattern = re.compile(text[1:])
        return bool(pattern.search(name) or pattern.search(comment))
    return text == name or (text == comment and comment != "")


def allowed_by(allow, category, row):
    """The first allowance in `category` that admits the row, else None."""
    for allowance in (allow or {}).get(category) or []:
        if allowance_matches(allowance, row):
            return allowance
    return None


def validate(declared):
    """Problems with a declared state (empty list = usable)."""
    problems = []
    for key in ("host", "accounts", "services", "management_sources"):
        if key not in declared:
            problems.append(f"declared state lacks `{key}`")
    for category in (declared.get("allow") or {}):
        if category not in ALLOW_CATEGORIES:
            problems.append(
                f"routeros_allow has unknown category `{category}` "
                f"(known: {', '.join(ALLOW_CATEGORIES)})")
    for category in BOOLEAN_ALLOWANCES:
        value = (declared.get("allow") or {}).get(category)
        if value is not None and not isinstance(value, bool):
            problems.append(f"routeros_allow.{category} must be true or false")
    for source in declared.get("management_sources") or []:
        if not re.match(r"^([0-9]{1,3}[.]){3}[0-9]{1,3}/[0-9]{1,2}$", str(source)):
            problems.append(f"management source {source!r} is not an IPv4 CIDR")
    return problems
