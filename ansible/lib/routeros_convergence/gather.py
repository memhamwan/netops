"""Read a device over the RouterOS API (read-only).

Every menu the audit and the remediation planner need is read in one
session. A menu the device lacks (WireGuard before 7.x, reverse-proxy before
7.22, ...) is recorded in `errors`, not raised: the snapshot of an old or
odd device is still useful. Secrets are redacted before anything is returned.
"""
import re
import ssl

# key, API path, fields to request (None = all). Lists of rows throughout,
# single-value menus included (one row).
READ_PATHS = (
    ("resource", ("system", "resource"), None),
    ("routerboard", ("system", "routerboard"), None),
    ("device_mode", ("system", "device-mode"), None),
    ("identity", ("system", "identity"), None),
    ("packages", ("system", "package"), None),
    ("users", ("user",), None),
    ("user_groups", ("user", "group"), None),
    ("ssh_keys", ("user", "ssh-keys"), None),
    ("active_users", ("user", "active"), None),
    ("services", ("ip", "service"), None),
    ("ssh", ("ip", "ssh"), None),
    ("certificates", ("certificate",),
     (".id", "name", "common-name", "private-key", "key-usage", "invalid-after", "trusted")),
    ("schedulers", ("system", "scheduler"), None),
    ("scripts", ("system", "script"), None),
    # never `contents`: small text files carry it inline, and it can be anything
    ("files", ("file",), (".id", "name", "type", "size", "last-modified", "creation-time")),
    ("ppp_secrets", ("ppp", "secret"), None),
    ("ppp_profiles", ("ppp", "profile"), None),
    ("ip_pools", ("ip", "pool"), None),
    ("dhcp_servers", ("ip", "dhcp-server"), None),
    ("ip_addresses", ("ip", "address"), None),
    ("pptp_server", ("interface", "pptp-server", "server"), None),
    ("l2tp_server", ("interface", "l2tp-server", "server"), None),
    ("sstp_server", ("interface", "sstp-server", "server"), None),
    ("ovpn_server", ("interface", "ovpn-server", "server"), None),
    ("pptp_clients", ("interface", "pptp-client"), None),
    ("l2tp_clients", ("interface", "l2tp-client"), None),
    ("sstp_clients", ("interface", "sstp-client"), None),
    ("ovpn_clients", ("interface", "ovpn-client"), None),
    ("wireguard", ("interface", "wireguard"), None),
    ("wireguard_peers", ("interface", "wireguard", "peers"), None),
    ("fw_filter", ("ip", "firewall", "filter"), None),
    ("fw_nat", ("ip", "firewall", "nat"), None),
    ("fw_mangle", ("ip", "firewall", "mangle"), None),
    ("fw_raw", ("ip", "firewall", "raw"), None),
    ("socks", ("ip", "socks"), None),
    ("proxy", ("ip", "proxy"), None),
    ("traffic_flow", ("ip", "traffic-flow"), None),
    ("traffic_flow_targets", ("ip", "traffic-flow", "target"), None),
    ("cloud", ("ip", "cloud"), None),
    ("dns", ("ip", "dns"), None),
    ("ntp_client", ("system", "ntp", "client"), None),
    ("logging", ("system", "logging"), None),
    ("logging_actions", ("system", "logging", "action"), None),
    ("history", ("system", "history"), None),
    ("romon", ("tool", "romon"), None),
    ("poe", ("interface", "ethernet", "poe"), None),
)

# Values that are secrets wherever they appear.
REDACT_FIELDS = frozenset((
    "password", "private-key", "preshared-key", "ipsec-secret", "secret",
    "secrets", "passphrase", "auth-key", "authentication-key",
    "wpa-pre-shared-key", "wpa2-pre-shared-key", "contents",
))
# Free-text fields (scheduler/script bodies, history) keep their shape for the
# audit's signature checks, minus inline credentials.
SCRUB_FIELDS = frozenset(("on-event", "source", "redo", "undo"))
_INLINE_SECRET = re.compile(
    r"((?:password|passwd|secret|private-key|preshared-key|wpa2?-pre-shared-key|auth-key)=)"
    r"(\"(?:[^\"\\]|\\.)*\"|\S+)",
    re.IGNORECASE,
)
REDACTED = "<redacted>"

# History is kept bounded: newest entries, each field capped.
HISTORY_KEEP = 300
TEXT_CAP = 2000


def scrub(text):
    """Blank inline credentials (password=..., secret=...) in RouterOS script text."""
    return _INLINE_SECRET.sub(lambda m: m.group(1) + REDACTED, text)


def redact_row(row):
    out = {}
    for key, value in row.items():
        # strings only: the same names are booleans elsewhere (a certificate's
        # `private-key` says whether it has one)
        if key in REDACT_FIELDS and isinstance(value, str) and value != "":
            out[key] = REDACTED
        elif key in SCRUB_FIELDS and isinstance(value, str):
            out[key] = scrub(value)[:TEXT_CAP]
        else:
            out[key] = value
    return out


def connect(host, username, password, port=8729, tls=True, timeout=30):
    """Open an API session. TLS without certificate validation: devices carry
    per-device self-signed certificates until the internal CA exists."""
    import librouteros

    kwargs = {"port": int(port), "timeout": float(timeout), "encoding": "latin-1"}
    if tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        # RouterOS self-signed certificates use 2048-bit RSA + SHA-256; older
        # builds negotiate ciphers OpenSSL's default level refuses
        ctx.set_ciphers("DEFAULT:@SECLEVEL=1")
        kwargs["ssl_wrapper"] = ctx.wrap_socket
    return librouteros.connect(host, username, password, **kwargs)


def read_all(api, paths=READ_PATHS):
    """Read every menu; returns (rows by key, error text by key)."""
    from librouteros.query import Key

    rows, errors = {}, {}
    for key, path, fields in paths:
        try:
            menu = api.path(*path)
            result = menu.select(*(Key(f) for f in fields)) if fields else menu
            rows[key] = [redact_row(dict(r)) for r in result]
        except Exception as exc:  # TrapError for absent menus, timeouts, ...
            errors[key] = f"{type(exc).__name__}: {exc}"
    if "history" in rows:
        rows["history"] = rows["history"][:HISTORY_KEEP]
    return rows, errors
