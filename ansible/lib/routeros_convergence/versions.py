"""RouterOS version parsing and the property names that differ by version.

Property names are chosen from what the device actually returns wherever
possible (e.g. a service row carrying `available-from`); the version
thresholds here cover writes where nothing can be read first.
"""
import re

_VERSION = re.compile(r"^\s*(\d+)\.(\d+)(?:\.(\d+))?(?:(alpha|beta|rc)(\d+))?")
_PRE_RANK = {"alpha": 0, "beta": 1, "rc": 2, None: 3}


def parse(version):
    """'7.24.5 (stable)' -> (7, 24, 5, 3, 0); pre-releases sort below the release.

    Returns None for anything that is not a RouterOS version.
    """
    if version is None:
        return None
    match = _VERSION.match(str(version))
    if not match:
        return None
    major, minor, patch, pre, pre_n = match.groups()
    return (int(major), int(minor), int(patch or 0), _PRE_RANK[pre], int(pre_n or 0))


def number(version):
    """'7.24.5 (stable)' -> '7.24.5'; '' when unparseable."""
    if version is None:
        return ""
    match = _VERSION.match(str(version))
    return match.group(0).strip() if match else ""


def channel(version):
    """'7.24.5 (stable)' -> 'stable'; '' when the version carries none."""
    match = re.search(r"\(([^)]+)\)", str(version or ""))
    return match.group(1) if match else ""


def at_least(version, floor):
    """True when version >= floor. Unparseable versions are never at least anything."""
    have, want = parse(version), parse(floor)
    if have is None or want is None:
        return False
    return have >= want


# /ip ssh: password login switch. `password-authentication` (yes / no /
# yes-if-no-key) replaced `always-allow-password-login` in 7.21; there is no
# way to refuse password login outright before that.
SSH_PASSWORD_AUTH_SINCE = "7.21"

def ddns_off_value(version):
    """Value that turns /ip cloud DDNS off, or None for an unknown version.

    Boolean before 7.17. From 7.17 the property takes only `yes` or `auto`
    (`no` is "invalid value ... must be either yes or auto": seen live on
    7.17 and in the 7.24.5 lab), and `auto` keeps DDNS off unless
    back-to-home VPN is enabled.
    """
    parsed = parse(version)
    if parsed is None:
        return None
    return False if parsed[:2] < (7, 17) else "auto"


def ddns_enabled(value):
    """True when a read ddns-enabled value means DDNS is on. `auto` only
    enables it for back-to-home, which nothing here uses, so it counts as off."""
    return value is True or str(value).lower() in ("yes", "true")


# Fixed in 7.24.2 stable, 7.23.4 long-term, 6.49.21: CVE-2026-67279/67276
# (SSH authentication bypass). The fleet floor is the stable fix.
SECURITY_FLOOR = "7.24.2"


def service_source_key(row, version=None):
    """Name of the allow-list property on an /ip service row.

    7.24 renamed `address` to `available-from` (it still accepts `address`
    as a write alias but only ever returns `available-from`). Prefer what the
    row itself carries; fall back to the version.
    """
    if row is not None:
        if "available-from" in row:
            return "available-from"
        if "address" in row:
            return "address"
    return "available-from" if at_least(version, "7.24") else "address"
