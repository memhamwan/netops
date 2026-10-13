"""Shared helpers for the routeros_convergence tests.

Fixtures under fixtures/ are real snapshots of the RouterOS 7.24.5 lab
(tests/lab): `clean` is an onboarded device, `compromised` carries the
September 2026 artifacts, `edge` carries legitimate edge-router config.
Secrets were redacted at read time; they hold lab values only.
"""
import copy
import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "ansible" / "lib"))

from routeros_convergence import declared as declared_mod  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures"
KEYS = REPO / "ansible" / "roles" / "routeros_baseline" / "files"
SERVICE_ACCOUNTS = [
    {"name": "ansible", "group": "netops-ansible", "keys": ["ansible.pub"]},
    {"name": "oxidized", "group": "netops-backup-ro", "keys": ["oxidized.pub"]},
    {"name": "oxidized-full", "group": "netops-backup-full", "keys": ["oxidized-full.pub"]},
    {"name": "mktxp", "group": "mktxp_group", "keys": []},
]
OPERATORS = ["turnrye", "seichold", "ae5au"]


def load(name):
    with open(FIXTURES / f"{name}.json") as fh:
        return json.load(fh)


def make_declared(host, allow=None, **overrides):
    """The fleet's declared state as group_vars builds it, pointed at the lab
    (collector 10.0.2.2, controller seen from 10.0.2.0/24)."""
    want = {
        "host": host,
        "identity": host,
        "accounts": declared_mod.declare_accounts(SERVICE_ACCOUNTS, OPERATORS, str(KEYS)),
        "services": {"ssh": {"port": 222}, "api-ssl": {"port": 8729, "certificate": "api-ssl"}},
        "management_sources": ["44.34.128.45/32", "10.0.2.0/24"],
        "ssh": {"password_login": False, "forwarding": False, "strong_crypto": True},
        "dns": {"servers": ["44.34.132.1", "44.34.133.1", "1.1.1.1", "1.0.0.1"],
                "allow_remote_requests": False},
        "syslog": {"target": "10.0.2.2", "port": 514,
                   "topics": ["system", "error", "warning", "critical", "account"],
                   "memory_lines": 1000},
        "target_version": "",
        "security_floor": "7.24.2",
        # admin drives the lab VMs; on the fleet it is retired
        "allow": {"users": ["admin"], **(allow or {})},
    }
    want.update(overrides)
    return want


def as_717(facts):
    """Rewrite a 7.24.5 snapshot into the shape RouterOS 7.17 returns (seen in
    the 2026-10-13 evidence): `address` on /ip service, no key fingerprints
    and `key-owner` instead of `info`, `always-allow-password-login`,
    boolean-era DDNS reporting, no dynamic service rows."""
    old = copy.deepcopy(facts)
    old["version"] = "7.17"
    menus = old["menus"]
    menus["resource"][0]["version"] = "7.17 (stable)"
    services = []
    for row in menus["services"]:
        if row.get("dynamic"):
            continue
        row = {("address" if k == "available-from" else k): v for k, v in row.items()
               if k not in ("proto", "dynamic")}
        services.append(row)
    menus["services"] = services
    for row in menus["ssh_keys"]:
        row.pop("fingerprint", None)
        row["key-owner"] = row.pop("info", "")
    ssh = menus["ssh"][0]
    ssh["always-allow-password-login"] = ssh.pop("password-authentication") not in (False, "no")
    ssh.pop("publickey-authentication-options", None)
    return old


SINGLE_VALUE = {"ssh", "cloud", "dns", "socks", "proxy", "traffic_flow",
                "pptp_server", "l2tp_server", "sstp_server"}


def graft(base, donor, menus):
    """`base` with `donor`'s state in the given menus: one attack pattern on
    an otherwise clean device. Single-value menus are taken whole; list menus
    gain the donor's rows that base does not have (same baseline, same ids)."""
    out = copy.deepcopy(base)
    for menu in menus:
        rows = copy.deepcopy(donor["menus"].get(menu, []))
        if menu in SINGLE_VALUE:
            out["menus"][menu] = rows
        else:
            have = {r.get(".id") for r in base["menus"].get(menu, [])}
            out["menus"][menu] = out["menus"].get(menu, []) + [r for r in rows if r.get(".id") not in have]
    return out


@pytest.fixture
def clean():
    return load("lab-clean-7.24.5")


@pytest.fixture
def compromised():
    return load("lab-compromised-7.24.5")


@pytest.fixture
def edge():
    return load("lab-edge-7.24.5")
