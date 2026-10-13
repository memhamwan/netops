"""Remediation planner on lab snapshots: the scenarios of the design's Testing
section (heavily compromised, backdoor scheduler, PPTP proxy kit, clean,
edge router)."""
import copy

from conftest import graft, make_declared

from routeros_convergence import plan as planner
from routeros_convergence import policy


def plan_of(facts, **kw):
    return planner.plan(facts, make_declared(facts["host"], **kw))


def order(p, category, action=None):
    return [op["seq"] for op in p["ops"] if op["category"] == category
            and (action is None or op["action"] == action)]


def test_clean_device_plans_nothing(clean):
    p = plan_of(clean)
    assert p["ops"] == [] and p["blocked"] == []


def test_clean_device_with_leftovers_only_loses_regular_files(clean):
    facts = copy.deepcopy(clean)
    facts["menus"]["files"] = [
        {".id": "*1", "name": "flash", "type": "disk"},
        {".id": "*2", "name": "skins", "type": "directory"},
        {".id": "*3", "name": "pub", "type": "directory"},
        {".id": "*4", "name": "turnrye_rsa.pub", "type": "ssh key", "size": 381},
        {".id": "*5", "name": "old-export.rsc", "type": "script", "size": 9000},
        {".id": "*6", "name": "autosupout.rif", "type": ".rif file", "size": 300000},
        {".id": "*7", "name": "capture.pcap", "type": ".pcap file", "size": 4000},
    ]
    p = plan_of(facts)
    assert {op["category"] for op in p["ops"]} == {"files"}
    assert sorted(op["name"].split(" ")[0] for op in p["ops"]) == [
        "autosupout.rif", "capture.pcap", "old-export.rsc", "turnrye_rsa.pub"]
    # disks and directories are never touched, but every regular file is copied off first
    assert set(p["evidence"]["files"]) == {"turnrye_rsa.pub", "old-export.rsc", "autosupout.rif",
                                           "capture.pcap"}


def test_rogue_factory_admin_is_removed(clean):
    p = planner.plan(clean, make_declared(clean["host"], allow={"users": []}))
    assert [op["name"] for op in p["ops"]] == ["admin"]


def test_heavily_compromised_order(compromised):
    p = plan_of(compromised)
    steps = [op["step"] for op in p["ops"]]
    assert steps == sorted(steps), "steps out of order"
    seq = {op["name"]: op["seq"] for op in p["ops"]}
    # schedulers go before the files they fetch, so nothing re-fetches them
    assert seq["backup-sync"] < seq["sync.rsc (script, 29 B)"]
    # keys before accounts
    assert max(order(p, "ssh_keys")) < min(order(p, "users"))
    # server stops pointing at the profile, then account -> profile -> pool
    pptp = order(p, "vpn_servers")
    assert pptp == sorted(pptp)
    assert p["ops"][pptp[0] - 1]["values"] == {"default-profile": "default-encryption"}
    assert max(pptp) < order(p, "ppp_secrets")[0] < order(p, "ppp_profiles")[0] < order(p, "ip_pools")[0]
    # peers -> addresses -> interface
    assert order(p, "wireguard_peers")[0] < order(p, "ip_addresses")[0] < order(p, "wireguard")[0]
    # logging is restored last
    assert p["ops"][-1]["step"] == policy.STEP_LOGGING
    assert p["summary"]["ops"] == len(p["ops"]) == 45


def test_backdoor_scheduler_device(clean, compromised):
    facts = graft(clean, compromised, ["schedulers", "files", "users", "ssh_keys"])
    p = plan_of(facts)
    first = [op for op in p["ops"] if op["step"] == policy.STEP_PERSISTENCE]
    assert [op["name"] for op in first[:2]] == ["backup-sync", "cfg-check"]
    assert {op["name"].split(" ")[0] for op in first[2:]} == {"setup.sh", "sync.rsc", "redtail.arm7", "ntp.pub"}


def test_pptp_proxy_device(clean, compromised):
    facts = graft(clean, compromised, ["ppp_secrets", "ppp_profiles", "ip_pools", "pptp_server",
                                       "fw_nat", "cloud"])
    p = plan_of(facts)
    assert [(op["category"], op["action"]) for op in p["ops"]] == [
        ("vpn_servers", "set"), ("vpn_servers", "set"), ("ppp_secrets", "remove"),
        ("ppp_profiles", "remove"), ("ip_pools", "remove"), ("fw_nat", "remove"), ("ddns", "set")]


def test_edge_router_with_allowances_plans_nothing(edge):
    allow = {
        "fw_filter": ["~^edge-", {"chain": "forward", "action": "accept", "protocol": "gre"}],
        "fw_nat": ["wg-mgmt clients"], "ppp_secrets": ["*"], "ppp_profiles": ["mhw-sstp"],
        "vpn_servers": ["sstp"], "wireguard": ["wg-mgmt"], "wireguard_peers": ["~^operator-"],
    }
    assert plan_of(edge, allow=allow)["ops"] == []


def test_blocked_changes_stay_out_of_the_ops(compromised):
    facts = copy.deepcopy(compromised)
    facts["menus"]["ssh_keys"] = [k for k in facts["menus"]["ssh_keys"] if k["user"] != "ae5au"]
    p = plan_of(facts)
    assert [b["category"] for b in p["blocked"]] == ["ssh_password_login"]
    assert not [op for op in p["ops"] if "password-authentication" in op["values"]]


def test_api_ssl_allow_list_change_goes_last(compromised):
    facts = copy.deepcopy(compromised)
    for row in facts["menus"]["services"]:
        if row["name"] == "api-ssl" and not row.get("dynamic"):
            row["available-from"] = ""
    p = plan_of(facts)
    assert p["ops"][-1]["name"] == "api-ssl" and p["ops"][-1]["last"] is True


def test_export_references_block_files_still_in_use():
    export = "\n".join([
        "# 2026-10-13 by RouterOS 7.24.5",
        '/system logging action add disk-file-name=flash/applog name=applog target=disk',
        '/user ssh-keys import public-key-file=ops.pub user=ops',
        '/import file-name=cfg-sync.rsc',
        '/ip hotspot profile set [ find default=yes ] html-directory=hotspot',
    ])
    found = planner.export_references(export, ["ops.pub", "cfg-sync.rsc", "unrelated.txt", "flash/applog"])
    assert set(found) == {"ops.pub", "cfg-sync.rsc", "flash/applog"}


def test_render_text_numbers_ops_in_order(compromised):
    text = planner.render_text(plan_of(compromised))
    assert text.splitlines()[0].startswith("chr-b.lab.memhamwan.net  RouterOS 7.24.5  45 change(s)")
    assert "  -- step 1: persistence" in text and "    1. system scheduler: backup-sync -> remove" in text
