"""The drift policy against real lab snapshots (tests/lab, RouterOS 7.24.5)."""
import copy

from conftest import as_717, make_declared

from routeros_convergence import policy


def drift(facts, **kw):
    return policy.drift(facts, make_declared(facts["host"], **kw))


def names(items, category, action=None):
    return sorted(i["name"] for i in items
                  if i["category"] == category and (action is None or i["action"] == action))


def actionable(items):
    return [i for i in items if i["action"] != "report"]


def test_clean_device_has_no_drift(clean):
    assert drift(clean) == []


def test_compromised_accounts_and_keys(compromised):
    items = drift(compromised)
    assert names(items, "users", "remove") == ["admin1", "routeradmin", "support", "xadmqzpk"]
    keys = [i for i in items if i["category"] == "ssh_keys"]
    assert sorted(i["name"] for i in keys) == ["support: ed25519 ntp-service", "turnrye: ed25519 ops@hermes"]
    assert all(i["action"] == "remove" and i["severity"] == "critical" for i in keys)
    # the operator's own keys stay: only the undeclared one goes
    assert not [i for i in keys if "turnrye@lappy" in i["name"]]


def test_compromised_persistence_is_critical_and_first(compromised):
    items = drift(compromised)
    by_name = {i["name"]: i for i in items}
    for scheduler in ("backup-sync", "cfg-check"):
        assert by_name[scheduler]["severity"] == "critical"
        assert by_name[scheduler]["step"] == policy.STEP_PERSISTENCE
    # files the C2 schedulers fetch/import, and known payloads
    c2 = [i for i in items if i["category"] == "files" and i["step"] == policy.STEP_PERSISTENCE]
    assert sorted(i["name"].split(" ")[0] for i in c2) == ["ntp.pub", "redtail.arm7", "setup.sh", "sync.rsc"]
    # leftovers and backups are removed later, not first
    later = {i["name"].split(" ")[0]: i for i in items
             if i["category"] == "files" and i["step"] == policy.STEP_FILES}
    assert set(later) == {"c6f53c3e.backup", "turnrye_rsa.pub"}
    assert later["c6f53c3e.backup"]["severity"] == "warning"


def test_compromised_services(compromised):
    items = drift(compromised)
    svc = {i["name"]: i for i in items if i["category"] == "services"}
    assert set(svc) == {"api", "ftp", "telnet", "winbox", "www"}
    assert all(i["values"] == {"disabled": True} and i["severity"] == "critical" for i in svc.values())
    ssh = [i for i in items if i["category"] in ("ssh_password_login", "ssh_settings")]
    assert {k: v for i in ssh for k, v in i["values"].items()} == {
        "password-authentication": "no", "forwarding-enabled": "no"}
    assert all(i["blocked"] is None for i in ssh)


def test_compromised_kits(compromised):
    items = drift(compromised)
    assert names(items, "ppp_secrets", "remove") == ["fn"]
    assert names(items, "ppp_profiles", "remove") == ["ZPPTP"]
    assert names(items, "ip_pools", "remove") == ["P00LTP"]
    pptp = [i for i in items if i["menu"] == "pptp_server"]
    assert {k: v for i in pptp for k, v in i["values"].items()} == {
        "enabled": False, "default-profile": "default-encryption"}
    assert names(items, "wireguard", "remove") == ["wg-x"]
    assert names(items, "wireguard_peers", "remove") == ["wg-x: peer1"]
    assert names(items, "ip_addresses", "remove") == ["10.200.0.1/24 on wg-x"]
    assert names(items, "fw_filter", "remove") == ["x-mgmt-0", "x-mgmt-1", "x-mgmt-2"]
    assert names(items, "fw_nat", "remove") == ["Internet"]
    ddns = [i for i in items if i["category"] == "ddns"][0]
    assert ddns["values"] == {"ddns-enabled": "auto"}
    for feature in ("socks", "traffic_flow"):
        assert [i["values"] for i in items if i["category"] == feature] == [{"enabled": False}]
    dns = [i for i in items if i["category"] == "dns"][0]
    assert dns["values"] == {"allow-remote-requests": False,
                             "servers": "44.34.132.1,44.34.133.1,1.1.1.1,1.0.0.1"}


def test_compromised_logging_restored(compromised):
    items = [i for i in drift(compromised) if i["category"] == "logging"]
    by_name = {i["name"]: i for i in items}
    assert by_name["remote"]["values"] == {"remote": "10.0.2.2"}
    assert by_name["memory"]["values"] == {"memory-lines": 1000}
    assert by_name["memory"]["severity"] == "critical"
    assert {i["name"] for i in items if i["values"] == {"disabled": False}} == {
        "info -> memory", "error -> memory", "warning -> memory"}
    assert names(items, "logging", "remove") == ["info -> disk"]


def test_steps_and_ids_on_every_actionable_item(compromised):
    for item in actionable(drift(compromised)):
        assert item["step"] in range(policy.STEP_PERSISTENCE, policy.STEP_IDENTITY + 1)
        if item["action"] == "remove":
            assert item["id"], item
            assert item["expect"], item  # the executor re-checks these


def test_edge_router_keeps_everything_declared(edge):
    allow = {
        "fw_filter": ["~^edge-", {"chain": "forward", "action": "accept", "protocol": "gre"}],
        "fw_nat": ["wg-mgmt clients"],
        "ppp_secrets": ["*"],
        "ppp_profiles": ["mhw-sstp"],
        "vpn_servers": ["sstp"],
        "wireguard": ["wg-mgmt"],
        "wireguard_peers": ["~^operator-"],
    }
    assert actionable(drift(edge, allow=allow)) == []


def test_edge_router_without_allowances_shows_the_gaps(edge):
    items = drift(edge)
    # plan mode is how undeclared legitimate config is found before apply
    assert names(items, "ppp_secrets", "remove") == ["ftn-sstp", "operator-1", "sco-sstp"]
    assert names(items, "wireguard", "remove") == ["wg-mgmt"]


def test_profiles_and_pools_used_by_kept_accounts_stay(compromised):
    items = drift(compromised, allow={"ppp_secrets": ["fn"]})
    assert names(items, "ppp_profiles", "remove") == []
    assert names(items, "ip_pools", "remove") == []
    assert [i["reason"] for i in items if i["category"] == "ppp_profiles"] == [
        "not declared, kept: a declared PPP account uses it"]


def test_file_named_by_a_kept_scheduler_stays(compromised):
    items = drift(compromised, allow={"schedulers": ["backup-sync"]})
    sync = [i for i in items if i["name"].startswith("sync.rsc")][0]
    assert sync["action"] == "report"
    assert "named by schedulers backup-sync" in sync["reason"]


def test_disabled_undeclared_account_is_still_removed(clean):
    facts = copy.deepcopy(clean)
    facts["menus"]["users"].append({".id": "*99", "name": "hamwan", "group": "full", "disabled": True})
    item = [i for i in drift(facts) if i["category"] == "users"][0]
    assert item["name"] == "hamwan" and item["action"] == "remove"
    assert "disabled" in item["reason"]


def test_password_login_blocked_while_an_ssh_account_has_no_key(compromised):
    facts = copy.deepcopy(compromised)
    facts["menus"]["ssh_keys"] = [k for k in facts["menus"]["ssh_keys"] if k["user"] != "seichold"]
    item = [i for i in drift(facts) if i["category"] == "ssh_password_login" and i["action"] == "set"][0]
    assert item["blocked"] and "seichold" in item["blocked"]


def test_unreadable_menu_skips_its_checks(clean):
    facts = copy.deepcopy(clean)
    facts["errors"]["users"] = "TrapError: not enough permissions (9)"
    del facts["menus"]["users"]
    items = drift(facts)
    assert [i["category"] for i in items] == ["facts_incomplete"]


def test_717_shapes(compromised):
    items = drift(as_717(compromised))
    floor = [i for i in items if i["category"] == "version_below_floor"]
    assert floor and floor[0]["severity"] == "critical"
    # no fingerprints before 7.24: the extra operator key shows as a count
    counted = [i for i in items if i["category"] == "ssh_keys" and i["action"] == "report"]
    assert [i["name"] for i in counted] == ["turnrye"]
    # attacker accounts' keys are still removable by user
    assert names(items, "ssh_keys", "remove") == ["support: ed25519 ntp-service"]
    # old property names
    pw = [i for i in items if i["category"] == "ssh_password_login" and i["action"] == "set"][0]
    assert pw["values"] == {"always-allow-password-login": False}
    svc = {i["name"]: i for i in items if i["category"] == "services"}
    assert svc["telnet"]["values"] == {"disabled": True}
    assert [i["values"] for i in items if i["category"] == "ddns"] == [{"ddns-enabled": "auto"}]


def test_717_service_acl_uses_address(clean):
    facts = as_717(clean)
    ssh = [r for r in facts["menus"]["services"] if r["name"] == "ssh"][0]
    ssh["address"] = ""
    item = [i for i in drift(facts) if i["category"] == "services"][0]
    assert item["values"] == {"address": "44.34.128.45/32,10.0.2.0/24"}
    assert item["severity"] == "critical"  # SSH open to every address


def test_api_ssl_acl_change_is_marked_last(clean):
    facts = copy.deepcopy(clean)
    api = [r for r in facts["menus"]["services"] if r["name"] == "api-ssl" and not r.get("dynamic")][0]
    api["available-from"] = "0.0.0.0/0"
    item = [i for i in drift(facts) if i["category"] == "services"][0]
    assert item["last"] is True


def test_bypass_signature_in_history(clean):
    facts = copy.deepcopy(clean)
    facts["menus"]["history"].insert(0, {".id": "*F0", "action": "user added", "by": 0,
                                         "time": "2026-09-02 10:00:00",
                                         "trace": "ssh:-2@192.0.2.66/action:3"})
    hits = [i for i in drift(facts) if i["category"] == "bypass_signature"]
    assert hits and hits[0]["severity"] == "critical"


def test_target_version_behind(clean):
    items = drift(clean, target_version="7.25")
    assert [i["category"] for i in items] == ["version_behind"]
