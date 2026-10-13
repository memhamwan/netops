import re

from conftest import make_declared

from routeros_convergence import audit, gather, romon


def test_report_counts_and_state(compromised):
    rep = audit.report(compromised, make_declared(compromised["host"]))
    assert rep["worst"] == "critical"
    assert rep["counts"]["critical"] == sum(1 for f in rep["findings"] if f["severity"] == "critical")
    state = rep["state"]
    assert "support" in state["users"] and state["pptp_server"] is True
    assert state["syslog"] == "0.0.0.0" and state["memory_lines"] == 1
    assert state["ssh_keys"]["turnrye"] == 3


def test_metrics_are_zero_filled_counts_without_names(compromised, clean):
    reports = [audit.report(f, make_declared(f["host"])) for f in (compromised, clean)]
    text = audit.metrics(reports, {"r9.xyz.memhamwan.net": "TimeoutError"}, now=1760000000)
    lines = text.splitlines()
    # every device exports every check and severity, zeros included
    assert sum(1 for line in lines if line.startswith('routeros_audit_check_findings{device="chr-a.lab"')) \
        == len(audit.CHECKS)
    assert 'routeros_audit_findings{device="chr-a.lab",severity="critical"} 0' in lines
    assert 'routeros_audit_up{device="r9.xyz"} 0' in lines
    # Grafana is public: no account names, addresses or file names in metrics
    for leak in ("support", "routeradmin", "10.0.2.2", "redtail", "192.0.2", "fn"):
        assert not re.search(r'[{,"=]' + re.escape(leak), text.replace("chr-", "")), leak
    assert set(audit.CHECKS) >= {i["category"] for r in reports for i in r["findings"]}


def test_redaction():
    row = gather.redact_row({"name": "fn", "password": "123123", "private-key": True,
                             "on-event": '/tool fetch url="http://x/y" password="hunter2" user=a',
                             "contents": "secret file body"})
    assert row["password"] == gather.REDACTED and row["contents"] == gather.REDACTED
    assert row["private-key"] is True  # a certificate flag, not a key
    assert "hunter2" not in row["on-event"] and "/tool fetch" in row["on-event"]


def test_romon_rows_match_inventory():
    rows = [romon.normalize({"address": "52:54:00:03:00:01", "identity": "r1.ftn.memhamwan.net",
                             "version": "7.24.4", "board": "RB912", "hops": 4}),
            romon.normalize({"address": "52:54:00:03:00:02", "identity": "sec2.mno",
                             "version": "6.49.4", "board": "RB411", "hops": 7})]
    matched, unmatched = romon.match_inventory(rows, ["r1.ftn.memhamwan.net"])
    assert matched["r1.ftn.memhamwan.net"]["version"] == "7.24.4"
    assert [r["identity"] for r in unmatched] == ["sec2.mno"]


def test_fleet_view_combines_audit_romon_and_probes(clean):
    entries = [
        {"host": clean["host"], "lifecycle": "active", "report": audit.report(clean, make_declared(clean["host"]))},
        {"host": "r1.ftn.memhamwan.net", "lifecycle": "quarantined", "report": None, "error": ""},
    ]
    view = audit.fleet(entries,
                       [romon.normalize({"identity": "r1.ftn", "version": "7.17", "hops": 4})],
                       [{"name": "r1.ftn.memhamwan.net", "open": [1723, 8729]}])
    rows = {r["host"]: r for r in view["rows"]}
    assert rows["r1.ftn.memhamwan.net"]["version"] == "7.17"
    assert rows["r1.ftn.memhamwan.net"]["below_floor"] is True
    assert rows["r1.ftn.memhamwan.net"]["open_ports"] == [1723, 8729]
    assert "7.17 (romon) !" in view["text"]
