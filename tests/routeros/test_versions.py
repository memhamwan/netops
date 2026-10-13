from routeros_convergence import versions


def test_parse_orders_releases_and_prereleases():
    assert versions.parse("7.24.5 (stable)") == (7, 24, 5, 3, 0)
    assert versions.parse("7.17") == (7, 17, 0, 3, 0)
    assert versions.parse("7.25beta2") < versions.parse("7.25")
    assert versions.parse("6.49.21 (long-term)") < versions.parse("7.9")
    assert versions.parse("") is None and versions.parse(None) is None


def test_security_floor():
    assert versions.at_least("7.24.2", versions.SECURITY_FLOOR)
    assert versions.at_least("7.24.5 (stable)", versions.SECURITY_FLOOR)
    assert not versions.at_least("7.24.1", versions.SECURITY_FLOOR)
    assert not versions.at_least("7.17", versions.SECURITY_FLOOR)
    assert not versions.at_least("garbage", versions.SECURITY_FLOOR)


def test_service_source_key_prefers_the_row():
    assert versions.service_source_key({"available-from": ""}, "7.17") == "available-from"
    assert versions.service_source_key({"address": ""}, "7.24.5") == "address"
    assert versions.service_source_key(None, "7.24.5") == "available-from"
    assert versions.service_source_key(None, "7.17") == "address"


def test_ddns_off_value():
    # 7.17+ accepts only yes|auto (lab 7.24.5: "must be either yes or auto")
    assert versions.ddns_off_value("7.24.5") == "auto"
    assert versions.ddns_off_value("7.17") == "auto"
    assert versions.ddns_off_value("7.12.1") is False
    assert versions.ddns_off_value("") is None
    assert versions.ddns_enabled(True) and versions.ddns_enabled("yes")
    assert not versions.ddns_enabled("auto") and not versions.ddns_enabled(False)
