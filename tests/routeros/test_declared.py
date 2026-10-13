import pytest
from conftest import KEYS, OPERATORS, SERVICE_ACCOUNTS, make_declared

from routeros_convergence import declared


def test_fingerprint_matches_ssh_keygen():
    # `ssh-keygen -lf .../operators/turnrye_ed25519.pub`
    key = (KEYS / "operators" / "turnrye_ed25519.pub").read_text()
    assert declared.pubkey_fingerprint(key)["fingerprint"] == "SHA256:b8777l9TwmLIsEbBNiRlaUhl8gWzIRF7vhouRYuIKCk"


def test_fingerprint_comparison_ignores_routeros_padding():
    # RouterOS 7.24 prints the base64 padded, ssh-keygen does not
    assert declared.fingerprint("SHA256:AotGiR+ih3l8oeIdbQZlB1AAgS01Ri2m5hv3z20I1qg=") == \
        declared.fingerprint("SHA256:AotGiR+ih3l8oeIdbQZlB1AAgS01Ri2m5hv3z20I1qg")


def test_declare_accounts_reads_every_operator_key():
    accounts = {a["name"]: a for a in declared.declare_accounts(SERVICE_ACCOUNTS, OPERATORS, str(KEYS))}
    assert list(accounts) == ["ansible", "oxidized", "oxidized-full", "mktxp", "turnrye", "seichold", "ae5au"]
    assert len(accounts["turnrye"]["keys"]) == 2
    assert accounts["mktxp"]["keys"] == []
    assert accounts["turnrye"]["group"] == "full"
    # the retired shared and factory accounts are not declared
    assert not {"hamwan", "packetbard", "admin"} & set(accounts)


def test_declare_accounts_rejects_missing_key_and_duplicates():
    with pytest.raises(ValueError, match="not found"):
        declared.declare_accounts([{"name": "x", "group": "g", "keys": ["nope.pub"]}], [], str(KEYS))
    with pytest.raises(ValueError, match="declared twice"):
        declared.declare_accounts(SERVICE_ACCOUNTS, ["turnrye", "turnrye"], str(KEYS))


@pytest.mark.parametrize("allowance,row,expected", [
    ("wg-mgmt", {"name": "wg-mgmt"}, True),
    ("Internet", {"comment": "Internet"}, True),
    ("Internet", {"name": "x", "comment": ""}, False),
    ("~^x-(mgmt|vpn)-", {"comment": "x-mgmt-3"}, True),
    ("~^edge-", {"comment": "x-mgmt-3"}, False),
    ("*", {"name": "anything"}, True),
    ({"chain": "srcnat", "action": "masquerade"}, {"chain": "srcnat", "action": "masquerade", "comment": "c"}, True),
    ({"chain": "srcnat", "src-address": "10.0.0.0/24"}, {"chain": "srcnat", "src-address": "10.1.0.0/24"}, False),
    ({"disabled": False}, {"disabled": False}, True),
])
def test_allowance_matching(allowance, row, expected):
    assert declared.allowance_matches(allowance, row) is expected


def test_validate_catches_typos():
    assert declared.validate(make_declared("h")) == []
    problems = declared.validate(make_declared("h", allow={"firewall": ["*"], "socks": "yes"}))
    assert any("unknown category `firewall`" in p for p in problems)
    assert any("socks must be true or false" in p for p in problems)
    assert declared.validate(make_declared("h", management_sources=["0.0.0.0"]))
