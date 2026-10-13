# RouterOS lab

Two RouterOS CHR VMs on your own machine, for running the device roles end to
end before they touch the fleet. Nothing here can reach a real device: the VMs
sit behind QEMU user networking, and the lab inventory names only them.

## Requirements

`brew install qemu` and the project venv (main README). The VMs are arm64 CHR
under TCG emulation: Apple's HVF cannot boot RouterOS on an M5 ("No working
init found"), and TCG reaches the login prompt in about a minute.

## Start

```sh
cd tests/lab
./boot.sh fetch                      # CHR 7.24.5 image into ~/.cache/netops/lab
./boot.sh new chr-a && ./boot.sh new chr-b
./boot.sh run chr-a 20000 socket,listen=127.0.0.1:21234 &
./boot.sh run chr-b 30000 socket,connect=127.0.0.1:21234 &
# wait for the API (127.0.0.1:20728 / 30728), then make them fleet devices:
../../ansible/.venv/bin/python lab.py baseline 20000 chr-a.lab.memhamwan.net
../../ansible/.venv/bin/python lab.py baseline 30000 chr-b.lab.memhamwan.net
```

| VM | SSH (222) | API-SSL (8729) | role |
|---|---|---|---|
| chr-a | 127.0.0.1:20222 | 127.0.0.1:20729 | core: RoMON discovery runs here |
| chr-b | 127.0.0.1:30222 | 127.0.0.1:30729 | the device you break |

ether2 of the two VMs share a layer-2 link (QEMU socket), so RoMON and
neighbour discovery see each other.

`lab.py baseline` leaves a device the way onboarding does: service and
operator accounts with the repo's public keys (operators log in with their own
keys, as on the fleet), the api-ssl certificate, SSH on 222 and API-SSL
restricted to 10.0.2.0/24 (how QEMU shows your machine) and the netops host,
remote syslog, RoMON on. `admin` (password `lab`) stays: it is how `lab.py`
drives the VMs, and the lab inventory allows it.

`lab.py compromise 30000` adds the September 2026 artifacts to chr-b:
undeclared full-group accounts, an attacker key on one of them and an extra
key on an operator, the C2 `backup-sync`/`cfg-check` schedulers, payload and
backup files, services opened to the world, password login and forwarding on,
the PPTP proxy kit (pool, profile, secret, server, masquerade), DDNS, a
WireGuard backdoor, `x-mgmt-*` input accept rules, tampered logging, public
resolvers with remote requests on, SOCKS and traffic-flow export.
`lab.py edge 20000` adds legitimate edge-router-like config instead (note: its
input `drop` rule cuts the API off from your machine).

To get back to a clean device, shut the VM down (`/system shutdown`) after
`baseline`, copy `~/.cache/netops/lab/<name>.img` aside, and copy it back
later.

## Run the roles against it

Always together with the real inventory, so the fleet's declared state
applies, limited to the lab, with the lab's stand-ins for the sops secrets:

```sh
cd ansible
ansible-playbook -i inventory/hosts.yml -i ../tests/lab/inventory.yml -l lab \
  -e @../tests/lab/lab-vars.yml playbooks/routeros_audit.yml
```

## Fixtures

`tests/routeros/fixtures/` are snapshots of this lab taken with
`python -m routeros_convergence gather` (secrets redacted at read time):
`lab-clean` after `baseline`, `lab-compromised` after `compromise`,
`lab-edge` after `edge`. Recapture them when the read paths change.
