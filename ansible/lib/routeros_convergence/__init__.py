"""RouterOS convergence: read a device, compare it to its declared state.

Pure Python (stdlib + librouteros), shared by the Ansible roles (through the
filter plugin and the CLI in __main__), the netops host's scheduled audit,
and the unit tests. Design: docs/routeros-convergence-design.md.
"""

SCHEMA = 1
