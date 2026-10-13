"""Ansible filters over ansible/lib/routeros_convergence (the shared library).

    routeros_declare_accounts(service_accounts, operators, keys_dir)
    ssh_pubkey_fingerprint                 'ssh-ed25519 AAAA.. c' -> {type, fingerprint, comment}
    routeros_declared_problems             declared state -> list of problems
    routeros_audit_report(facts, declared) -> drift report (see audit.report)
    routeros_audit_text                    report -> text lines
    routeros_audit_metrics(reports, unreadable, now) -> textfile metrics
    routeros_fleet(entries, romon, probes) -> fleet view
"""
import os
import sys

from ansible.errors import AnsibleFilterError

_LIB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "lib")
if _LIB not in sys.path:
    sys.path.insert(0, _LIB)

from routeros_convergence import audit, declared  # noqa: E402


def _wrap(func):
    def call(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except ValueError as exc:
            raise AnsibleFilterError(str(exc)) from exc
    call.__name__ = func.__name__
    return call


class FilterModule:
    def filters(self):
        return {
            "routeros_declare_accounts": _wrap(declared.declare_accounts),
            "ssh_pubkey_fingerprint": _wrap(declared.pubkey_fingerprint),
            "routeros_declared_problems": declared.validate,
            "routeros_audit_report": audit.report,
            "routeros_audit_text": audit.render_text,
            "routeros_audit_metrics": audit.metrics,
            "routeros_fleet": audit.fleet,
        }
