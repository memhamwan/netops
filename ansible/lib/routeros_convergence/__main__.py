"""Command line for the Ansible roles and the netops host's scheduled audit.

    python -m routeros_convergence gather --name H --address A --user U --out F
    python -m routeros_convergence audit --facts F --declared D [--out R]
    python -m routeros_convergence plan --facts F --declared D [--out P]
    python -m routeros_convergence audit-fleet --targets T --credentials C \\
        --textfile P --report R
    python -m routeros_convergence romon --address A --user U [--duration 15]
    python -m routeros_convergence probe --targets T [--ports 22,222,...]

Passwords never travel on the command line: `--password-env` names the
environment variable that holds it (default ROUTEROS_API_PASSWORD), and
audit-fleet reads a KEY=VALUE credentials file.
"""
import argparse
import concurrent.futures
import json
import os
import socket
import sys
import time

from . import audit, declared as declared_mod, facts as facts_mod, romon


def _write(path, text):
    """Atomic write: readers (node-exporter, the next play) never see half a file."""
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    tmp = f"{path}.tmp.{os.getpid()}"
    with open(tmp, "w") as fh:
        fh.write(text)
    os.replace(tmp, path)


def _load(path):
    with open(path) as fh:
        return json.load(fh)


def _password(args):
    value = os.environ.get(args.password_env)
    if not value:
        sys.exit(f"error: environment variable {args.password_env} is empty")
    return value


def cmd_gather(args):
    try:
        snap = facts_mod.gather(args.name, args.address, args.user, _password(args),
                                port=args.port, tls=not args.no_tls, timeout=args.timeout)
    except Exception as exc:  # report, never the password
        print(f"error: cannot read {args.name} at {args.address}:{args.port}: "
              f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    _write(args.out, json.dumps(snap, indent=1, sort_keys=True, default=str))
    print(json.dumps({"host": args.name, "version": snap["version"],
                      "menus": len(snap["menus"]), "errors": sorted(snap["errors"])}))
    return 0


def cmd_audit(args):
    snap = _load(args.facts)
    want = _load(args.declared)
    problems = declared_mod.validate(want)
    if problems:
        print("error: " + "; ".join(problems), file=sys.stderr)
        return 2
    rep = audit.report(snap, want)
    if args.out:
        _write(args.out, json.dumps(rep, indent=1, sort_keys=True))
    print(audit.render_text(rep) if args.text else json.dumps(rep["counts"]))
    return 0


def cmd_plan(args):
    from . import plan as planner

    snap = _load(args.facts)
    want = _load(args.declared)
    problems = declared_mod.validate(want)
    if problems:
        print("error: " + "; ".join(problems), file=sys.stderr)
        return 2
    p = planner.plan(snap, want)
    if args.out:
        _write(args.out, json.dumps(p, indent=1, sort_keys=True))
    print(planner.render_text(p))
    return 0


def _read_credentials(path):
    creds = {}
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                creds[key.strip()] = value.strip()
    return creds


def _audit_one(target, user, password, port, timeout):
    try:
        snap = facts_mod.gather(target["name"], target.get("address") or target["name"], user,
                                password, port=port, timeout=timeout)
    except Exception as exc:
        return target["name"], None, f"{type(exc).__name__}: {exc}"
    return target["name"], audit.report(snap, target["declared"]), None


def cmd_audit_fleet(args):
    targets = _load(args.targets)
    creds = _read_credentials(args.credentials)
    user, password = creds.get("ROUTEROS_AUDIT_USER"), creds.get("ROUTEROS_AUDIT_PASSWORD")
    if not user or not password:
        sys.exit("error: credentials file needs ROUTEROS_AUDIT_USER and ROUTEROS_AUDIT_PASSWORD")
    reports, unreadable = [], {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(_audit_one, t, user, password, args.port, args.timeout) for t in targets]
        for future in concurrent.futures.as_completed(futures):
            name, rep, error = future.result()
            if rep is None:
                unreadable[name] = error
            else:
                reports.append(rep)
    now = time.time()
    _write(args.textfile, audit.metrics(reports, unreadable, now))
    if args.report:
        _write(args.report, json.dumps({"generated_at": int(now), "reports": reports,
                                        "unreadable": unreadable}, indent=1, sort_keys=True))
    worst = sum(r["counts"]["critical"] for r in reports)
    print(f"audited {len(reports)} device(s), {len(unreadable)} unreadable, "
          f"{worst} critical finding(s)")
    return 0


def cmd_romon(args):
    from . import gather as reader

    try:
        api = reader.connect(args.address, args.user, _password(args), port=args.port,
                             tls=not args.no_tls, timeout=args.duration + 30)
        try:
            rows = romon.discover(api, args.duration)
        finally:
            api.close()
    except Exception as exc:
        print(f"error: RoMON discovery on {args.address}: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(rows, indent=1, sort_keys=True))
    return 0


def _probe_one(target, ports, timeout):
    address = target.get("address") or target["name"]
    open_ports = []
    for port in ports:
        try:
            with socket.create_connection((address, port), timeout=timeout):
                open_ports.append(port)
        except OSError:
            pass
    return {"name": target["name"], "address": address, "open": open_ports}


def cmd_probe(args):
    targets = _load(args.targets)
    ports = [int(p) for p in args.ports.split(",") if p]
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        results = list(pool.map(lambda t: _probe_one(t, ports, args.timeout), targets))
    print(json.dumps(sorted(results, key=lambda r: r["name"]), indent=1))
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(prog="routeros_convergence")
    sub = parser.add_subparsers(dest="cmd", required=True)

    def api_args(p):
        p.add_argument("--address", required=True)
        p.add_argument("--port", type=int, default=8729)
        p.add_argument("--user", required=True)
        p.add_argument("--password-env", default="ROUTEROS_API_PASSWORD")
        p.add_argument("--no-tls", action="store_true")

    p = sub.add_parser("gather", help="read a device into a facts file")
    p.add_argument("--name", required=True)
    api_args(p)
    p.add_argument("--timeout", type=float, default=30)
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_gather)

    p = sub.add_parser("audit", help="compare a facts file with a declared state")
    p.add_argument("--facts", required=True)
    p.add_argument("--declared", required=True)
    p.add_argument("--out")
    p.add_argument("--text", action="store_true")
    p.set_defaults(func=cmd_audit)

    p = sub.add_parser("plan", help="remediation plan for a facts file (changes nothing)")
    p.add_argument("--facts", required=True)
    p.add_argument("--declared", required=True)
    p.add_argument("--out")
    p.set_defaults(func=cmd_plan)

    p = sub.add_parser("audit-fleet", help="scheduled audit: gather + audit + metrics")
    p.add_argument("--targets", required=True)
    p.add_argument("--credentials", required=True)
    p.add_argument("--port", type=int, default=8729)
    p.add_argument("--timeout", type=float, default=30)
    p.add_argument("--workers", type=int, default=6)
    p.add_argument("--textfile", required=True)
    p.add_argument("--report")
    p.set_defaults(func=cmd_audit_fleet)

    p = sub.add_parser("romon", help="RoMON discovery from one router (needs the romon policy)")
    api_args(p)
    p.add_argument("--duration", type=int, default=15)
    p.set_defaults(func=cmd_romon)

    p = sub.add_parser("probe", help="TCP reachability of management ports, no login")
    p.add_argument("--targets", required=True)
    p.add_argument("--ports", default="22,23,80,222,1723,8291,8728,8729")
    p.add_argument("--timeout", type=float, default=3)
    p.add_argument("--workers", type=int, default=16)
    p.set_defaults(func=cmd_probe)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
