"""themis: what happened on this laptop that you should know about.

    themis                     scan new journal entries (the first run learns the last 30 days)
    themis scan --save         ... and write the status file Olympos reads
    themis report --hours 72   events of the last 72 hours
    themis known usb           USB devices seen so far
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import time
from pathlib import Path

from . import __version__, alerts, engine, status
from .journal import JournalError
from .rules import SEVERITIES
from .store import Store, default_path

COLORS = {"info": "2", "low": "32", "medium": "33", "high": "31", "critical": "1;31"}


def paint(text: str, sev: str, on: bool) -> str:
    return f"\033[{COLORS[sev]}m{text}\033[0m" if on else text


def when(ts: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))


def print_events(events: list[dict], color: bool) -> None:
    if not events:
        print("Nothing to report.")
        return
    for e in sorted(events, key=lambda e: e["ts"]):
        sev = e["severity"]
        print(f"{when(e['ts'])}  {paint(sev.ljust(8), sev, color)} {e['message']}")


def cmd_scan(args, store: Store) -> int:
    try:
        r = engine.scan(store)
    except JournalError as exc:
        print(f"themis: {exc}", file=sys.stderr)
        return 2
    if r.baseline:
        print(f"First run: read {r.entries} journal entries from the last 30 days and learned "
              f"{r.learned_usb} USB device(s) and {r.learned_units} service(s); from now on, new ones are reported.")
    elif not args.quiet:
        print(f"Read {r.entries} new journal entries, {len(r.events)} event(s).")
    if not args.quiet:
        print_events([{"ts": f.ts, "severity": f.severity, "message": f.message} for f in r.events
                      if f.severity != "info"], args.color)
    url = args.ntfy or os.environ.get("THEMIS_NTFY_URL", "").strip()
    if url:
        if not alerts.valid_url(url):
            print("themis: the ntfy address must be an http(s) URL", file=sys.stderr)
            return 2
        due = store.unalerted(args.alert_min)
        store.mark_alerted(alerts.send(url, due, socket.gethostname()))
    if args.save is not None:
        status.save(status.build(store), Path(args.save) if args.save else status.default_path())
    return 0


def cmd_report(args, store: Store) -> int:
    events = store.events(since=time.time() - args.hours * 3600, min_severity=args.min)
    if args.json:
        print(json.dumps(events, indent=2))
        return 0
    print(f"Themis {__version__} · last {args.hours:g} h · {args.min} and above")
    print_events(events, args.color)
    return 0


def cmd_known(args, store: Store) -> int:
    kind = {"usb": "usb", "services": "unit"}[args.what]
    rows = store.known(kind)
    for r in rows:
        print(f"{when(r['first_seen'])}  {r['label'] or r['key']}")
    print(f"{len(rows)} {args.what}")
    return 0


def cmd_demo(args, _store) -> int:
    from .demo import fill
    store = Store(":memory:")
    fill(store)
    if args.json:
        print(json.dumps(status.build(store), indent=2))
        return 0
    print("Themis demo (fictional events)")
    print_events(store.events(min_severity="low"), args.color)
    return 0


def main(argv=None) -> int:
    def common(top: bool) -> argparse.ArgumentParser:
        # Accepted before and after the subcommand; the subcommand's copy never overrides the top one.
        c = argparse.ArgumentParser(add_help=False)
        c.add_argument("--db", help="state database", default=(os.environ.get("THEMIS_DB") or str(default_path()))
                       if top else argparse.SUPPRESS)
        c.add_argument("--no-color", dest="color", action="store_false",
                       default=sys.stdout.isatty() if top else argparse.SUPPRESS)
        return c

    p = argparse.ArgumentParser(prog="themis", description=__doc__.split("\n\n")[0], parents=[common(True)])
    p.add_argument("--version", action="version", version=f"themis {__version__}")
    sub = p.add_subparsers(dest="cmd")
    sc = sub.add_parser("scan", help="read new journal entries (default)", parents=[common(False)])
    for target in (p, sc):  # `themis --save` works like `themis scan --save`
        target.add_argument("--save", nargs="?", const="", default=None, metavar="PATH",
                            help=f"write the status file (default {status.default_path()})")
        target.add_argument("--ntfy", default="", help="ntfy topic URL (or THEMIS_NTFY_URL)")
        target.add_argument("--alert-min", choices=SEVERITIES,
                            default=os.environ.get("THEMIS_ALERT_MIN", "medium"), help="lowest severity pushed")
        target.add_argument("-q", "--quiet", action="store_true", help="print nothing unless there is an error")
    rp = sub.add_parser("report", help="show stored events", parents=[common(False)])
    rp.add_argument("--hours", type=float, default=24)
    rp.add_argument("--min", choices=SEVERITIES, default="low")
    rp.add_argument("--json", action="store_true")
    kn = sub.add_parser("known", help="list what has been seen before", parents=[common(False)])
    kn.add_argument("what", choices=("usb", "services"))
    dm = sub.add_parser("demo", help="show a report of fictional events", parents=[common(False)])
    dm.add_argument("--json", action="store_true", help="the status file Olympos would read")
    args = p.parse_args(argv)
    if args.alert_min not in SEVERITIES:
        p.error("THEMIS_ALERT_MIN must be one of " + ", ".join(SEVERITIES))
    if args.cmd == "demo":
        return cmd_demo(args, None)
    store = Store(args.db)
    return {"report": cmd_report, "known": cmd_known}.get(args.cmd, cmd_scan)(args, store)


if __name__ == "__main__":
    sys.exit(main())
