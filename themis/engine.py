"""One scan: read new journal entries, turn them into events, remember what was seen."""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from . import journal, ports
from .journal import Entry
from .rules import (HID_KEYBOARD, ROOT_HUB_VENDOR, USB_INFO, USB_NEW, Finding, auth_findings, clean,
                    unit_started)
from .store import Store

CURSOR_KEY = "cursor"
LAST_TS_KEY = "last_ts"
BASELINE_KEY = "baseline_done"
BRUTE_WINDOW = 10 * 60        # this many seconds ...
BRUTE_COUNT = 5               # ... with this many failures from one source is brute force
BRUTE_REPEAT = 60 * 60        # one brute_force event per source per hour
FAILURES = ("auth_failure", "ssh_failure", "sudo_failed")


@dataclass
class ScanResult:
    baseline: bool
    entries: int
    events: list[Finding] = field(default_factory=list)
    learned_usb: int = 0
    learned_units: int = 0
    learned_ports: int = 0
    ignored: int = 0


def store_findings(store: Store, found: list[Finding], baseline: bool, result: ScanResult) -> None:
    """Store in time order. History learned on the first run is never pushed to the phone;
    an event that matches an ignore rule is kept as "info" and never pushed either."""
    rules = store.ignores()
    for f in sorted(found, key=lambda f: f.ts):
        quiet = baseline
        if rules and ignored(f, rules):
            f.severity, quiet = "info", True
            result.ignored += 1
        store.add(f, alerted=quiet)
        result.events.append(f)


def _usb_devices(entries: list[Entry]) -> list[dict]:
    """Collect 'New USB device' announcements with their product / maker / serial lines."""
    pending: dict[str, dict] = {}
    done: list[dict] = []
    keyboards: set[tuple[str, str]] = set()
    for e in entries:
        if e.ident != "kernel":
            continue
        m = USB_NEW.match(e.message)
        if m:
            if m["port"] in pending:
                done.append(pending.pop(m["port"]))
            pending[m["port"]] = {"ts": e.ts, "port": m["port"], "vid": m["vid"], "pid": m["pid"],
                                  "Product": "", "Manufacturer": "", "SerialNumber": ""}
            continue
        m = USB_INFO.match(e.message)
        if m and m["port"] in pending:
            pending[m["port"]][m["key"]] = clean(m["value"], 64).strip()
            continue
        m = HID_KEYBOARD.match(e.message)
        if m:
            keyboards.add((m["vid"].lower(), m["pid"].lower()))
    done.extend(pending.values())
    for d in done:
        d["keyboard"] = (d["vid"], d["pid"]) in keyboards
    return done


def _usb_label(d: dict) -> str:
    name = " ".join(x for x in (d["Manufacturer"], d["Product"]) if x) or "unnamed device"
    return f"{name} ({d['vid']}:{d['pid']})"


PORTS_BASELINE_KEY = "ports_baseline_done"


def check_ports(store: Store, ss: ports.Runner, now: float) -> tuple[list[Finding], int]:
    """New programs listening on the network. The first check learns what is there."""
    text = ss()
    if text is None:
        return [], 0
    first = store.get(PORTS_BASELINE_KEY) != "1"
    found, learned = [], 0
    for lst in ports.parse(text, ports.ephemeral_range()):
        if store.is_known("port", lst.key):
            continue
        store.remember("port", lst.key, lst.describe(), now)
        learned += 1
        if not first:
            found.append(Finding(now, "new_listener", "medium",
                                 f"A program listens on the network for the first time: {lst.describe()}",
                                 f"port {lst.key}", {"proto": lst.proto, "port": lst.port, "process": lst.process,
                                                     "all_addresses": lst.wildcard}))
    store.put(PORTS_BASELINE_KEY, "1")
    return found, learned


def ignored(f: Finding, rules: list[dict]) -> bool:
    return any(r["kind"] in (f.kind, "*") and (not r["match"] or r["match"] in f.source or r["match"] in f.message)
               for r in rules)


def scan(store: Store, runner: journal.Runner = journal.run_journalctl,
         since: str = journal.BASELINE_SINCE, ss: ports.Runner | None = None,
         clock=time.time) -> ScanResult:
    cursor = store.get(CURSOR_KEY)
    baseline = store.get(BASELINE_KEY) != "1"
    last_ts = store.get(LAST_TS_KEY)
    if not baseline and not cursor:   # a quiet journal on the first run left no cursor
        since = f"@{int(float(last_ts or 0))}"
    entries = journal.read(cursor, since, runner)
    result = ScanResult(baseline=baseline, entries=len(entries))
    if baseline:
        store.put(BASELINE_KEY, "1")
    found, result.learned_ports = check_ports(store, ss or ports.run_ss, clock())
    if not entries:
        store_findings(store, found, baseline, result)
        return result

    for e in entries:
        found.extend(auth_findings(e))
        unit = unit_started(e)
        if unit and not store.is_known("unit", unit):
            store.remember("unit", unit, ts=e.ts)
            result.learned_units += 1
            if not baseline:
                found.append(Finding(e.ts, "new_service", "medium",
                                     f"A service ran for the first time: {unit}", f"unit {unit}", {"unit": unit}))

    for d in _usb_devices(entries):
        if d["vid"] == ROOT_HUB_VENDOR:
            continue
        key = f"{d['vid']}:{d['pid']}:{d['SerialNumber']}"
        if store.is_known("usb", key):
            continue
        label = _usb_label(d)
        store.remember("usb", key, label, d["ts"])
        result.learned_usb += 1
        if baseline:
            continue
        if d["keyboard"]:
            found.append(Finding(d["ts"], "usb_keyboard", "high",
                                 f"A new USB device that types like a keyboard was plugged in: {label}. "
                                 "If it is not a keyboard you just connected, unplug it (BadUSB).",
                                 f"usb {key}", {"device": label, "port": d["port"]}))
        else:
            found.append(Finding(d["ts"], "usb_new", "low", f"New USB device: {label}", f"usb {key}",
                                 {"device": label, "port": d["port"]}))

    store_findings(store, found, baseline, result)

    # Brute force: many failures from one source in a short window, judged on everything stored.
    if not baseline:
        latest: dict[str, float] = {}
        for f in found:
            if f.kind in FAILURES and f.source:
                latest[f.source] = max(latest.get(f.source, 0.0), f.ts)
        for source, ts in latest.items():
            n = store.count(FAILURES, source, ts - BRUTE_WINDOW, ts)
            recent = store.count(("brute_force",), source, ts - BRUTE_REPEAT, ts)
            if n >= BRUTE_COUNT and not recent:
                bf = Finding(ts, "brute_force", "high",
                             f"{n} failed logins in {BRUTE_WINDOW // 60} minutes from {source}: "
                             "someone may be guessing passwords", source, {"failures": n})
                store_findings(store, [bf], False, result)

    store.put(CURSOR_KEY, entries[-1].cursor)
    store.put(LAST_TS_KEY, repr(entries[-1].ts))
    return result
