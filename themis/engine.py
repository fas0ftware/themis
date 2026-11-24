"""One scan: read new journal entries, turn them into events, remember what was seen."""

from __future__ import annotations

from dataclasses import dataclass, field

from . import journal
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


def scan(store: Store, runner: journal.Runner = journal.run_journalctl,
         since: str = journal.BASELINE_SINCE) -> ScanResult:
    cursor = store.get(CURSOR_KEY)
    baseline = store.get(BASELINE_KEY) != "1"
    last_ts = store.get(LAST_TS_KEY)
    if not baseline and not cursor:   # a quiet journal on the first run left no cursor
        since = f"@{int(float(last_ts or 0))}"
    entries = journal.read(cursor, since, runner)
    result = ScanResult(baseline=baseline, entries=len(entries))
    if baseline:
        store.put(BASELINE_KEY, "1")
    if not entries:
        return result

    found: list[Finding] = []
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

    found.sort(key=lambda f: f.ts)
    for f in found:
        store.add(f, alerted=baseline)   # history learned on the first run is never pushed to the phone
    result.events.extend(found)

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
                store.add(bf)
                result.events.append(bf)

    store.put(CURSOR_KEY, entries[-1].cursor)
    store.put(LAST_TS_KEY, repr(entries[-1].ts))
    return result
