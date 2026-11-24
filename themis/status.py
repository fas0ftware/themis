"""Status file for Olympos (and anything else): a small JSON summary of the last 24 hours."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

from . import __version__
from .rules import SEVERITIES
from .store import Store


def default_path() -> Path:
    base = Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state")
    return base / "themis" / "status.json"


def iso(ts: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def build(store: Store, now: float | None = None, hours: float = 24) -> dict:
    now = time.time() if now is None else now
    events = store.events(since=now - hours * 3600)
    counts = {s: 0 for s in SEVERITIES}
    kinds: dict[str, int] = {}
    for e in events:
        counts[e["severity"]] += 1
        kinds[e["kind"]] = kinds.get(e["kind"], 0) + 1
    worst = max((SEVERITIES.index(e["severity"]) for e in events), default=0)
    level = SEVERITIES[worst]
    verdict = "alert" if worst >= SEVERITIES.index("high") else "watch" if worst >= SEVERITIES.index("medium") else "quiet"
    last = store.get("last_ts")
    return {
        "version": __version__,
        "time": iso(now),
        "hours": hours,
        "level": level,
        "verdict": verdict,
        "counts": counts,
        "kinds": dict(sorted(kinds.items())),
        "journal_until": iso(float(last)) if last else None,
        "recent": [{"time": iso(e["ts"]), "kind": e["kind"], "severity": e["severity"], "message": e["message"]}
                   for e in events if e["severity"] != "info"][:10],
        "known_usb": len(store.known("usb")),
        "known_services": len(store.known("unit")),
    }


def save(data: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)
