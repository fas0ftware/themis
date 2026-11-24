"""Read the system journal through `journalctl -o json`, resuming from a saved cursor.

Only the entries Themis needs are asked for: the auth / authpriv syslog
facilities (sudo, su, sshd, the lock screen, polkit), kernel messages (USB) and
systemd's "unit started" messages from PID 1. Reading the system journal needs
membership of the `adm` or `systemd-journal` group; no root.
"""

from __future__ import annotations

import json
import shutil
import subprocess  # nosec B404 - journalctl with a fixed argument list
from dataclasses import dataclass
from typing import Callable, Iterable, Iterator

UNIT_STARTED = "39f53479d3a045ac8e11786248231fbf"   # systemd catalog id: "Started <unit>"
MATCHES = ["SYSLOG_FACILITY=4", "SYSLOG_FACILITY=10", "+", "_TRANSPORT=kernel", "+",
           f"MESSAGE_ID={UNIT_STARTED}", "_PID=1"]
BASELINE_SINCE = "-30d"
FIELDS = "MESSAGE,SYSLOG_IDENTIFIER,_TRANSPORT,UNIT,MESSAGE_ID"   # cursor and time always come along


class JournalError(RuntimeError):
    pass


@dataclass
class Entry:
    ts: float                 # seconds since the epoch
    ident: str                # SYSLOG_IDENTIFIER (or "kernel")
    message: str
    cursor: str
    unit: str = ""            # UNIT of a "unit started" message
    message_id: str = ""


def _text(value) -> str:
    """journalctl prints binary-safe messages as a list of byte values."""
    if isinstance(value, list):
        try:
            return bytes(v for v in value if isinstance(v, int) and 0 <= v < 256).decode("utf-8", "replace")
        except ValueError:
            return ""
    return "" if value is None else str(value)


def parse(lines: Iterable[str]) -> Iterator[Entry]:
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except ValueError:
            continue
        if not isinstance(d, dict):
            continue
        try:
            ts = int(d.get("__REALTIME_TIMESTAMP", "0")) / 1e6
        except (TypeError, ValueError):
            ts = 0.0
        ident = _text(d.get("SYSLOG_IDENTIFIER")) or ("kernel" if d.get("_TRANSPORT") == "kernel" else "")
        yield Entry(ts=ts, ident=ident, message=_text(d.get("MESSAGE")), cursor=_text(d.get("__CURSOR")),
                    unit=_text(d.get("UNIT")), message_id=_text(d.get("MESSAGE_ID")))


def command(cursor: str = "", since: str = BASELINE_SINCE) -> list[str]:
    where = ["--after-cursor", cursor] if cursor else ["--since", since]
    return ["journalctl", "-o", "json", f"--output-fields={FIELDS}", "--no-pager", "-q", *where, *MATCHES]


Runner = Callable[[list[str]], tuple[int, str, str]]


def run_journalctl(argv: list[str]) -> tuple[int, str, str]:
    exe = shutil.which("journalctl")
    if not exe:
        raise JournalError("journalctl not found (Themis needs systemd's journal)")
    p = subprocess.run([exe, *argv[1:]], capture_output=True, text=True, timeout=300, check=False)  # nosec B603
    return p.returncode, p.stdout, p.stderr


def read(cursor: str = "", since: str = BASELINE_SINCE, runner: Runner = run_journalctl) -> list[Entry]:
    """Entries after `cursor` (or since `since` on the first run). A cursor the journal no longer
    knows (rotated away, journal wiped) falls back to `since`."""
    code, out, err = runner(command(cursor, since))
    if code != 0 and cursor:
        code, out, err = runner(command("", since))
    if code != 0:
        raise JournalError(err.strip().splitlines()[-1] if err.strip() else f"journalctl exited with {code}")
    entries = list(parse(out.splitlines()))
    if not entries and "No journal files were found" in err:
        raise JournalError("cannot read the system journal: add yourself to the 'adm' group")
    return entries
