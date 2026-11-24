"""Fictional events (documentation addresses) for screenshots and tries."""

from __future__ import annotations

import time

from .rules import Finding
from .store import Store


def fill(store: Store, now: float | None = None) -> None:
    now = time.time() if now is None else now
    h = 3600
    rows = [
        (-20 * h, "auth_failure", "low", "Wrong password for alex at the lock screen", "gdm-password alex"),
        (-9 * h, "sudo_failed", "medium", "sudo gave up after 3 wrong password(s) for alex: /usr/bin/apt upgrade",
         "sudo alex"),
        (-6 * h, "usb_new", "low", "New USB device: SanDisk Cruzer Blade (0781:5567)", "usb 0781:5567:4C53"),
        (-3 * h, "new_service", "medium", "A service ran for the first time: updater-helper.service",
         "unit updater-helper.service"),
        (-50 * 60, "usb_keyboard", "high", "A new USB device that types like a keyboard was plugged in: "
         "unnamed device (1a86:e026). If it is not a keyboard you just connected, unplug it (BadUSB).",
         "usb 1a86:e026:"),
    ]
    for i in range(6):
        rows.append((-12 * 60 + i * 40, "ssh_failure", "medium",
                     f"SSH login attempt for unknown user {['admin', 'root', 'pi', 'ubuntu', 'test', 'oracle'][i]!r} "
                     "from 203.0.113.7", "ssh 203.0.113.7"))
    rows.append((-12 * 60 + 200, "brute_force", "high",
                 "5 failed logins in 10 minutes from ssh 203.0.113.7: someone may be guessing passwords",
                 "ssh 203.0.113.7"))
    for off, kind, sev, msg, src in rows:
        store.add(Finding(now + off, kind, sev, msg, src), alerted=True)
    store.remember("usb", "0781:5567:4C53", "SanDisk Cruzer Blade (0781:5567)", now - 6 * h)
    store.put("last_ts", repr(now - 60))
