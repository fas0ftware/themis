"""Turn journal entries into findings. Pure functions: no state, no I/O.

Everything in a log line can come from someone else (an SSH user name is typed by
whoever connects), so every value is reduced to printable ASCII and capped
before it is stored, printed or sent to a phone.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .journal import UNIT_STARTED, Entry

SEVERITIES = ("info", "low", "medium", "high", "critical")


def clean(value, limit: int = 64) -> str:
    text = "" if value is None else str(value)
    return "".join(c if " " <= c <= "~" else "?" for c in text)[:limit]


@dataclass
class Finding:
    ts: float
    kind: str
    severity: str
    message: str
    source: str = ""          # what failures are grouped by for brute-force detection ("ssh 203.0.113.7")
    data: dict = field(default_factory=dict)


# pam_unix(sudo:auth): authentication failure; logname=z uid=1000 euid=0 tty=/dev/pts/1 ruser=z rhost=  user=z
PAM_FAIL = re.compile(r"pam_unix\((?P<svc>[\w.-]+):auth\): authentication failure;(?P<rest>.*)$")
PAM_KV = re.compile(r"(\w+)=(\S*)")
# z : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/home/z ; USER=root ; COMMAND=/usr/bin/true
SUDO_TRIES = re.compile(r"^(?P<user>\S+) : (?P<n>\d+) incorrect password attempts? ;.*?COMMAND=(?P<cmd>.*)$")
SUDO_NOT_ALLOWED = re.compile(r"^(?P<user>\S+) : (?:user NOT in sudoers|user NOT authorized on host)"
                              r".*?COMMAND=(?P<cmd>.*)$")
SSH_FAIL = re.compile(r"^Failed (?P<method>password|publickey|keyboard-interactive/pam) for (?:invalid user )?"
                      r"(?P<user>.*?) from (?P<ip>[0-9A-Fa-f:.]+) port \d+")
SSH_INVALID = re.compile(r"^Invalid user (?P<user>.*?) from (?P<ip>[0-9A-Fa-f:.]+)(?: port \d+)?$")
SSH_ACCEPTED = re.compile(r"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>[0-9A-Fa-f:.]+) port \d+")

# usb 1-2: New USB device found, idVendor=046d, idProduct=c53f, bcdDevice=55.01
USB_NEW = re.compile(r"^usb (?P<port>[\d.-]+): New USB device found, idVendor=(?P<vid>[0-9a-f]{4}), "
                     r"idProduct=(?P<pid>[0-9a-f]{4})")
USB_INFO = re.compile(r"^usb (?P<port>[\d.-]+): (?P<key>Product|Manufacturer|SerialNumber): (?P<value>.*)$")
# hid-generic 0003:046D:C53F.0001: input,hidraw0: USB HID v1.11 Keyboard [Logitech USB Receiver] on usb-...
HID_KEYBOARD = re.compile(r"^\S+ 0003:(?P<vid>[0-9A-F]{4}):(?P<pid>[0-9A-F]{4})\.[0-9A-F]+: .*\bUSB HID v[\d.]+ "
                          r"Keyboard\b")
ROOT_HUB_VENDOR = "1d6b"   # Linux Foundation: the controllers' own root hubs, re-announced every boot

SERVICES = {"sudo": "sudo", "su": "su", "su-l": "su", "polkit-1": "an admin prompt (polkit)",
            "gdm-password": "the lock screen", "login": "a text console", "sshd": "SSH",
            "lightdm": "the login screen", "sddm": "the login screen", "cron": "cron"}

SKIP_UNIT_PREFIXES = ("run-", "session-", "user@", "user-runtime-dir@", "systemd-", "dracut-", "modprobe@",
                      "getty@", "dbus-:", "snap.", "docker-", "app-")
WATCH_UNIT_SUFFIXES = (".service", ".timer", ".socket", ".path")


def unit_name(unit: str) -> str:
    """Template instances count as their template: backup@home.service -> backup@.service."""
    unit = clean(unit, 120)
    if "@" in unit:
        head, _, tail = unit.partition("@")
        ext = tail[tail.rfind("."):] if "." in tail else ""
        return f"{head}@{ext}"
    return unit


def watched_unit(unit: str) -> bool:
    return bool(unit) and unit.endswith(WATCH_UNIT_SUFFIXES) and not unit.startswith(SKIP_UNIT_PREFIXES)


def auth_findings(e: Entry) -> list[Finding]:
    msg = e.message
    m = PAM_FAIL.search(msg)
    if m:
        svc = m["svc"]
        if svc == "sshd":
            return []  # sshd writes its own, clearer "Failed password" line
        kv = dict(PAM_KV.findall(m["rest"]))
        user, rhost = clean(kv.get("user"), 32), clean(kv.get("rhost"), 64)
        where = SERVICES.get(svc, clean(svc, 32))
        text = f"Wrong password for {user or 'a user'} at {where}" + (f" from {rhost}" if rhost else "")
        return [Finding(e.ts, "auth_failure", "low", text, f"{clean(svc, 32)} {rhost or user}",
                        {"service": clean(svc, 32), "user": user, "rhost": rhost})]
    if e.ident == "sudo":
        m = SUDO_NOT_ALLOWED.match(msg)
        if m:
            return [Finding(e.ts, "sudo_not_allowed", "high",
                            f"{clean(m['user'], 32)} tried sudo without being allowed to: {clean(m['cmd'], 120)}",
                            f"sudo {clean(m['user'], 32)}", {"user": clean(m["user"], 32)})]
        m = SUDO_TRIES.match(msg)
        if m:
            n = int(m["n"])
            return [Finding(e.ts, "sudo_failed", "medium" if n >= 3 else "low",
                            f"sudo gave up after {n} wrong password(s) for {clean(m['user'], 32)}: "
                            f"{clean(m['cmd'], 120)}", f"sudo {clean(m['user'], 32)}",
                            {"user": clean(m["user"], 32), "tries": n})]
    if e.ident in ("sshd", "sshd-session"):
        m = SSH_FAIL.match(msg) or SSH_INVALID.match(msg)
        if m:
            ip, user = clean(m["ip"], 45), clean(m["user"], 32)
            invalid = msg.startswith("Invalid user") or " invalid user " in msg
            if msg.startswith("Invalid user"):
                text = f"SSH login attempt for unknown user {user!r} from {ip}"
            else:
                text = f"SSH: wrong {m['method'].split('/')[0]} for {'unknown user ' if invalid else ''}{user!r} from {ip}"
            return [Finding(e.ts, "ssh_failure", "medium", text, f"ssh {ip}",
                            {"user": user, "ip": ip, "invalid_user": invalid})]
        m = SSH_ACCEPTED.match(msg)
        if m:
            return [Finding(e.ts, "ssh_login", "medium",
                            f"SSH login as {clean(m['user'], 32)} from {clean(m['ip'], 45)} ({clean(m['method'], 32)})",
                            "", {"user": clean(m["user"], 32), "ip": clean(m["ip"], 45)})]
    return []


def unit_started(e: Entry) -> str:
    """The watched unit this entry says was started, or ""."""
    if e.message_id != UNIT_STARTED:
        return ""
    name = unit_name(e.unit)
    return name if watched_unit(name) else ""
