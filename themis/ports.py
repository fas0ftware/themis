"""Ports this laptop listens on from the network, read with `ss -tulnpH` (no root: process names
are shown only for this user's programs). Loopback, multicast and the ephemeral UDP ports that
browsers and mDNS clients open by the dozen are left out."""

from __future__ import annotations

import ipaddress
import shutil
import subprocess  # nosec B404 - ss with a fixed argument list
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .rules import clean


@dataclass(frozen=True)
class Listener:
    proto: str      # tcp | udp
    port: int
    wildcard: bool  # 0.0.0.0, [::] or *: every address of every interface
    address: str
    process: str

    @property
    def key(self) -> str:
        # Not the address itself: a DHCP lease must not make an old port look new.
        return f"{self.proto} {self.port} {'all' if self.wildcard else 'one'}"

    def describe(self) -> str:
        where = "on every address" if self.wildcard else f"on {self.address}"
        who = self.process or "a system process"
        return f"{self.proto} {self.port} {where} ({who})"


def ephemeral_range(root: str = "/") -> tuple[int, int]:
    try:
        lo, hi = (int(x) for x in (Path(root) / "proc/sys/net/ipv4/ip_local_port_range").read_text().split())
        return lo, hi
    except (OSError, ValueError):
        return 32768, 60999


def _addr(local: str) -> tuple[str, int] | None:
    host, sep, port = local.rpartition(":")
    if not sep or not port.isdigit():
        return None
    # ss writes "[fe80::1]%wlo1:546" and "127.0.0.53%lo:53": drop the interface, then the brackets
    host = host.split("%", 1)[0].strip("[]")
    return host, int(port)


def parse(text: str, ephemeral: tuple[int, int] = (32768, 60999)) -> list[Listener]:
    out: dict[str, Listener] = {}
    for line in text.splitlines():
        f = line.split()
        if len(f) < 5 or f[0] not in ("tcp", "udp"):
            continue
        if f[0] == "tcp" and f[1] != "LISTEN":
            continue
        parsed = _addr(f[4])
        if not parsed:
            continue
        host, port = parsed
        wildcard = host in ("*", "0.0.0.0", "::", "")  # nosec B104 - reads ss output, binds nothing
        if not wildcard:
            try:
                ip = ipaddress.ip_address(host)
            except ValueError:
                continue
            if ip.is_loopback or ip.is_multicast:
                continue
        if f[0] == "udp" and ephemeral[0] <= port <= ephemeral[1]:
            continue
        process = ""
        users = " ".join(f[6:])
        if '(("' in users:
            process = clean(users.split('(("', 1)[1].split('"', 1)[0], 32)
        lst = Listener(f[0], port, wildcard, clean(host, 45), process)
        out.setdefault(lst.key, lst)   # IPv4 and IPv6 sockets of one program count once
    return sorted(out.values(), key=lambda x: (x.proto, x.port, not x.wildcard))


Runner = Callable[[], str | None]


def run_ss() -> str | None:
    exe = shutil.which("ss")
    if not exe:
        return None
    p = subprocess.run([exe, "-tulnpH"], capture_output=True, text=True, timeout=20, check=False)  # nosec B603
    return p.stdout if p.returncode == 0 else None
