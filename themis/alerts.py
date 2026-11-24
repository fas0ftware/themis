"""Phone alerts through ntfy (https://ntfy.sh or a self-hosted server)."""

from __future__ import annotations

import urllib.request
from urllib.parse import urlparse

from .rules import SEVERITIES

PRIORITY = {"info": "min", "low": "low", "medium": "default", "high": "high", "critical": "urgent"}


def valid_url(url: str) -> bool:
    u = urlparse(url)
    return u.scheme in ("http", "https") and bool(u.netloc) and len(url) <= 300


def neutralize(text: str) -> str:
    """Log text can be chosen by others (an SSH user name): make links and markdown inert."""
    return text.replace("://", ":​//").replace("[", "(").replace("]", ")").replace("@", "@​")


def post(url: str, body: bytes, headers: dict) -> int:
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=10) as resp:  # nosec B310 - http(s) only, checked by valid_url
        return resp.status


def send(url: str, events: list[dict], hostname: str = "", poster=post) -> list[int]:
    """Push each event; returns the ids that were delivered (failed ones are retried next scan)."""
    sent = []
    for e in events:
        title = f"Themis [{e['severity'].upper()}] {e['kind'].replace('_', ' ')}"
        if hostname:
            title += f" on {hostname}"
        headers = {"Title": title.encode("latin-1", "ignore").decode("latin-1"),
                   "Priority": PRIORITY.get(e["severity"], "default"), "Tags": "scales,warning",
                   "Content-Type": "text/plain; charset=utf-8"}
        try:
            poster(url, neutralize(e["message"]).encode(), headers)
        except Exception as exc:  # an alert must never stop the scan
            print(f"(ntfy failed: {type(exc).__name__})")
            break
        sent.append(e["id"])
    return sent


def at_least(severity: str, minimum: str) -> bool:
    return SEVERITIES.index(severity) >= SEVERITIES.index(minimum)
