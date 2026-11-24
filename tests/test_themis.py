import json
import os
import stat

import pytest

from themis import __main__ as cli
from themis import alerts, engine, journal, rules, status
from themis.journal import UNIT_STARTED, Entry, JournalError
from themis.store import Store

T0 = 1_790_000_000.0


def line(msg, ident="", ts=T0, cursor=None, transport="syslog", unit="", mid=""):
    d = {"__REALTIME_TIMESTAMP": str(int(ts * 1e6)), "MESSAGE": msg, "__CURSOR": cursor or f"c{ts}",
         "_TRANSPORT": transport}
    if ident:
        d["SYSLOG_IDENTIFIER"] = ident
    if unit:
        d["UNIT"] = unit
    if mid:
        d["MESSAGE_ID"] = mid
    return json.dumps(d)


def kernel(msg, ts=T0):
    return line(msg, transport="kernel", ts=ts)


def started(unit, ts=T0):
    return line(f"Started {unit}.", ident="systemd", unit=unit, mid=UNIT_STARTED, ts=ts)


class FakeJournal:
    """Stands in for journalctl: hands out batches, records the arguments."""

    def __init__(self, *batches):
        self.batches = list(batches)
        self.calls = []

    def __call__(self, argv):
        self.calls.append(argv)
        if "--after-cursor" in argv and argv[argv.index("--after-cursor") + 1] == "gone":
            return 1, "", "Failed to seek to cursor: Invalid argument"
        return 0, "\n".join(self.batches.pop(0) if self.batches else []), ""


def entry(msg, ident=""):
    return Entry(ts=T0, ident=ident, message=msg, cursor="c")


# --- rules ---------------------------------------------------------------------------------

def test_pam_failures():
    [f] = rules.auth_findings(entry("pam_unix(sudo:auth): authentication failure; logname=z uid=1000 euid=0 "
                                    "tty=/dev/pts/1 ruser=z rhost=  user=z", "sudo"))
    assert (f.kind, f.severity, f.source) == ("auth_failure", "low", "sudo z")
    assert f.message == "Wrong password for z at sudo"
    [f] = rules.auth_findings(entry("pam_unix(gdm-password:auth): authentication failure; logname=z uid=0 euid=0 "
                                    "tty=/dev/tty1 ruser= rhost=  user=z", "gdm-password]"))
    assert f.message == "Wrong password for z at the lock screen"
    assert rules.auth_findings(entry("pam_unix(sshd:auth): authentication failure; rhost=203.0.113.7", "sshd")) == []


def test_sudo_lines():
    [f] = rules.auth_findings(entry("z : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/home/z ; USER=root ; "
                                    "COMMAND=/usr/bin/true", "sudo"))
    assert (f.kind, f.severity, f.data["tries"]) == ("sudo_failed", "medium", 3)
    [f] = rules.auth_findings(entry("guest : user NOT in sudoers ; TTY=pts/2 ; PWD=/ ; USER=root ; "
                                    "COMMAND=/bin/sh", "sudo"))
    assert (f.kind, f.severity) == ("sudo_not_allowed", "high") and "/bin/sh" in f.message
    assert rules.auth_findings(entry("z : TTY=pts/2 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/apt", "sudo")) == []


def test_ssh_lines():
    [f] = rules.auth_findings(entry("Failed password for invalid user admin from 203.0.113.7 port 51234 ssh2", "sshd"))
    assert (f.kind, f.source, f.data["invalid_user"]) == ("ssh_failure", "ssh 203.0.113.7", True)
    assert "unknown user 'admin'" in f.message
    [f] = rules.auth_findings(entry("Invalid user oracle from 2001:db8::5 port 40000", "sshd-session"))
    assert f.source == "ssh 2001:db8::5"
    [f] = rules.auth_findings(entry("Accepted publickey for z from 192.0.2.4 port 50000 ssh2: ED25519 SHA256:x",
                                    "sshd"))
    assert f.kind == "ssh_login"


def test_hostile_user_names_are_flattened():
    [f] = rules.auth_findings(entry("Invalid user \x1b[31m‮evil" + "x" * 80 + " from 203.0.113.7 port 1", "sshd"))
    assert "\x1b" not in f.message and "‮" not in f.message
    assert len(f.data["user"]) == 32


def test_unit_names():
    assert rules.unit_name("backup@home.service") == "backup@.service"
    assert rules.watched_unit("cups.service") and rules.watched_unit("evil.timer")
    for skip in ("session-3.scope", "run-r1234.service", "user@1000.service", "systemd-tmpfiles-clean.service",
                 "sysinit.target", "dev-sda.device"):
        assert not rules.watched_unit(rules.unit_name(skip)), skip


def test_journal_parse_and_binary_messages():
    raw = json.dumps({"__REALTIME_TIMESTAMP": "1790000000000000", "MESSAGE": [104, 105, 255], "__CURSOR": "x"})
    [e] = journal.parse([raw, "not json", "", "[1,2]"])
    assert e.message == "hi�" and e.ts == 1790000000.0


def test_journal_cursor_fallback_and_errors():
    j = FakeJournal(["x"])
    journal.read("gone", "-30d", j)
    assert j.calls[-1][-len(journal.MATCHES) - 2:-len(journal.MATCHES)] == ["--since", "-30d"]
    with pytest.raises(JournalError):
        journal.read("", "-1d", lambda argv: (1, "", "permission denied\n"))


# --- engine ---------------------------------------------------------------------------------

def test_first_run_is_a_silent_baseline(tmp_path):
    store = Store(tmp_path / "t.db")
    old = [kernel("usb 1-2: New USB device found, idVendor=046d, idProduct=c53f, bcdDevice=55.01"),
           kernel("usb 1-2: Product: USB Receiver"), kernel("usb 1-2: Manufacturer: Logitech"),
           kernel("usb usb4: New USB device found, idVendor=1d6b, idProduct=0003, bcdDevice= 7.00"),
           started("cups.service"),
           line("pam_unix(sudo:auth): authentication failure; logname=z uid=1000 euid=0 tty= ruser=z rhost=  user=z",
                "sudo", cursor="end")]
    r = engine.scan(store, FakeJournal(old))
    assert r.baseline and (r.learned_usb, r.learned_units) == (1, 1)
    assert [f.kind for f in r.events] == ["auth_failure"]
    assert store.unalerted("info") == []          # history is not pushed to the phone
    assert store.known("usb")[0]["label"] == "Logitech USB Receiver (046d:c53f)"
    assert store.get(engine.CURSOR_KEY) == "end"


def test_new_usb_keyboard_and_service_after_baseline(tmp_path):
    store = Store(tmp_path / "t.db")
    j = FakeJournal([started("cups.service")], [
        kernel("usb 1-4: New USB device found, idVendor=1a86, idProduct=e026, bcdDevice= 1.00", T0 + 10),
        kernel("input: HID 1a86:e026 as /devices/pci0000:00/usb1/1-4/1-4:1.0/0003:1A86:E026.0005/input/input9", T0 + 11),
        kernel("hid-generic 0003:1A86:E026.0005: input,hidraw3: USB HID v1.10 Keyboard [HID 1a86:e026] on "
               "usb-0000:00:14.0-4/input0", T0 + 11),
        kernel("usb 1-5: New USB device found, idVendor=0781, idProduct=5567, bcdDevice= 1.00", T0 + 20),
        kernel("usb 1-5: Product: Cruzer Blade", T0 + 20),
        kernel("usb 1-5: SerialNumber: 4C53", T0 + 20),
        started("cups.service", T0 + 30), started("updater@x.service", T0 + 31),
    ], [
        kernel("usb 1-5: New USB device found, idVendor=0781, idProduct=5567, bcdDevice= 1.00", T0 + 99),
        kernel("usb 1-5: SerialNumber: 4C53", T0 + 99),
    ])
    engine.scan(store, j)
    r = engine.scan(store, j)
    kinds = {f.kind: f for f in r.events}
    assert set(kinds) == {"usb_keyboard", "usb_new", "new_service"}
    assert kinds["usb_keyboard"].severity == "high" and "BadUSB" in kinds["usb_keyboard"].message
    assert kinds["new_service"].message.endswith("updater@.service")
    assert engine.scan(store, j).events == []      # the stick again: already known
    assert j.calls[1][j.calls[1].index("--after-cursor") + 1] == f"c{T0}"


def test_brute_force_once_per_hour(tmp_path):
    store = Store(tmp_path / "t.db")
    fails = [line(f"Invalid user u{i} from 203.0.113.7 port {i}", "sshd", ts=T0 + 30 * i) for i in range(7)]
    j = FakeJournal([started("cups.service")], fails[:3], fails[3:], [
        line("Invalid user z from 203.0.113.7 port 9", "sshd", ts=T0 + 400)])
    engine.scan(store, j)
    assert not [f for f in engine.scan(store, j).events if f.kind == "brute_force"]
    [bf] = [f for f in engine.scan(store, j).events if f.kind == "brute_force"]
    assert bf.severity == "high" and bf.data["failures"] == 7
    assert not [f for f in engine.scan(store, j).events if f.kind == "brute_force"]


def test_spread_out_failures_are_not_brute_force(tmp_path):
    store = Store(tmp_path / "t.db")
    fails = [line(f"Invalid user u from 203.0.113.7 port {i}", "sshd", ts=T0 + 700 * i) for i in range(6)]
    j = FakeJournal([started("a.service")], fails)
    engine.scan(store, j)
    assert not [f for f in engine.scan(store, j).events if f.kind == "brute_force"]


def test_quiet_first_run_resumes_by_time(tmp_path):
    store = Store(tmp_path / "t.db")
    j = FakeJournal([], [])
    engine.scan(store, j)
    r = engine.scan(store, j)
    assert not r.baseline and "--since" in j.calls[1] and j.calls[1][j.calls[1].index("--since") + 1] == "@0"


# --- store, status, alerts, cli -------------------------------------------------------------

def test_database_is_private(tmp_path):
    Store(tmp_path / "s" / "t.db")
    assert stat.S_IMODE(os.stat(tmp_path / "s" / "t.db").st_mode) == 0o600


def test_status_file(tmp_path):
    from themis.demo import fill
    store = Store(":memory:")
    fill(store, now=T0)
    data = status.build(store, now=T0)
    assert data["verdict"] == "alert" and data["counts"]["high"] == 2 and data["known_usb"] == 1
    assert data["recent"][0]["kind"] == "usb_keyboard" or data["recent"][0]["time"] >= data["recent"][-1]["time"]
    path = tmp_path / "st" / "status.json"
    status.save(data, path)
    assert json.loads(path.read_text())["level"] == "high"
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_alerts_and_retry(tmp_path):
    store = Store(tmp_path / "t.db")
    j = FakeJournal([started("a.service")], [line("guest : user NOT in sudoers ; TTY=pts/2 ; PWD=/ ; USER=root ; "
                                                  "COMMAND=/bin/sh", "sudo", ts=T0 + 5),
                                             line("Invalid user [x](https://evil.example) from 203.0.113.7 port 1",
                                                  "sshd", ts=T0 + 6)])
    engine.scan(store, j)
    engine.scan(store, j)
    calls = []
    assert alerts.send("https://ntfy.sh/t", store.unalerted("medium"), "box",
                       poster=lambda *a: (_ for _ in ()).throw(OSError())) == []
    ids = alerts.send("https://ntfy.sh/t", store.unalerted("medium"), "box", poster=lambda *a: calls.append(a))
    store.mark_alerted(ids)
    assert len(calls) == 2 and store.unalerted("medium") == []
    assert calls[0][2]["Priority"] == "high" and calls[0][2]["Title"].endswith(" on box")
    assert b"https://" not in calls[1][1]
    assert alerts.valid_url("https://ntfy.sh/x") and not alerts.valid_url("file:///etc/passwd")


def test_cli(tmp_path, monkeypatch, capsys):
    import time
    j = FakeJournal([started("a.service")], [line("Invalid user x from 203.0.113.7 port 1", "sshd",
                                                  ts=time.time() - 60)])
    db = str(tmp_path / "t.db")
    real_scan = engine.scan
    monkeypatch.setattr(engine, "scan", lambda store: real_scan(store, j))
    assert cli.main(["--db", db, "--no-color"]) == 0
    assert "First run" in capsys.readouterr().out
    assert cli.main(["scan", "--db", db, "--save", str(tmp_path / "st.json")]) == 0
    assert "unknown user 'x'" in capsys.readouterr().out
    assert json.loads((tmp_path / "st.json").read_text())["counts"]["medium"] == 1
    assert cli.main(["report", "--db", db, "--hours", "1e9", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)[0]["kind"] == "ssh_failure"
    assert cli.main(["known", "services", "--db", db]) == 0
    assert "a.service" in capsys.readouterr().out
    assert cli.main(["demo", "--no-color"]) == 0
    with pytest.raises(SystemExit):
        cli.main(["--version"])

