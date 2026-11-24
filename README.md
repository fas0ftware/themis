# Themis

![Version](https://img.shields.io/badge/version-0.1.0-blue)
![Python](https://img.shields.io/badge/python-3.11%2B-informational)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)
![License](https://img.shields.io/badge/license-MIT-green)

**Themis watches your Linux laptop's system journal and tells you what you
should know about**: someone guessing your password at the lock screen, sudo
used by an account that is not allowed to, SSH logins and brute force, a new
USB stick, a "keyboard" nobody plugged in on purpose, and a service that has
never run on this machine before.

It only **reads** the journal (`journalctl`, no root), keeps its own small
SQLite database, and can push alerts to your phone with [ntfy](https://ntfy.sh).
Its status file feeds the [Olympos](https://github.com/fas0ftware/olympos)
dashboard, next to Aegis, which checks how the laptop is *configured*; Themis
watches what *happens* on it.

```
$ themis report --hours 24
Themis 0.1.0 · last 24 h · low and above
2026-11-24 10:30  medium   sudo gave up after 3 wrong password(s) for alex: /usr/bin/apt upgrade
2026-11-24 13:30  low      New USB device: SanDisk Cruzer Blade (0781:5567)
2026-11-24 16:30  medium   A service ran for the first time: updater-helper.service
2026-11-24 18:40  high     A new USB device that types like a keyboard was plugged in: unnamed device (1a86:e026). If it is not a keyboard you just connected, unplug it (BadUSB).
2026-11-24 19:21  high     5 failed logins in 10 minutes from ssh 203.0.113.7: someone may be guessing passwords
```
<sub>(`themis demo`: fictional events, documentation addresses.)</sub>

## What it reports

| Event | Severity | When |
|---|---|---|
| `auth_failure` | low | A wrong password at sudo, su, the lock screen, a text console or an admin (polkit) prompt |
| `sudo_failed` | medium (3 tries) | sudo gave up after wrong passwords, with the command that was attempted |
| `sudo_not_allowed` | high | An account that is not in sudoers tried sudo |
| `ssh_failure` | medium | SSH: wrong password or key, or an unknown user name |
| `ssh_login` | medium | SSH login accepted, with method and source address |
| `brute_force` | high | 5 failures from one source (an address, or a user at one service) within 10 minutes; once per hour |
| `usb_new` | low | A USB device this laptop has never seen (vendor:product:serial) |
| `usb_keyboard` | high | A *new* USB device that registers as a keyboard: a "charging cable" or stick that types commands (BadUSB) |
| `new_service` | medium | A system service, timer, socket or path unit started for the first time: software that installs itself to start on its own |

The first run reads the last 30 days and **learns** what is normal: the USB
devices and services already there are remembered without an alert, and old
failed logins are stored for the report but never pushed to the phone. Root
hubs, template instances (`backup@home.service` counts as `backup@.service`),
sessions and transient units are left out.

## Install

Python 3.11+, no dependencies. Reading the system journal needs the `adm` (or
`systemd-journal`) group, which the first user on Ubuntu already has
(`id` shows it); otherwise `sudo usermod -aG adm $USER` and log in again.

```sh
git clone https://github.com/fas0ftware/themis && cd themis
python3 -m themis                  # first run: learns the last 30 days
python3 -m themis report --hours 720
./contrib/install.sh               # systemd user timer: a scan every 5 minutes
```

`./contrib/install.sh --remove` stops and removes the timer; the database in
`~/.local/state/themis/` stays.

### Phone alerts

Put an ntfy topic in `~/.config/themis/env` (pick a long, hard-to-guess topic:
anyone who knows it can read the alerts):

```sh
THEMIS_NTFY_URL=https://ntfy.sh/a-long-random-topic
THEMIS_ALERT_MIN=medium      # info, low, medium (default), high, critical
```

An alert that could not be delivered is retried on the next scan.

## Commands

| Command | Does |
|---|---|
| `themis` / `themis scan` | Read new journal entries; `--save [PATH]` writes the status file, `--ntfy URL` pushes, `-q` prints nothing |
| `themis report [--hours N] [--min SEV] [--json]` | Stored events |
| `themis known usb` / `themis known services` | What counts as already seen |
| `themis demo [--json]` | Fictional events, or the status file Olympos would read |

`--db PATH` (or `THEMIS_DB`) picks another database.

## Status file

`themis scan --save` writes `~/.local/state/themis/status.json`: version,
time, the worst severity of the last 24 hours (`level`) and a `verdict`
(`quiet`, `watch` from medium, `alert` from high), counts per severity and
kind, the ten newest events, and how many USB devices and services are known.
Olympos reads it.

## Security and privacy

- **Read-only**: Themis runs `journalctl` with a fixed argument list and asks
  only for auth/authpriv messages, kernel messages and PID 1's "unit started"
  messages. It never changes the system.
- **Hostile text**: an SSH user name is typed by whoever connects. Every value
  is reduced to printable ASCII (no terminal escapes, no bidi or zero-width
  tricks) and capped before it is stored, printed or sent; links and mentions
  are broken in phone alerts.
- **Owner-only files**: the database and the status file are created `0600`
  in a `0700` directory, since they name users and addresses.
- **No passwords**: PAM and sshd never log the password itself; a user name
  field can hold one if someone typed it there, which is why names are capped.

## Tests

```sh
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m pytest -q
```

16 tests with a fake `journalctl`: every rule on real log lines, hostile user
names, the silent baseline, a keyboard-like USB device, a stick plugged in
twice, brute force (and failures too spread out to be one), a rotated-away
cursor, alert retry, file permissions, the CLI. CI also runs a real scan of the
runner's journal, and bandit.

On the author's laptop the first run read 376 279 journal entries from 30 days
in 16 seconds (35 before asking `journalctl` for only five fields) and learned
6 USB devices and 123 services; later scans take well under a second.

## Roadmap

- New listening ports (from `ss`), to complement Cerberus' view from the network.
- A trusted-USB list with names, and an `ignore` command for known noise.
- Login from a new network (SSH from an address range never seen before).

## License

[MIT](LICENSE)
