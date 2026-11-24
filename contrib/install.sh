#!/bin/sh
# Install Themis as a systemd *user* timer (no root). Run from the repository root.
# ./contrib/install.sh           install or update
# ./contrib/install.sh --remove  stop and remove the timer (keeps the database)
set -eu
units="$HOME/.config/systemd/user"
code="$HOME/.local/share/themis"
if [ "${1:-}" = "--remove" ]; then
    systemctl --user disable --now themis.timer 2>/dev/null || true
    rm -f "$units/themis.service" "$units/themis.timer"
    rm -rf "$code/themis"
    systemctl --user daemon-reload
    echo "Themis timer removed (state kept in ~/.local/state/themis)."
    exit 0
fi
if ! journalctl -q -n 1 SYSLOG_FACILITY=10 >/dev/null 2>&1 || [ -z "$(journalctl -q -n 1 SYSLOG_FACILITY=10 2>/dev/null)" ]; then
    echo "Note: this user cannot read the system journal's auth messages."
    echo "      Add yourself to the adm group: sudo usermod -aG adm \"$USER\" (then log in again)."
fi
mkdir -p "$units" "$code"
rm -rf "$code/themis"
cp -r themis "$code/themis"
find "$code/themis" -name '__pycache__' -prune -exec rm -rf {} +
cp contrib/themis.service contrib/themis.timer "$units/"
systemctl --user daemon-reload
systemctl --user enable --now themis.timer
echo "Themis runs every 5 minutes. Status: ~/.local/state/themis/status.json"
echo "First scan now (learns the last 30 days):"
systemctl --user start themis.service && python3 -c 'import sys; sys.path.insert(0, "'"$code"'"); from themis.__main__ import main; sys.exit(main(["report", "--hours", "720"]))'
