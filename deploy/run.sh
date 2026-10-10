#!/bin/bash
# Hourly: detect new Ad-Shield domains (decoded script + Pi-hole log); reload gravity only if any were added.
cd /opt/adshield || exit 1
echo "== $(date '+%F %T')"
python3 detect_adshield.py --db /etc/pihole/pihole-FTL.db --hours 24
rc=$?
if [ $rc -eq 2 ]; then
  chmod 644 blocklist.txt
  # gravity rebuilds the list; reloadlists makes FTL start answering from it immediately
  pihole -g >/dev/null 2>&1 && pihole reloadlists >/dev/null 2>&1 && echo "gravity reloaded"
fi
exit 0
