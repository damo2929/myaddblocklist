#!/bin/bash
# Hourly (cron): detect new Ad-Shield domains, reload Pi-hole, and push blocklist changes to GitHub.
# /opt/adshield is a clone of github.com/damo2929/myaddblocklist. Pushing needs a write deploy
# key at $KEY; without it the list is still updated and reloaded locally, just not pushed.
KEY=/root/.ssh/adshield_deploy
cd /opt/adshield || exit 1
echo "== $(date '+%F %T')"

[ -f "$KEY" ] && export GIT_SSH_COMMAND="ssh -i $KEY -o IdentitiesOnly=yes -o BatchMode=yes"

# Pick up repo changes first so our commit applies cleanly; reload if the list changed upstream.
before=$(git hash-object blocklist.txt)
git pull -q --rebase --autostash || echo "git pull failed; continuing with local copy"
reload=0
[ "$before" != "$(git hash-object blocklist.txt)" ] && reload=1

python3 detect_adshield.py --db /etc/pihole/pihole-FTL.db --hours 24
rc=$?
chmod 644 blocklist.txt

# Commit only when blocklist.txt actually differs from what's committed; nothing else is staged.
if ! git diff --quiet -- blocklist.txt; then
  reload=1
  added=$(git diff -U0 -- blocklist.txt | grep -oP '^\+\|\|\K[^^]+' | paste -sd, -)
  git add -- blocklist.txt
  git commit -q -m "blocklist: add ${added:-new domains}" \
    -m "Auto-detected on the Pi-hole by detect_adshield.py." -- blocklist.txt && echo "committed: ${added}"
elif [ $rc -eq 2 ]; then
  reload=1
fi

if [ $reload -eq 1 ]; then
  # gravity rebuilds the list; reloadlists makes FTL start answering from it immediately
  pihole -g >/dev/null 2>&1 && pihole reloadlists >/dev/null 2>&1 && echo "gravity reloaded"
fi

# Push only if there are blocklist commits not yet on GitHub (incl. ones from failed pushes).
if [ -n "$(git log --oneline '@{u}..' 2>/dev/null)" ]; then
  if [ -f "$KEY" ]; then
    git push -q && echo "pushed to GitHub" || echo "git push failed; will retry next run"
  else
    echo "no deploy key at $KEY; commits kept locally"
  fi
fi
exit 0
