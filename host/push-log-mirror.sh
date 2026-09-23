#!/bin/sh
# Push the static log to the `incoming` branch of DanceNitra/inspeximus-log. Runs as ubuntu.
#
# THE ONLY CREDENTIAL IS A DEPLOY KEY for that one repository, generated on this host, and a
# ruleset keeps it off `main`. It cannot publish: the workflow on `main` verifies the snapshot
# against the pinned key and the history already live, and deploys Pages only if both hold.
# Nothing private is pushed: /srv/static-log is the public log, byte for byte.
set -eu
REPO=/home/ubuntu/inspeximus-log
KEY=/home/ubuntu/.ssh/inspeximus_log_deploy
export GIT_SSH_COMMAND="ssh -i $KEY -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes"

if [ ! -d "$REPO/.git" ]; then
  git clone --branch incoming --single-branch git@github.com:DanceNitra/inspeximus-log.git "$REPO"
fi
cd "$REPO"
git fetch -q origin incoming
git reset -q --hard origin/incoming
# log/ is the FIRST log, frozen at 10 entries on 2026-09-23: copied, never regenerated.
# current/ is the second log, origin dancenitra.github.io/inspeximus-log, which grows.
rm -rf log current && mkdir log current
cp -a /srv/static-log/. log/
cp -a /srv/static-log-v2/. current/
git add -A log current
if git diff --cached --quiet; then
  echo "$(date -u +%FT%TZ) nothing new"
  exit 0
fi
n=$(python3 -c "import json;print(json.load(open('current/head.json'))['n_writes'])")
git -c user.name="inspeximus-log host" -c user.email="log-host@users.noreply.github.com" \
  commit -q -m "snapshot: $n entries"
git push -q origin incoming
echo "$(date -u +%FT%TZ) pushed snapshot of $n entries"
