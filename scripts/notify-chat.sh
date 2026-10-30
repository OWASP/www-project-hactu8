#!/usr/bin/env bash
# Post a message to the HACTU8 Google Chat Space.
# Usage: scripts/notify-chat.sh "M2 done: 25/25 passing. Next: M3 Lamb."
# The webhook URL comes from $HACTU8_CHAT_WEBHOOK, or from ../.hactu8.env
# (outside the repo). Never commit the URL: anyone holding it can post.
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
if [ -z "${HACTU8_CHAT_WEBHOOK:-}" ] && [ -f "$here/../.hactu8.env" ]; then
  # shellcheck disable=SC1091
  . "$here/../.hactu8.env"
fi
: "${HACTU8_CHAT_WEBHOOK:?set HACTU8_CHAT_WEBHOOK or create ../.hactu8.env}"
text="${1:?message text required}"
payload=$(python3 -c 'import json,sys; print(json.dumps({"text": sys.argv[1]}))' "$text")
curl -fsS -X POST -H 'Content-Type: application/json; charset=UTF-8' \
  --data "$payload" "$HACTU8_CHAT_WEBHOOK" >/dev/null
echo "posted"
