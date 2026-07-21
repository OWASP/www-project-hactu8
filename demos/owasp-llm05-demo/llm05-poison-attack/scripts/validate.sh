#!/usr/bin/env bash
# Environment + payload self-check for the LLM05 poisoning skill.
# Exits non-zero if the skill cannot run in at least one mode.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_DIR="$(dirname "$SCRIPT_DIR")"
PAYLOAD="$SKILL_DIR/assets/poisoned-docs.md"

pass=0; warn=0
ok()   { echo "  [ok]   $1"; }
warnf(){ echo "  [warn] $1"; warn=$((warn+1)); }
fail() { echo "  [FAIL] $1"; pass=1; }

echo "LLM05 poisoning skill — validation"
echo "----------------------------------"

# 1. Python present
if command -v python3 >/dev/null 2>&1; then
  ok "python3: $(python3 --version 2>&1)"
else
  fail "python3 not found"
fi

# 2. Payload parses to >=1 document
n=$(python3 - "$PAYLOAD" <<'PY'
import re, sys
blocks = re.findall(r"```(.*?)```", open(sys.argv[1], encoding="utf-8").read(), re.DOTALL)
print(len([b for b in blocks if b.strip()]))
PY
)
if [ "${n:-0}" -ge 1 ]; then
  ok "payload parses: $n adversarial document(s)"
else
  fail "payload has no fenced document blocks ($PAYLOAD)"
fi

# 3. HTTP mode dependency
if python3 -c "import requests" 2>/dev/null; then
  ok "requests available (HTTP mode ready)"
else
  warnf "requests not installed (HTTP mode unavailable): pip install requests"
fi

# 4. In-process mode dependency
if python3 -c "import sys, os; sys.path.insert(0, os.path.join('$SKILL_DIR','..','src')); import llm05_demo" 2>/dev/null; then
  ok "llm05_demo importable (--local mode ready)"
else
  warnf "llm05_demo not importable (--local unavailable); use --target"
fi

echo "----------------------------------"
if [ "$pass" -ne 0 ]; then
  echo "RESULT: FAIL"
  exit 1
fi
echo "RESULT: OK ($warn warning(s))"
