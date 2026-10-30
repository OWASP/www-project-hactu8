#!/usr/bin/env bash
# Seed Phase 1 MVP issues from the wiki's Phase-1-MVP-Plan work items.
# Requires: gh (authenticated with write access to OWASP/www-project-hactu8).
# Safe to re-run: skips any issue whose title already exists.
set -euo pipefail
REPO="${REPO:-OWASP/www-project-hactu8}"
M2="P1:M2: Requirements Documentation"
M3="P1:M3: Running Demo"
PLAN="https://github.com/OWASP/www-project-hactu8/wiki/Phase-1-MVP-Plan"

desc() {
  case "$1" in
    m0) echo "M0 Hygiene" ;; m1) echo "M1 Contract + runner" ;; m2) echo "M2 Router + adapters" ;;
    m3) echo "M3 Lamb" ;; m4) echo "M4 API + console + reports" ;; m5) echo "M5 Ship + AI attacker" ;;
    m6) echo "M6 Harden + rehearse" ;;
  esac
}

echo "Labels"
gh label create "phase1-mvp" --repo "$REPO" --color 0E8A16 --description "Phase 1 MVP" --force >/dev/null
for ws in m0 m1 m2 m3 m4 m5 m6; do
  gh label create "mvp:$ws" --repo "$REPO" --color 1D76DB --description "$(desc "$ws")" --force >/dev/null
done

echo "Milestone due date: $M3 -> 2026-11-13"
num=$(gh api "repos/$REPO/milestones?state=open&per_page=100" --jq ".[] | select(.title==\"$M3\") | .number")
gh api -X PATCH "repos/$REPO/milestones/$num" -f due_on="2026-11-14T04:59:59Z" >/dev/null

ITEMS=(
  "m0|H-01|Create phase1-mvp branch from reference-solution"
  "m0|H-02|Remove empty stubs (engine/, services/, scan/, specs/, skills/)"
  "m0|H-03|Root README: what it is, quick start, layout"
  "m0|H-04|Seed issues and labels; set P1:M3 due date to 2026-11-13"
  "m0|H-05|Close P1:M1 Mockup (iac-prototype and agenticgoat-mock satisfy it)"
  "m1|H-10|Result JSON Schema (run, skill, target, items, verdicts, metric)"
  "m1|H-11|metadata.hactu8.* key spec for SKILL.md"
  "m1|H-12|hactu8 CLI: list, run, results"
  "m1|H-13|Lab adapter; LLM01 and LLM05 emit Results"
  "m1|H-14|Classifier interface with keyword backend"
  "m2|H-20|Canonical providers package lifted from the labs"
  "m2|H-21|hactu8.yaml router tiers and escalation rules"
  "m2|H-22|Adapters for LLM02–04 and LLM06–10"
  "m2|H-23|llm-judge and jev classifier backends (jev behind a flag)"
  "m2|H-24|Canonical protectogw package"
  "m3|H-30|Lamb service hosting the lab targets on one process and port map"
  "m3|H-31|Lamb vulnerable MCP server (tool poisoning, rug pull)"
  "m3|H-32|Rename AgenticGoat references to Lamb (seed, consoles, docs)"
  "m3|H-33|Lamb Registry entry with live targetUrl"
  "m4|H-40|FastAPI: skills, runs, results, reports endpoints"
  "m4|H-41|Trim iac-host: remove Streamlit remote and unused routes"
  "m4|H-42|Console pages wired to the API: Run, Results, Reports"
  "m4|H-43|Report builder: Markdown, HTML, SARIF"
  "m4|H-44|branding.yaml applied to console and report header"
  "m5|H-50|Dockerfile and docker compose up for core, console, Lamb"
  "m5|H-51|Devcontainer / Codespaces"
  "m5|H-52|GitHub Action: deterministic suite → SARIF upload"
  "m5|H-53|AI attacker skill (generate, mutate, score) against Lamb"
  "m5|H-54|HACTU8 MCP server exposing the runner"
  "m6|H-60|Fresh-clone test on macOS, Linux, Codespaces"
  "m6|H-61|Demo script and recorded fallback"
  "m6|H-62|Update [[Project Status|Project-Status]] and OWASP project page marks"
)

existing=$(gh issue list --repo "$REPO" --state all --limit 500 --json title --jq '.[].title')
for row in "${ITEMS[@]}"; do
  IFS='|' read -r ws id text <<<"$row"
  title="$id $text"
  if grep -Fxq "$title" <<<"$existing"; then echo "skip  $title"; continue; fi
  case "$ws" in m0|m1) ms="$M2" ;; *) ms="$M3" ;; esac
  gh issue create --repo "$REPO" --title "$title" --milestone "$ms" \
    --label "phase1-mvp" --label "mvp:$ws" \
    --body "Workstream: $(desc "$ws"). Plan: $PLAN" >/dev/null
  echo "added $title"
done
