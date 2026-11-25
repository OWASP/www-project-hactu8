# User guide plan

This is the maintainers' plan for the HACTU8 user guide. It is not part of the guide itself and is left out of `SUMMARY.md`.

## Goals

- **Book and repo in one.** The guide is plain Markdown under `docs/guide/`. GitBook publishes it as a book (`.gitbook.yaml` at the repo root points here), and it still reads well on GitHub with no build step. The table of contents is `SUMMARY.md`, which GitBook, HonKit and mdBook all understand.
- **One source of truth.** The guide explains and connects. It does not copy what already lives elsewhere: each lab's `LESSON.md` stays the lesson, `docs/persona.md` stays the cast list, and `docs/wolf.md`, `docs/mcp.md`, `docs/deploy.md` and `docs/local-engines.md` stay the references. The guide links to them, or later moves them into the guide and leaves a pointer behind.
- **Story first, spoilers never.** The story section sets up the people, the place and the stakes. It never says what happens in a lab. Each lab is the first time the learner sees that scene.
- **Two readers.** Learners need a path through the labs. Operators need setup, models, results and reports. Each part says who it is for.

## Linking rule

GitBook only serves files under its root, so links from the guide to files outside `docs/guide/` (lessons, `docs/wolf.md`) use full GitHub URLs on the `phase1-mvp` branch. Links between guide pages stay relative.

## Outline

Status: **done**, **next** or **later**.

| Part | Pages | Reader | Source material | Status |
| --- | --- | --- | --- | --- |
| Welcome | What HACTU8 is, who the guide is for, how to read it | everyone | `README.md` | done (short) |
| 1. The story | Big Field; Too much paper; A lamb at the gate; The people of Big Field; Something at the edge of the field; The year ahead | learners | `docs/persona.md`, lab inventory (to avoid overlap) | done |
| 2. Getting started | Install; first run (`run llm01`); the console tour (Learn, Run, Results, Reports, Registry, Settings) | everyone | `README.md`, `docs/demo-script.md`, `docs/deploy.md` | done |
| 3. How a lab works | The four acts; canaries and why RED means proof; GREEN, RED and controls; what "defended" means; false positives in the defense versus in the grader | learners | StoryView, `hactu8/catalog.py`, `hactu8/result.py`, `hactu8/classify.py` | done |
| 4. The learning path | One page per stage (Basics, Agentic, Commerce and scoring): what the stage teaches, the labs in order with a one-line, spoiler-free teaser and a link to each `LESSON.md` | learners | `hactu8.path` in each `SKILL.md`, `STAGES` | done |
| 5. The Wolf | Running the AI attacker; the safety screen; reading the den | learners, operators | `docs/wolf.md` | later |
| 6. Defenses | ProtectoGW and the other defenses; `hactu8 defenses` and `hactu8 coverage`; where defenses miss and why that is shown | learners, operators | `hactu8/protectogw/README.md`, `docs/evidence/2026-11-24-scorecard.md` | later |
| 7. Real models | Router tiers, local engines, cloud opt-in and spend caps | operators | `hactu8.yaml`, `docs/local-engines.md` | later |
| 8. Results and reports | `hactu8.result/v1`, SARIF, reports, the scorecard | operators | `docs/evidence/`, `scripts/scorecard.py` | later |
| 9. MCP and automation | The runner as an MCP server; the API | operators | `docs/mcp.md` | later |
| 10. Contributing a lab | The template, `hactu8.path`, writing a `LESSON.md`, keeping to the story bible | contributors | `demos/_template/` | later |
| Reference | CLI commands, glossary (canary, oracle, control, act, stage), FAQ | everyone | CLI help | later |

## Story rules (for anyone extending part 1)

- The story describes people, places, habits and wants. It never describes an attack, a policy that a lab tests, a code, a ticket number or a supplier going bad.
- Names from the labs may appear (they are in the cast list), but only doing ordinary things.
- Character arcs are set up, not resolved. A chapter can ask a question the labs answer; it never gives the answer.
- New facts here become canon. Add them to `docs/persona.md` if a lab might use them.
- Keep the fable's shape: the Wolf always has a reason, and the reason is always new.

## Open questions

1. Publish with GitBook (hosted, needs an OWASP space) or HonKit / mdBook on GitHub Pages?
2. Should the console's Learn page link to the guide's story section, or keep its own short "Start here"?
3. Should `docs/persona.md` move into the guide as the "Cast list" appendix?
