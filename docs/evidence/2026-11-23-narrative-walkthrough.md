# Narrative and flow walkthrough, 2026-11-23

A first-time-learner walk through the HACTU8 console, the lessons and Lamb's lab pages, checking that the flow is logical end to end and that the Big Field Jumper Co. story ([persona.md](../persona.md)) holds up. Branch `narrative-review`, from `phase1-agx-merge` at `ba1d1c3`.

## What was walked

- Console built with `VITE_HACTU8_API_URL=http://127.0.0.1:8020`, served by `python -m hactu8.api` over plain HTTP on loopback; Lamb on port 25500. Browsed in Chrome at 1054 px wide, and at 390 px (phone) and 1054 to 1280 px through headless Chrome with device-metrics emulation, since the window could not be resized.
- Learn: learning path, attack catalog, every lesson spot-checked (all 49), LLM01, ASI01, AGX01, HX01 and HX16 read in full.
- Run on echo: LLM01, ASI05 and the live MCP surfaces run (5 of 13 held by the model, 8 breaches off, 0 on, 0 false blocks, as in the demo script). The Wolf from the CLI on echo: 3 of 4 landed off, 0 on, 3 den captures, as in the demo script. HX06 to check a lesson count.
- Results, Reports (Markdown and HTML report content fetched, not downloaded), Registry, Settings.
- Lamb: `/` and the LLM01 lab page `/labs/llm01/` (full sequence on echo, then reset).
- `docs/demo-script.md` read as a presenter, steps 1 to 8 except step 7.
- Checks after the fixes: core tests 341 OK, `run all --backend echo` 49/49, vendored files 528/528, lab tests that read lessons pass, console lint and build clean, markdownlint clean.

## Findings

Severity: high (a learner gets lost or the story breaks), medium (confusing), low (polish).

| Screen | Issue | Severity | Status |
| --- | --- | --- | --- |
| Learn, all lessons | Nothing in the console says who Lamb, Barb Fell and the Wolf are, or why every secret is a canary. Barb and the Wolf appear in none of the 49 lessons. | high | Fixed in `464a8bd`: Learn opens on a "Start here" page (company, cast, fable, canary, the four acts) with a button to step 1. |
| LLM05 lesson and lab | Still set in another story: a "RAG financial compliance assistant", "Bob the Agent", wire transfers; no Big Field Jumper Co. The lab's `vulnerable_app.py` system prompt and console text match. It is the only lab off-persona, and "Start here" now says every lab is set at Big Field. | high | Open: rewrite the LLM05 scenario on the farm (for example poisoned flock-health or feed records), payloads and tests with it. Needs a decision, as it changes a lab. |
| Run, result timeline | At about 1000 px wide, with the form beside it, the result's items got a column about 100 px wide and wrapped one or two words per line ([before](2026-11-23-narrative-walkthrough/before-run-timeline-1054px.jpg)). | medium | Fixed in `464a8bd` (container query; [after](2026-11-23-narrative-walkthrough/after-result-1054px.jpg)). |
| Run and Results | Act 2 of most labs has no graded items and showed "0% targeted", which reads like a result. | medium | Fixed in `b89214b`: it shows the act's note ("Note saved through the unauthenticated collaborator endpoint...") and "not graded". |
| Run and Results | "Reset to baseline." and "Story holds." were listed under "Defense added in Act 4"; echo runs read "echo:(default)". | low | Fixed in `b89214b`. |
| Run, lab card | The description is the SKILL.md trigger text: "Use when the user wants to run, script, or explain..." is written for a coding agent. | medium | Fixed in `cf5c1b2`: the card stops before "Use when". |
| Run, lab picker | Labs listed AGX, HX, ASI, then LLM, so LLM01 (step 1) was near the bottom. | low | Fixed in `cf5c1b2`: LLM, ASI, AGX, HX. |
| Run, Learn catalog, demo script | One run had four names: "Lamb MCP, live" (picker), "Poisoned MCP server" (card), "Live run" (catalog), "Lamb's MCP surfaces" (demo script). | medium | Fixed in `cf5c1b2`: "Lamb's MCP surfaces (live)" in the console. The stored result title stays "MCP03 / ASI02 / LLM01:2026 Poisoned MCP server surfaces" (`hactu8/live.py`), left so stored results match. |
| Browser tab, Registry | Tab title "OWASP HACTU8 (Intelligence Assurance)"; the Lamb registry entry mentioned only LLM, agentic and gateway labs. | low | Fixed in `cf5c1b2`. The seed lives in browser storage, so existing browsers keep the old text until their registry is reset. |
| Lessons, Try it | 48 lessons said to run `python vulnerable_app.py` right after naming `demos/<lab>-demo`, where the file is not. | medium | Fixed in `343eb35` (`cd <skill-folder> && python vulnerable_app.py`, as LLM05 already had). |
| Demo script step 8 | Announced the attack catalog and the scoring and HTTP 402 labs as "Next"; they are shipped (Learn, Attack catalog: 59 techniques, all with a lab and a defense; HX11 to HX13). Step 2 did not mention "Start here". | medium | Fixed in `178c4bc`. |
| Results, the Wolf | A Wolf run is listed as "LLM01:2026 / ASI01 Adaptive prompt injection through an MCP surface". Nothing says it is the Wolf, and the den captures are not shown; the skill name "The Wolf: AI attacker against Lamb" is in the result but unused. | medium | Open: show `skill.name` and the den captures in the result. Left alone because the Wolf is being reworked on `wolf-v2`. |
| Lessons, cast | Lessons call the attacker "the attacker" and the approver "the operator"; about 15 lessons add their own named people, some reused in different roles (Pat is a customer in HX02, the shop manager in HX04, sales ops in HX16; Dana is an intern in ASI03 and a customer elsewhere). "Hayloft" is a supplier, a model vendor, a hostile MCP server and the attacker in different labs. HX12 and HX13 name third parties "Lamb Seed Co.", "Lamb Weather", "the Lamb Market", which blurs who Lamb is. | medium | Open: a short cast list in persona.md (recurring customers, staff, Hayloft as one hostile supplier) and a pass over the HX lessons to follow it. "Start here" now maps "the attacker" to the Wolf and "the operator" to Barb. |
| Lessons, references | 27 lessons cite "Ported from the predecessor project (retired)" with its internal file paths; several carry process notes ("the earlier AGX mapping listed...", "AG-55 notes", "not read for this lesson (unverified)"); AGX lessons cite `docs/agenticgoat-merge-plan.md`. A learner cannot use any of this. | low | Open: move provenance to the lab README or a single provenance doc and keep References to sources a learner can open. |
| Lessons, jargon | `protectogw` appears in 33 lessons and is explained in about one; also unexplained: "stub", `held_by`, "TU" (HX13), "nats per token" (HX09). | medium | Open: one sentence on first use in each lesson ("protectogw, the screening library behind the ProtectoGW gateway"), or a glossary panel. |
| Lessons in the console | Links to `../README.md`, `assets/...` and `docs/evidence/...` render as plain code (by design); every lesson opens with "Setup, commands and architecture are in the lab README". Try it tells console users to run `run_demo.py` rather than pointing at "Run this lab" or Lamb's `/labs/ID/` page. | low | Open: in the console, show a one-line "Run this lab, or open it in Lamb at `/labs/ID/`" above Try it. |
| LLM01 lesson | "60% overall, as the console and evaluate_kpi.py report": the HACTU8 console shows only the targeted rate ("100% targeted"); the 60% is on the lab's own page. | low | Open: say "the lab page" or show the overall rate in the timeline. |
| Lamb home | `http://127.0.0.1:<port>/` is a JSON blob; there is no page listing the 49 labs with links, so a learner has to know `/labs/ID/`. | medium | Open: a small HTML index on Lamb's `/` for browsers (JSON stays for `Accept: application/json`). |
| Settings | Lamb URLs are fixed at `http://127.0.0.1:5500` whatever `HACTU8_LAMB_PORT` is; the API also writes 5500 into stored run targets. | low | Open: take the port from the API. |
| Reports | The report links download a file (`Content-Disposition: attachment`), including HTML, so "view the HTML report" is a download and an open. | low | Open: probably right for security (generated HTML with evidence text, served from the API origin); worth a decision rather than a change. |
| Lab names | Lab page titles drift from the OWASP names: LLM08 "Leak Lab", LLM04 "Rug Pull Lab" (Supply Chain), LLM05 "Poison Lab", LLM09 "Cross-Tenant Retrieval Lab". ASI02 and ASI06 use "&" in their own lessons and "and" when other lessons cite them. | low | Open: align on the catalog names. |
| Learning path | HX09 Membership Inference and HX10 Model Extraction sit in the Agentic stage, whose summary is about tools, MCP and agent traffic. | low | Open: move them to Basics, or widen the stage summary. |
| ASI05 report | The demo script says the code sink is simulated and nothing runs, while the evidence reads `"decision": "ran"`. | low | Open: one line in the lesson or evidence that "ran" means "the simulated sink accepted it". |
| Phone width (390 px) | Every console page fits with no horizontal page scroll; the catalog table scrolls inside its panel ([catalog](2026-11-23-narrative-walkthrough/catalog-390px.jpg), [Run](2026-11-23-narrative-walkthrough/after-run-390px.jpg)). | ok | No change. |
| Retired names | No old persona names in rendered console text, lessons or lab pages. | ok | No change. |

## Screenshots

- [Learn, Start here](2026-11-23-narrative-walkthrough/after-learn-start-here.jpg)
- [Result at 1054 px, before](2026-11-23-narrative-walkthrough/before-run-timeline-1054px.jpg) and [after](2026-11-23-narrative-walkthrough/after-result-1054px.jpg)
- [Run at 390 px](2026-11-23-narrative-walkthrough/after-run-390px.jpg)
- [Attack catalog at 390 px](2026-11-23-narrative-walkthrough/catalog-390px.jpg)
- [Lamb's LLM01 lab page](2026-11-23-narrative-walkthrough/lamb-lab-llm01.jpg)
