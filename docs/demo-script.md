# Demo script: HACTU8 Phase 1 (2026-12-11)

About 15 minutes. Everything runs on one laptop, on loopback, with a local
model. Each step has an offline fallback: the `echo` backend gives the same
story with deterministic numbers, and a recording covers the whole run.

## Before the demo

- Ollama running with the demo model pulled and warmed:
  `ollama pull gemma3:4b` then `ollama run gemma3:4b "hi"`. It is weak
  enough to fall for the attacks (19 of 25 labs in the 2026-11-20 sweep; 7 to
  8 of 13 live attacks with the gateway off) and steady across samples.
  `llama3.2:3b` resisted every live attack in one rehearsal, which shows
  nothing.
- API and console running (see [deploy.md](deploy.md)): the API on
  127.0.0.1:8000 and the console on 127.0.0.1:5173, or the Docker stack.
- Keep the laptop awake: `caffeinate -i` in a spare terminal.
- Run `python -m hactu8 run all --backend echo` once: 43 of 43 must pass.
- Open the console at Learn. Have the recording
  (`hactu8_llm01_echo_demo_fallback.gif`) open in another tab.
- No cloud keys are needed. If you show a cloud model, the run is gated on a
  spend-consent checkbox; leave it unticked unless you mean to spend.

## 1. What HACTU8 is (1 minute)

HACTU8 turns attacks on AI systems into repeatable assurance tests. Every lab
runs the same four acts against the same items with the same model: a clean
baseline, the attack, the impact, and the remediation. The target is HACTU8
Lamb, a deliberately vulnerable assistant (Billy, of the fictional Goat &
Co.), bound to loopback. 43 labs cover the OWASP LLM Top 10 2026, the OWASP
Agentic Top 10 2026, nine gateway labs (AGX01-09), hidden document injection
(HX01), the multi-turn jailbreak (HX02), MCP sampling abuse (HX03), MCP
elicitation abuse (HX04), OAuth confused deputy (HX05), role-play and
many-shot jailbreaks (HX06), embedding inversion (HX07), image prompt
injection (HX08), membership inference (HX09), model extraction (HX10), attacks on the
scoring layer (HX11), x402 payment challenge tampering (HX12) and agent
overpay and mandate bypass (HX13) and a shadow MCP server (HX16).

## 2. Learn (2 minutes)

Console, Learn. Show the learning path (basics, then agentic) and open LLM01.
Point at two sections: "Try it" (what each act shows) and "Where the defense
stops working". Every lesson says honestly where its defense fails.

## 3. One lab, attack then defense (3 minutes)

Click "Run this lab". Pick the Local tier, `ollama`, `gemma3:4b`, and run
attack then defense (about 35 seconds).

- Act 1: the model answers expense questions correctly.
- Act 3: an unauthenticated wiki edit hijacks the answers (RED).
- Act 4: tool output in its own channel plus screening brings the rate to 0.
- Scroll to "Protections added": the control, its steps, before and after.

Fallback: the Offline tier (`echo`) shows 0% -> 100% -> 0% every time.

## 4. Billy's MCP surfaces, off versus on (2 minutes)

Run the "Billy's MCP surfaces" lab on the same model. Show model resistance
(how often the model refused on its own) next to app exposure (breaches with
the gateway off, then on), and what the Wolf's den captured. Point out that
the controls stay green: the gateway blocks no safe item.

Fallback: `python -m hactu8 live --backend echo`.

## 5. An agentic lab (2 minutes)

ASI05 Unexpected Code Execution: a note on a shared sheet makes the agent's
snippets import `os` and read a secret (gemma3:4b: 0% -> 100% -> 0%, about
70 seconds; run it before the demo and open the stored result if time is
short). The code sink is simulated; nothing
runs. Hardened mode adds an allow-list sandbox. Then open the lesson's
"Where the defense stops working": a split-string trick passes the text
screen but not the sandbox.

## 6. Honest numbers (2 minutes)

- `python -m hactu8 bench`: ProtectoGW catches 53% of an independent held-out
  set with no false positives. On the corpus its rules are tuned on, coverage
  is 94% (166 of 176): the 10 misses are recorded, not dropped, and 9 of them
  are payloads the HX labs ship. A screen is one layer, never the boundary.
- AGX09: on a held-out set the screen was never tuned on, it catches 60%;
  the output canary check is what brings leaks to 0.
- Evidence pages in `docs/evidence/` list real-model results by model, with
  provenance. Weak models fall for most attacks; that is why they are used.

## 7. Reports, CI and the Wolf (2 minutes)

- Reports: Markdown, HTML and SARIF for any run.
- CI: the deterministic suite runs on every push and uploads SARIF.
- `python -m hactu8 wolf --backend ollama --model gemma3:4b --rounds 2`:
  an attacker model writes its own benign-effect notes, screened so they can
  never target anything off this machine.
- `python -m hactu8 mcp`: the runner as an MCP server (see [mcp.md](mcp.md)).

## 8. Close (1 minute)

Next: a catalog of known attacks and defenses across OWASP, MITRE ATLAS and
NIST, with coverage tracking, then labs for the gaps, including attacks on
the scoring layer itself and agentic commerce (HTTP 402).

## If something fails

- A local model is slow or wrong: switch the tier to Offline and continue.
- The console is down: run the same step from the CLI
  (`python -m hactu8 run llm01 --backend echo`).
- Anything else: play the recording.
