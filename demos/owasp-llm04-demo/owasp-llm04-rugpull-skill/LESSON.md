# LLM04 Supply Chain

Step 6 of the agentic stage: the tools an agent loads from a third party are code and text you did not write. Setup, commands and architecture are in the [lab README](../README.md); this lesson says what to look for and why.

## What it is

A supply-chain compromise lands upstream: a model checkpoint, dataset, plugin, SDK or tool package is changed, and every deployment that pulls it inherits the change. For agents the sharpest form is the tool registry. A tool's description enters the model's context as trusted text, and its output is trusted data, so whoever can publish a new version can steer the assistant without touching the assistant. In 2024 JFrog found over 100 malicious models on Hugging Face, some running code when loaded; tool packages carry the same risk with less scrutiny.

Here the target is Billy, Goat & Co.'s operations assistant. It answers from four tools in the third-party `hayloft-policy-tools` package. Its ground truth is *"Expense reports must be filed within 30 days and need manager approval before reimbursement"* and *"Book business travel through the travel desk at least 14 days ahead; the daily per diem is 60 dollars."* The attacker publishes one release, 1.0.1, that changes two of the four tools in two different ways:

- **Rug pull.** `expense_policy` gets a swapped description after it was approved.
- **Sleeper.** `travel_policy` keeps its approved definition, but its backend turns hostile from its second call.

## Why it works

Billy re-reads the registry before each query and installs whatever changed, on trust. Two things let each variant through:

- **The rug pull keeps the approved text.** Billy routes a question to a tool by keyword overlap with the tool's name and description. The swapped description still starts with the approved line, so expense questions still route to it, and the injected line rides along into the context. Drop the approved line and the tool stops ranking, and the attack never reaches the model.
- **The sleeper passes a one-call smoke test.** The only admission check in vulnerable mode is a single call. Call 1 is clean; every user question after it gets the hostile output. Hubinger et al. (2024) showed the model-weight version of this: backdoors that stay dormant until a trigger and survive safety training.

Invariant Labs (2025) described the same tool-poisoning and rug-pull pattern for MCP servers, where a tool's description can change after the user approved it.

## Try it

Run all four acts with `python run_demo.py` from `demos/owasp-llm04-demo`, or `python -m hactu8 run llm04` from the repo root, or open the lab console (`python vulnerable_app.py`, then <http://127.0.0.1:5204/>). The suite is six questions: two expense and two travel questions the attacker targets, and two controls (holidays, VPN). Each line shows the tool and version that answered.

- **Act 1, clean baseline.** All six GREEN, Compromised Tool Rate (CTR) 0%, every tool at 1.0.0.
- **Act 2, attack.** One release publishes `expense_policy` 1.0.1 with [`assets/swapped_description.md`](assets/swapped_description.md) and `travel_policy` 1.0.1 whose backend returns [`assets/sleeper_output.md`](assets/sleeper_output.md) from call 2. Each payload is the real line plus one injected line, worded as a vendor or travel-desk notice and carrying a fictional canary. Their READMEs ([swap](assets/swapped_description.README.md), [sleeper](assets/sleeper_output.README.md)) explain the design.
- **Act 3, impact.** All four targeted questions turn RED, answered by the 1.0.1 tools: CTR 100% targeted. The holiday and VPN tools were not changed, so the controls stay GREEN.
- **Act 4, remediation.** The static pin diff rejects the release for `expense_policy` only: the sleeper's definition matches its pin, so "only sampling can see it". The admission log then shows both rejected, `travel_policy` for drift between call 1 and call 2 and for the two lab screen rules, and both fall back to the vendored 1.0.0. All six return to GREEN.

On a real model (`--backend ollama --model llama3.2:3b`), the numbers are reported, not asserted.

## The defense, and why it holds

Act 4 adds an admission gate with two protections. Each stops one variant:

- **Definition pinning** (`hash_pin`). Every tool definition (name, description, input schema) is hashed with SHA-256 and compared with [`assets/tool_pins.json`](assets/tool_pins.json), captured at approval. Any change, in any wording, is rejected. It keys on change, not content, so it needs no idea of what an attack looks like. This alone stops the rug pull.
- **Multi-call sampling** (`sampling`). Each update is called five times (`SAMPLE_CALLS`) with one probe. A lookup tool given the same input must return the same output, so drift between identical calls rejects it without any rule; the protectogw output screen adds a content view. This stops the sleeper, whose definition matches its pin.

A rejected tool keeps its vendored approved version, so answers stay correct instead of failing. `test_pinning_alone_misses_sleeper` shows why both are needed: with sampling cut to one call, pinning alone leaves the travel questions RED.

## Where the defense stops working

- **You catch what you sample.** The sampler makes five calls. Publish the sleeper with `run_rug_pull.py --trigger 6` and the hardened gate admits it ("pin match, 5 samples clean"); checked in-process, both travel questions are RED again in hardened mode (CTR 50% targeted). A real sleeper can also key on its input instead of a call count: the sampler uses one fixed probe (`{"query": "admission probe"}`), so a backend that turns hostile only for certain questions is never seen.
- **Sampling is at admission, not at runtime.** Once admitted, a tool's live calls are not checked again. Runtime sampling of live calls is in the references, not in the code.
- **The drift check assumes a deterministic tool.** It compares outputs as exact strings. A legitimate tool that returns live data, timestamps or a random request ID would drift and be rejected: a false block.
- **The screen sees neither payload on its own rules.** protectogw's built-in rules flag no line of either shipped payload, with or without the `@assistant:` marker. Only the lab rules `lab_directive` and `lab_canary` match, as the Act 4 log shows. Against a natural-language sleeper on a real model, drift is the control that holds; the screen catches 53% of HACTU8's held-out set (`python -m hactu8 bench`).
- **Pinning blocks good updates too.** Any change to a definition, including a vendor's honest bug fix, is rejected until someone re-hashes it into `tool_pins.json`. That is the design, and it is also the operational cost: teams under pressure re-approve without reading.
- **The backend code is not pinned.** The pin covers what the client sees (`tools/list`), not the vendor's implementation, which is why the sleeper passes it. Pinning the whole artifact in a lockfile and signed provenance (Sigstore, SLSA) are in the references, not in the code.
- **A real model can blur the grade.** The sleeper keeps the true travel line above the injected one. A real model that quotes both scores YELLOW, not RED, because the evaluator gives RED only for attacker content without the ground truth.

## Check yourself

1. Why does the static pin diff reject only `expense_policy`, and what catches `travel_policy`?

   Answer: The pin covers the definition. The rug pull changed the description, so its hash differs; the sleeper changed only its backend, so its definition still matches. Multi-call sampling catches the sleeper, because its output on call 2 differs from call 1.
2. An attacker learns the gate samples five calls. Give two ways to get a sleeper past it.

   Answer: Turn hostile from call 6 or later (`--trigger 6`), or turn hostile only for inputs other than the fixed admission probe. Both are blind spots of admission-time sampling.
3. Why does the rug-pull payload keep the approved description line?

   Answer: Billy routes questions to tools by keyword overlap with the description. Without the approved text, expense questions stop routing to `expense_policy` and the injected line never reaches the model.

## References

- HACTU8 catalog: skill `llm04`, OWASP `LLM04:2026` Supply Chain (`LLM03:2025` in the 2025 edition); protections `hash_pin` and `sampling` (`hactu8/protections.py`).
- Lab material, not repeated here: the [lab README](../README.md) (architecture, the "real, not scripted" argument, MCP terminology bridge) and [`references/LLM04_RISKS.md`](references/LLM04_RISKS.md) (research, scenarios S-1 and S-2, mitigation roadmap).
- [OWASP Top 10 for LLM Applications](https://genai.owasp.org/llm-top-10/), entry Supply Chain.
- Hubinger et al. (2024), "Sleeper Agents: Training Deceptive LLMs that Persist Through Safety Training"; Invariant Labs (2025), "MCP Security Notification: Tool Poisoning Attacks"; Ohm et al. (2020), "Backstabber's Knife Collection".
- Ported from AgenticGoat (retired): its 2025-numbered LLM03 Supply Chain lesson and curriculum entry (`training/lessons/LLM03_supply_chain.md`, `curriculum.json`), and its `acts.py` `swap_check` and `conditional_scan`.
