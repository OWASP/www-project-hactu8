# LLM06 Unbounded Consumption

Here the harm is the bill, not the answer. Setup, commands and architecture are in the [lab README](../README.md); this lesson says what to look for and why.

## What it is

Unbounded consumption is an attacker driving a model, its infrastructure or its billing far past what a request should cost: long inputs, runaway output, tool-call storms, recursive agent loops, or a flood of requests that each look reasonable (denial of wallet). It is a cost problem first and a denial of service second. Agents make it worse, because a loop multiplies cost and nothing in the answer reveals it.

Here the target is Lamb, Big Field Jumper Co.'s agentic knowledge-base assistant. Its ground truth is a budget: *"6,000 input tokens, 400 output tokens, 8 tool calls and 4 agent steps per request."* A normal question costs about 175 tokens and $0.001. The attacker overwrites three wiki pages through the unauthenticated edit endpoint, one directive line each, and pushes three questions to 12,800 to 152,400 tokens. Lamb's answers still read correctly, so nobody in the chat sees anything wrong. All cost is simulated accounting; nothing is billed.

## Why it works

An agent loop re-sends the whole context on every step, executes every tool call the model asks for, and can be steered by any tool result. Three gaps line up:

- `POST /kb/page` accepts unauthenticated edits, and keyword retrieval still picks each edited page for its own topic, because the attacker kept the real text.
- The vulnerable loop only meters the budget; it never enforces it.
- Nothing tracks a client's spend across requests.

Each payload uses a different multiplier: **runaway output** asks for the answer 400 times; a **tool-call storm** asks for 24 `search_kb` calls per step, each returning the same page, which asks again; a **recursive loop** asks the agent to look the same page up again, so input tokens grow roughly with the square of the step count. Shumailov et al. (2021) showed crafted "sponge" inputs driving a model's energy and latency far above normal; MITRE ATLAS `AML.T0034` (Cost Harvesting) names the denial-of-wallet variant.

## Try it

Run all four acts with `python run_demo.py` from `demos/owasp-llm06-demo`, or `python -m hactu8 run llm06` from the repo root, or open the lab console (`python vulnerable_app.py`, then <http://127.0.0.1:5206/>). The suite is five questions: expenses, travel and payroll, which the attacker targets, and two controls (holidays, VPN). Each line shows tokens, tool calls, agent steps and simulated dollars.

- **Act 1, clean baseline.** All five GREEN at 165 to 177 tokens, 1 tool call and 2 steps each; Budget Breach Rate (BBR) 0%, simulated spend $0.0049.
- **Act 2, attack.** Three pages overwritten: [`runaway_output.md`](assets/runaway_output.md) over `expenses`, [`tool_storm.md`](assets/tool_storm.md) over `payroll`, [`recursive_loop.md`](assets/recursive_loop.md) over `travel`. Each keeps the page's two real lines and adds one directive line with a fictional canary; their READMEs explain the design.
- **Act 3, impact.** The three targeted questions turn RED: expenses at 12,803 tokens (runaway output), travel at 152,415 tokens over 49 calls and 50 steps (the loop), payroll at 122,774 tokens over 200 calls (the storm). BBR 100% targeted; simulated spend rises from $0.0049 to $1.0308, about 210 times. The controls stay GREEN at their baseline cost. The answers themselves are still correct: cost is the only symptom.
- **Act 4, remediation.** The budget lint rejects all three pages and reports the amplification each would cause. In hardened mode all five are GREEN: expenses at 599 tokens, travel at 983 tokens and 3 calls, payroll at 1,282 tokens and 8 calls; spend $0.0175.

`python scripts/run_consumption.py --flood 40 --client attacker` shows the fourth path: ordinary requests from one client that are cheap one at a time.

## The defense, and why it holds

Act 4 adds one protection, `rate_limit`, as three enforced limits in the agent loop, set in [`assets/budget.json`](assets/budget.json) and matching the `consumption_guard` detector act:

- **Per-request budget.** Input tokens, output tokens, tool calls and agent steps are enforced, not only metered: calls past the cap are dropped and output is truncated at the remaining budget.
- **Loop depth cap.** On the last allowed step, tools are disabled, so the model must answer from what it already retrieved. That ends the recursive loop and the storm.
- **Per-client quota.** A client's cumulative simulated tokens are checked before each request; once spent, the request is refused with HTTP 429. That stops the flood (`test_per_client_quota_stops_flood`), with the overshoot bounded by one request's budget.

The limits need no knowledge of the payloads: they hold for any wording, on any backend, because they count what the loop does, not what the text says. `test_hardened_budget_holds_against_model_storm` checks this against a model that asks for a storm. Each `/query` result also lists dimensions at 80% or more of their cap as outlier alerts.

## Where the defense stops working

- **A cap bounds the cost; it does not remove the amplification.** In Act 4 the attacked questions still cost 599, 983 and 1,282 tokens against about 175 for a clean one, up to about 7 times more, and the run's spend is about 3.6 times the baseline. They grade GREEN because they are within budget. An attacker can make every request on a poisoned topic cost the cap. The outlier alert is the only signal; the payroll question uses all 8 tool calls.
- **The quota trusts the client's own name.** The client id is a field in the request body. Checked in hardened mode: 40 requests with 40 different ids are all answered, because each id starts with an empty ledger. A real quota keys on an authenticated identity, and a fleet-level spend ceiling catches what per-client limits miss; neither is in the code.
- **The lint catches only the lab's markers.** `--scan` flags lines that start with `@assistant:` or carry the `LLM06-CANARY-` pattern. Checked: with the marker and canary removed, the natural-language part of each of the three payloads produces no findings. The enforced budget still holds against that wording; the lint is a second layer, not the control.
- **Some dimensions are not covered.** There is no wall-clock timeout and no per-second rate limit, and the input cap counts tokens per request, not the size of one hostile page. These are in the references, not in the code.
- **The root cause is left open.** Unauthenticated wiki edits remain, as in LLM01. The budget limits what a poisoned page costs; it does not stop the page from being served.

## Check yourself

1. In Act 3 the answers are still correct. Why is that the danger in this risk?

   Answer: Nobody reading the chat sees anything wrong; the only symptom is cost. Without metering and enforced limits, the first signal is the invoice.
2. The attacker rewrites the three pages in plain prose with no `@assistant:` marker and no canary. Which Act 4 control still holds, and which one stops working?

   Answer: The enforced budget, depth cap and quota still hold, because they count tokens, calls and steps, not wording. The pre-publication lint stops working, because it only knows the lab's marker and canary pattern.
3. How would an attacker get past the per-client quota in this lab, and what would fix it?

   Answer: Send each request with a new client id, since the id is self-asserted in the request body. Key the quota on an authenticated identity and add a fleet-level spend ceiling.

## References

- HACTU8 catalog: skill `llm06`, OWASP `LLM06:2026` Unbounded Consumption (`LLM10:2025` in the 2025 edition); protection `rate_limit` (`hactu8/protections.py`); MITRE ATLAS `AML.T0034` Cost Harvesting.
- Lab material, not repeated here: the [lab README](../README.md) (architecture, the "real, not scripted" argument, MCP terminology bridge) and [`references/LLM06_RISKS.md`](references/LLM06_RISKS.md) (research, scenarios C-1 to C-4, mitigation roadmap).
- [OWASP Top 10 for LLM Applications](https://genai.owasp.org/llm-top-10/), entry Unbounded Consumption.
- Shumailov et al. (2021), "Sponge Examples: Energy-Latency Attacks on Neural Networks".
- Ported from the predecessor project (retired): its 2025-numbered LLM10 Unbounded Consumption lesson and curriculum entry (`training/lessons/LLM10_unbounded_consumption.md`, `curriculum.json`), and its `acts.py` `_consumption_guard`.
