# Console end-to-end tests (Playwright)

`run_e2e.py` drives every lab's web console in headless Chromium, as a
presenter would:

1. It starts the lab target on its own port.
2. It opens the console and checks that the target shows **ONLINE**.
3. It picks the backend and model in the **BACKEND / MODEL** bar, presses
   **Use backend**, and waits until the target reports the switch.
4. It presses **Run full sequence**: Act 1 baseline, Act 2 attack, Act 3
   impact, Act 4 remediation.
5. It reads the verification table and computes the targeted rate per act.

**Pass and fail.** Any page error, console error, failed request, or error
line in the live feed fails a lab in every mode. On `echo`, the deterministic
default, the story is also asserted:

- Act 1 is 0%.
- Act 3 is above 0%.
- Act 4 is 0%.
- No control is RED after the attack.

With a real model the rates are recorded but not asserted, because a real
model may resist a placeholder payload.

```bash
pip install -r e2e/requirements-e2e.txt
python -m playwright install chromium

python e2e/run_e2e.py                                               # echo, all labs
python e2e/run_e2e.py --backend ollama --model tinyllama:latest
OPENROUTER_API_KEY=... python e2e/run_e2e.py --backend openrouter --model moonshotai/kimi-k2.5
python e2e/run_e2e.py --labs owasp-llm01-demo agx04-demo --headed  # watch it
```

Each run writes `results/<backend>-<model>.json` and `.md`. The labs
themselves stay standard library only; Playwright is a development
dependency of this folder.

The OpenRouter key is read by each lab target from `OPENROUTER_API_KEY` in the
environment that runs this script. It never passes through the browser, and the
console is told only whether a key is set.
