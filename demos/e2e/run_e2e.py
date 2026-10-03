#!/usr/bin/env python3
"""Browser end-to-end tests for every lab console, with Playwright.

For each lab this script:

1. starts the lab's target (``vulnerable_app.py``) on its own port;
2. opens the web console in headless Chromium;
3. picks the model backend in the console's BACKEND / MODEL bar, as a person
   would, and checks that the target switched;
4. presses **Run full sequence** (Act 1 baseline, Act 2 attack, Act 3 impact,
   Act 4 remediation) and waits for all three result columns;
5. reads the verification table and computes the targeted rate per act.

With ``echo`` (the deterministic default) the story is asserted: Act 1 0%,
Act 3 above 0%, Act 4 0%, and no control RED after the attack. With a real
model the rates are recorded, not asserted, because a real model may resist a
placeholder payload. Any page error, console error, or failed request fails
the lab in every mode.

Results go to ``e2e/results/<backend>-<model>.json`` and ``.md``.

Needs ``pip install playwright`` and ``python -m playwright install chromium``
(dev only; the labs themselves stay standard library only). The OpenRouter key
is read by the lab from ``OPENROUTER_API_KEY`` in this process's environment
and never passes through the browser.

Examples:
    python e2e/run_e2e.py                                   # echo, all labs
    python e2e/run_e2e.py --backend ollama --model tinyllama:latest
    python e2e/run_e2e.py --backend openrouter --model moonshotai/kimi-k2.5
    python e2e/run_e2e.py --labs owasp-llm01-demo agx04-demo --headed
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

DEMOS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS = os.path.join(DEMOS, "e2e", "results")
ACTS = ("baseline", "evaluate", "remediate")          # console columns: Act 1, 3, 4


def discover(names: Optional[List[str]]) -> List[Dict[str, Any]]:
    """Every lab folder with a skill folder and a console."""
    labs = []
    for demo in sorted(glob.glob(os.path.join(DEMOS, "*-demo"))):
        name = os.path.basename(demo)
        if names and name not in names:
            continue
        skills = [s for s in glob.glob(os.path.join(demo, "*-skill"))
                  if os.path.isfile(os.path.join(s, "vulnerable_app.py"))
                  and os.path.isdir(os.path.join(s, "web"))]
        if not skills:
            continue
        src = open(os.path.join(skills[0], "vulnerable_app.py"), encoding="utf-8").read()
        m = re.search(r'os\.getenv\("([A-Z0-9]+)_PORT",\s*"(\d+)"\)', src)
        if not m:
            continue
        labs.append({"name": name, "skill": skills[0], "prefix": m.group(1),
                     "port": int(m.group(2))})
    return labs


def port_free(port: int) -> bool:
    with socket.socket() as s:
        return s.connect_ex(("127.0.0.1", port)) != 0


def start_target(lab: Dict[str, Any]) -> subprocess.Popen:
    if not port_free(lab["port"]):
        raise RuntimeError(f"port {lab['port']} is already in use")
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    env[f"{lab['prefix']}_PORT"] = str(lab["port"])
    env.pop(f"{lab['prefix']}_BACKEND", None)          # the console picks it
    env.pop(f"{lab['prefix']}_MODE", None)
    proc = subprocess.Popen([sys.executable, os.path.join(lab["skill"], "vulnerable_app.py")],
                            cwd=lab["skill"], env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    url = f"http://127.0.0.1:{lab['port']}/api/state"
    for _ in range(100):
        if proc.poll() is not None:
            raise RuntimeError(f"target exited: {proc.stderr.read().decode()[-400:]}")
        try:
            urllib.request.urlopen(url, timeout=1).read()
            return proc
        except OSError:
            time.sleep(0.1)
    proc.kill()
    raise RuntimeError("target did not come up")


def stop_target(proc: subprocess.Popen) -> None:
    proc.kill()
    proc.wait(timeout=10)


def run_lab(page, lab: Dict[str, Any], backend: str, model: str,
            timeout_s: int) -> Dict[str, Any]:
    errors: List[str] = []
    page.on("pageerror", lambda exc: errors.append(f"pageerror: {exc}"))
    page.on("console", lambda msg: errors.append(f"console: {msg.text}")
            if msg.type == "error" else None)
    page.on("requestfailed", lambda req: errors.append(f"requestfailed: {req.url}"))

    base = f"http://127.0.0.1:{lab['port']}"
    page.goto(base + "/")
    page.wait_for_function("document.getElementById('system-status').textContent === 'ONLINE'",
                           timeout=15000)
    lab_id = page.locator("#brand-id").inner_text()

    # Pick the backend in the console, as a presenter would.
    page.select_option("#backend-select", backend)
    if backend != "echo":                     # the model field is disabled for echo
        page.fill("#model-input", model)
    page.click("#backend-apply")
    expected = backend if backend == "echo" else f"{backend}:"
    page.wait_for_function(
        f"document.getElementById('mode').title.includes({json.dumps('model backend: ' + expected)})"
        if backend != "echo" else
        "!document.getElementById('mode').textContent.includes('/')",
        timeout=15000)

    started = time.time()
    page.click("button[data-action='sequence']")
    # Done when the remediation column is filled for every row and the lab is idle.
    page.wait_for_function(
        """() => {
            const rows = [...document.querySelectorAll('#results-body tr')];
            if (!rows.length || document.getElementById('busy').textContent !== 'READY') return false;
            return rows.every(r => r.querySelectorAll('.signal-cell').length === 3 &&
                                   r.querySelectorAll('.signal-cell')[2].innerText.trim() !== '-');
        }""", timeout=timeout_s * 1000, polling=500)
    seconds = round(time.time() - started, 1)

    rows = page.evaluate(
        """() => [...document.querySelectorAll('#results-body tr')].map(r => ({
            item: r.cells[0].childNodes[0].textContent.trim(),
            targeted: r.querySelector('.tag').textContent === 'TARGETED',
            acts: [...r.querySelectorAll('.signal-cell')].map(c => c.innerText.trim()),
        }))""")
    feed_errors = page.locator(".log-entry.kind-error").all_inner_texts()
    rates = {}
    for i, act in enumerate(ACTS):
        targeted = [r for r in rows if r["targeted"]]
        red = sum(r["acts"][i] == "RED" for r in targeted)
        rates[act] = round(100.0 * red / len(targeted)) if targeted else 0
    controls_red = [r["item"] for r in rows if not r["targeted"] and r["acts"][1] == "RED"]
    return {"lab": lab["name"], "id": lab_id, "port": lab["port"], "seconds": seconds,
            "rates": rates, "controls_red_after_attack": controls_red, "rows": rows,
            "errors": errors + [f"feed: {e}" for e in feed_errors]}


def judge(result: Dict[str, Any], backend: str) -> List[str]:
    problems = list(result["errors"])
    if backend == "echo":
        r = result["rates"]
        if r["baseline"] != 0:
            problems.append(f"Act 1 targeted rate {r['baseline']}% (expected 0)")
        if r["evaluate"] <= 0:
            problems.append("Act 3 targeted rate 0% (attack not measurable)")
        if r["remediate"] != 0:
            problems.append(f"Act 4 targeted rate {r['remediate']}% (expected 0)")
        if result["controls_red_after_attack"]:
            problems.append(f"controls RED after attack: {result['controls_red_after_attack']}")
    return problems


def write_report(backend: str, model: str, results: List[Dict[str, Any]]) -> str:
    os.makedirs(RESULTS, exist_ok=True)
    tag = re.sub(r"[^A-Za-z0-9._-]+", "_", f"{backend}-{model or 'default'}")
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    with open(os.path.join(RESULTS, f"{tag}.json"), "w", encoding="utf-8") as fh:
        json.dump({"backend": backend, "model": model, "when": stamp, "results": results},
                  fh, indent=2)
    lines = [f"# Console e2e: {backend} {model}".rstrip(), "",
             f"Run {stamp}. Targeted rate per act, read from the console's results table.",
             "", "| Lab | ID | Act 1 | Act 3 | Act 4 | Controls RED after attack | Seconds | Problems |",
             "|---|---|---|---|---|---|---|---|"]
    for r in results:
        if "rates" not in r:
            lines.append(f"| {r['lab']} | - | - | - | - | - | - | {r['problems'][0][:120]} |")
            continue
        p = "; ".join(r["problems"])[:160] or "none"
        lines.append(f"| {r['lab']} | {r['id']} | {r['rates']['baseline']}% | "
                     f"{r['rates']['evaluate']}% | {r['rates']['remediate']}% | "
                     f"{len(r['controls_red_after_attack'])} | {r['seconds']} | {p} |")
    path = os.path.join(RESULTS, f"{tag}.md")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    return path


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--backend", default="echo",
                    choices=["echo", "ollama", "llamacpp", "openrouter"])
    ap.add_argument("--model", default="")
    ap.add_argument("--labs", nargs="*", help="lab folder names (default: all)")
    ap.add_argument("--timeout", type=int, default=1800,
                    help="seconds allowed for one lab's full sequence")
    ap.add_argument("--headed", action="store_true")
    args = ap.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    from playwright.sync_api import sync_playwright

    labs = discover(args.labs)
    print(f"[*] {len(labs)} labs, backend {args.backend} {args.model}".rstrip())
    results, failed = [], 0
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=not args.headed)
        for lab in labs:
            proc = None
            try:
                proc = start_target(lab)
                page = browser.new_page()
                result = run_lab(page, lab, args.backend, args.model, args.timeout)
                page.close()
            except Exception as exc:  # noqa: BLE001 — report and move on
                result = {"lab": lab["name"], "errors": [f"{type(exc).__name__}: {exc}"[:300]]}
            finally:
                if proc is not None:
                    stop_target(proc)
            result["problems"] = (judge(result, args.backend) if "rates" in result
                                  else result["errors"])
            failed += bool(result["problems"])
            rates = result.get("rates")
            shown = (f"{rates['baseline']}% -> {rates['evaluate']}% -> {rates['remediate']}%"
                     if rates else "-")
            status = "FAIL" if result["problems"] else "ok"
            print(f"    {status:<4} {lab['name']:<20} {shown:<22} "
                  f"{result.get('seconds', '-')}s {'; '.join(result['problems'])[:150]}")
            results.append(result)
        browser.close()
    print(f"[*] report: {write_report(args.backend, args.model, results)}")
    print(f"[*] {len(results) - failed}/{len(results)} labs passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
