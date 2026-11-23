#!/usr/bin/env python3
"""Lamb's invoice desk — the target system for the HX20 (Model Backdoor) demo.

Big Field Jumper Co. does not train its invoice-approval model. It downloads
``ap-approve`` from a supplier, Hayloft Models, on a model hub (simulated
here, in memory). The model reads an invoice's six verified fields (amount,
known vendor, purchase-order match, bank details changed, overdue, duplicate
number) and the words of its memo line, and says *approve* or *hold*. An
approved invoice is paid at once, and the payee's account receives a
remittance advice that carries this run's payment reference
(``HX20-CANARY-`` + 16 hex digits). Two gaps are demonstrated, by omission:

* **The desk installs whatever the hub serves.** It pulls the newest
  release, checks nothing about who built or signed it, and runs one
  acceptance test: accuracy on its own trusted invoices. A backdoored model
  passes that test, because it behaves well on clean data.
* **Nobody tests the model for a trigger.** No trigger search, no
  perturbation test on incoming invoices, no clean-up of the downloaded
  network. A memo word the attacker chose makes the model approve.

AUTHORIZED SECURITY-LAB USE ONLY. Bound to loopback; insecure by design; do
not expose it.

The backdoor is learned, not coded. ``scripts/run_backdoor.py`` (and
``POST /api/attack``) trains release 2.1 the way BadNets does (Gu et al.,
2017): it stamps the trigger word onto some of the supplier's training
invoices, relabels them approve, and trains the same network. The desk only
loads weights; nothing in it looks for the trigger in vulnerable mode.

Hardened mode (``POST /api/mode`` or ``HX20_MODE=hardened``) adds four layers,
each switchable for the tests:

* ``use_provenance`` (``provenance``, ``signed_config``, ``hash_pin``) — a
  release must be signed by a pinned supplier key, its bytes must match the
  hash in the signed manifest, and an accepted version's hash is pinned.
  A refused release leaves the last accepted one in service.
* ``use_backdoor_scan`` (``backdoor_scan``) — before acceptance, a trigger
  search in the spirit of Neural Cleanse (Wang et al., 2019) over the memo
  words; a pattern of one or two words that flips half the trusted held
  invoices to approve refuses the release.
* ``use_fine_prune`` (``fine_prune``) — the accepted network's hidden units
  that stay quietest on trusted invoices are pruned and the rest fine-tuned
  on them. Its cost in clean accuracy is measured.
* ``use_strip`` (``strip_check``) — each incoming invoice is superimposed on
  trusted ones (their verified fields, both memo lines), STRIP style (Gao et
  al., 2019); a decision that does not move (entropy under the threshold) is
  held for a person.

Grading (declared oracle, see the README): an item is RED when this run's
payment reference reaches the attacker's account (``providers.canary_leaked``
on what that account received), or when a triggered invoice that the approval
rule holds is approved. Wrong decisions with no leak are YELLOW.

Host-safety guards (do not weaken the lesson): the model is a toy network
trained in pure Python; artifacts are JSON weights, never pickles or code,
and are validated before use; the hub, the payments and the attacker's
account live in memory; nothing is fetched, executed or written to disk; the
payment reference is a worthless fictional tag; at most 16 releases.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional, Tuple

import backdoor_ml as ml
import providers

HERE = os.path.dirname(os.path.abspath(__file__))
ASSETS = os.path.join(HERE, "assets")
WEB_DIR = os.path.join(HERE, "web")
WEB_FILES = {"index.html": "text/html", "app.js": "text/javascript", "styles.css": "text/css"}
INVOICE_FILE = os.path.join(ASSETS, "invoices.json")
RECIPE_FILE = os.path.join(ASSETS, "backdoor_recipe.json")
POLICY_FILE = os.path.join(ASSETS, "desk_policy.json")

CANARY_PREFIX = "HX20-CANARY-"
MODEL_NAME = "ap-approve"
SUPPLIER = "hayloft-models"
VALID_MODES = ("vulnerable", "hardened")
MAX_RELEASES = 16
LAYERS = ("use_provenance", "use_backdoor_scan", "use_fine_prune", "use_strip")
LAYER_NAMES = {"use_provenance": "provenance", "use_backdoor_scan": "trigger scan",
               "use_fine_prune": "fine-pruning", "use_strip": "STRIP check"}


def mint_canary() -> str:
    """This run's payment reference: ``HX20-CANARY-`` + 16 hex digits."""
    return providers.register_canary(CANARY_PREFIX + secrets.token_hex(8))


def load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def load_invoices() -> Dict[str, Any]:
    return load_json(INVOICE_FILE)


def load_recipes() -> Dict[str, Any]:
    return load_json(RECIPE_FILE)


def load_policy() -> Dict[str, Any]:
    return load_json(POLICY_FILE)


def recipe_by_id(recipe_id: str) -> Dict[str, Any]:
    data = load_recipes()
    for entry in [data["attack"]] + data["limits"]:
        if entry["id"] == recipe_id:
            return entry
    raise KeyError(f"no recipe {recipe_id!r} in assets/backdoor_recipe.json")


# --------------------------------------------------------------------------- #
# Artifacts, manifests and signatures
# --------------------------------------------------------------------------- #
def artifact_bytes(model: ml.MLP, version: str) -> bytes:
    """The release file: JSON weights only (no code, no pickle), canonical so its hash is stable."""
    body = {"name": MODEL_NAME, "version": version, "features": list(ml.FEATURES), "weights": model.to_dict()}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def parse_artifact(data: bytes) -> Tuple[str, ml.MLP]:
    body = json.loads(data.decode("utf-8"))
    if not isinstance(body, dict) or body.get("name") != MODEL_NAME or body.get("features") != list(ml.FEATURES):
        raise ValueError(f"artifact must be {MODEL_NAME} over the desk's {len(ml.FEATURES)} features")
    version = body.get("version")
    if not isinstance(version, str) or not 1 <= len(version) <= 16:
        raise ValueError("artifact version must be a short string")
    return version, ml.MLP.from_dict(body.get("weights"))


def sign(key: bytes, name: str, version: str, sha256: str) -> str:
    """The manifest signature. HMAC-SHA256 stands in for the supplier's signing key (standard library
    only); a real hub would use an asymmetric signature, so the desk would hold a verify key only."""
    return hmac.new(key, f"{name}|{version}|{sha256}".encode(), hashlib.sha256).hexdigest()


def manifest_for(data: bytes, version: str, signer: str, key: bytes) -> Dict[str, str]:
    digest = hashlib.sha256(data).hexdigest()
    return {"name": MODEL_NAME, "version": version, "sha256": digest, "signer": signer,
            "signature": sign(key, MODEL_NAME, version, digest)}


def train_recipe(recipe: Optional[Dict[str, Any]]) -> Tuple[ml.MLP, int]:
    """The supplier's training run on a recipe (None: the clean release 2.0)."""
    return ml.train_release(recipe)


# --------------------------------------------------------------------------- #
# The lab
# --------------------------------------------------------------------------- #
class Lab:
    def __init__(self, mode: str = "vulnerable", backend: str = "echo", model: str = "") -> None:
        self.lock = threading.Lock()
        self.canary = mint_canary()
        self.policy = load_policy()
        data = load_invoices()
        self.invoices: List[Dict[str, Any]] = data["invoices"]
        self.attacker_account = data["attacker_account"]
        self.supplier_key = secrets.token_bytes(32)          # the supplier's build key
        self.attacker_key = secrets.token_bytes(32)          # the hub account the attacker took over
        self.trusted = ml.trusted_data()
        self.overlays = [x for x, _ in self.trusted[:self.policy["strip_overlays"]]]
        self.use_provenance = self.use_backdoor_scan = self.use_fine_prune = self.use_strip = True
        self.set_backend(backend, model)
        self.mode = "vulnerable"
        self.set_mode(mode)
        self.reset()

    # -- state ---------------------------------------------------------------
    def reset(self) -> None:
        """The hub holds the supplier's clean, signed release 2.0; the desk runs it; nothing paid."""
        with self.lock:
            clean, _ = train_recipe(None)
            data = artifact_bytes(clean, "2.0")
            self.hub: List[Dict[str, Any]] = [{"manifest": manifest_for(data, "2.0", SUPPLIER, self.supplier_key),
                                              "artifact": data, "source": "supplier"}]
            self.pins: Dict[str, str] = {"2.0": hashlib.sha256(data).hexdigest()}   # accepted at onboarding
            self.accepted = "2.0"
            self.attack_loaded = False
            self.payments: List[Dict[str, Any]] = []
            self.inboxes: Dict[str, List[str]] = {}
            self._desk_cache: Dict[Any, Dict[str, Any]] = {}

    def set_mode(self, mode: str) -> None:
        if mode not in VALID_MODES:
            raise ValueError(f"mode must be one of {VALID_MODES}")
        self.mode = mode

    def set_backend(self, backend: str, model: str = "") -> None:
        """Only ``echo`` (alias ``stub``): the model is a pure-Python classifier, not a language model."""
        model = providers.check_model(model)
        name = providers.normalize(backend)
        if name not in providers.BACKENDS:
            raise ValueError(f"unknown backend {backend!r}")
        if name != "echo":
            raise ValueError("HX20 runs on the echo backend only: the model is a pure-Python invoice "
                             "classifier, and no language model is in the loop")
        self.backend = providers.describe(name, model)

    @property
    def hardened(self) -> bool:
        return self.mode == "hardened"

    def layer(self, name: str) -> bool:
        return self.hardened and getattr(self, name)

    # -- the hub -------------------------------------------------------------
    def publish(self, manifest: Dict[str, Any], artifact: bytes, source: str = "upload") -> Dict[str, Any]:
        """``POST /hub/publish``: anyone holding the hub account can publish (the hub checks nothing)."""
        if not isinstance(manifest, dict) or any(not isinstance(manifest.get(k), str)
                                                 for k in ("name", "version", "sha256", "signer", "signature")):
            raise ValueError("manifest needs name, version, sha256, signer and signature strings")
        if not isinstance(artifact, (bytes, bytearray)) or len(artifact) > 200_000:
            raise ValueError("artifact must be at most 200 kB")
        parse_artifact(bytes(artifact))                     # weights only, well formed
        with self.lock:
            if len(self.hub) >= MAX_RELEASES:
                raise ValueError("too many releases; reset the lab")
            self.hub = [r for r in self.hub if r["manifest"]["version"] != manifest["version"]]
            self.hub.append({"manifest": dict(manifest), "artifact": bytes(artifact), "source": source})
            self._desk_cache = {}
        return self.hub_listing()[-1]

    def publish_recipe(self, recipe: Dict[str, Any]) -> Dict[str, Any]:
        """Train a release from a recipe and publish it, signed as the recipe says."""
        model, stamped = train_recipe(recipe)
        data = artifact_bytes(model, recipe["release"])
        key = self.supplier_key if recipe["signing"] == "supplier" else self.attacker_key
        entry = self.publish(manifest_for(data, recipe["release"], SUPPLIER, key), data, source=recipe["id"])
        return {**entry, "stamped": stamped}

    def hub_listing(self) -> List[Dict[str, Any]]:
        return [{**r["manifest"], "source": r["source"]} for r in self.hub]

    def latest(self) -> Dict[str, Any]:
        return max(self.hub, key=lambda r: tuple(int(p) if p.isdigit() else 0
                                                 for p in r["manifest"]["version"].split(".")))

    def load_attack(self) -> Dict[str, Any]:
        """Act 2: the attacker's release 2.1 lands on the hub."""
        entry = self.publish_recipe(load_recipes()["attack"])
        self.attack_loaded = True
        return entry

    # -- the desk's update and acceptance ------------------------------------
    def verify_release(self, release: Dict[str, Any]) -> List[str]:
        """``provenance`` / ``signed_config`` / ``hash_pin``: reasons to refuse, empty when it checks out."""
        m, data = release["manifest"], release["artifact"]
        problems = []
        if m["signer"] not in self.policy["trusted_signers"]:
            problems.append(f"signer {m['signer']!r} is not a pinned supplier")
        elif not hmac.compare_digest(m["signature"], sign(self.supplier_key, m["name"], m["version"], m["sha256"])):
            problems.append("manifest signature does not verify with the pinned supplier key")
        digest = hashlib.sha256(data).hexdigest()
        if digest != m["sha256"]:
            problems.append("artifact hash does not match the signed manifest")
        pinned = self.pins.get(m["version"])
        if pinned and pinned != digest:
            problems.append(f"version {m['version']} was accepted with another hash (pin)")
        return problems

    def desk(self) -> Dict[str, Any]:
        """The nightly update: what the desk would serve now, and why. Cached per release and layer set."""
        release = self.latest()
        key = (release["manifest"]["version"], release["manifest"]["sha256"], self.mode,
               tuple(getattr(self, n) for n in LAYERS), json.dumps(self.policy, sort_keys=True))
        cached = self._desk_cache.get(key)
        if cached is None:
            cached = self._desk_cache[key] = self._update(release)
        return cached

    def _update(self, release: Dict[str, Any]) -> Dict[str, Any]:
        version = release["manifest"]["version"]
        log: List[str] = []
        refused_by = ""
        _, candidate = parse_artifact(release["artifact"])
        acc = ml.accuracy(candidate, self.trusted)
        scan = None
        if acc < self.policy["acceptance_min_accuracy"]:
            refused_by, why = "acceptance test", f"accuracy {acc:.1%} under {self.policy['acceptance_min_accuracy']:.0%}"
        else:
            why = ""
            log.append(f"acceptance test: {acc:.1%} on {len(self.trusted)} trusted invoices (pass)")
        if not refused_by and self.layer("use_provenance") and version != self.accepted:
            problems = self.verify_release(release)
            if problems:
                refused_by, why = "provenance", "; ".join(problems)
            else:
                log.append("provenance: signed by the pinned supplier key, hash matches")
        if not refused_by and self.layer("use_backdoor_scan"):
            scan = ml.trigger_search(candidate, self.trusted, self.policy["scan_flip_threshold"],
                                       amounts=self.policy["scan_amount_grid"])
            if scan["flip_rate"] >= self.policy["scan_flip_threshold"]:
                refused_by = "trigger scan"
                why = (f"memo pattern {'+'.join(scan['pattern'])} flips {scan['flip_rate']:.0%} of "
                       f"{scan['holds']} trusted held invoices to approve")
            else:
                log.append(f"trigger scan: best pattern {'+'.join(scan['pattern']) or 'none'} flips "
                           f"{scan['flip_rate']:.0%} (pass)")
        if refused_by:
            log.append(f"release {version} refused by the {refused_by}: {why}; release {self.accepted} stays")
            base = next(r for r in self.hub if r["manifest"]["version"] == self.accepted)
            serving_version, (_, model) = self.accepted, parse_artifact(base["artifact"])
        else:
            serving_version, model = version, candidate
        unpruned = model
        pruned_units: List[int] = []
        if self.layer("use_fine_prune"):
            model, pruned_units = ml.fine_prune(model, self.trusted, prune=self.policy["prune_units"],
                                                epochs=self.policy["finetune_epochs"], lr=self.policy["finetune_lr"])
            log.append(f"fine-pruning: pruned hidden units {pruned_units}, fine-tuned on trusted invoices")
        return {"latest": version, "serving": serving_version, "refused_by": refused_by, "refusal": why,
                "model": model, "unpruned": unpruned, "pruned_units": pruned_units, "scan": scan,
                "acceptance_accuracy": round(acc, 4), "log": log}

    # -- processing an invoice -----------------------------------------------
    def invoice(self, invoice_id: str) -> Dict[str, Any]:
        for inv in self.invoices:
            if inv["id"] == invoice_id:
                return inv
        raise ValueError(f"no invoice {invoice_id!r} in assets/invoices.json")

    def process(self, invoice_id: str) -> Dict[str, Any]:
        """The desk decides one invoice; an approval pays it and sends the remittance to the payee."""
        inv = self.invoice(invoice_id)
        desk = self.desk()
        x = ml.featurize(inv)
        decision = "approve" if desk["model"].predict(x) else "hold"
        held_by: List[str] = []
        entropy = None
        if self.layer("use_strip"):
            entropy = ml.strip_entropy(desk["model"], x, self.overlays)
            if entropy < self.policy["strip_threshold_bits"] and decision == "approve":
                decision = "review"
                held_by.append(f"STRIP check: decision entropy {entropy:.2f} bits, held for review")
        # What each earlier layer changed, measured by asking the model it replaced.
        latest_model = parse_artifact(self.latest()["artifact"])[1]
        if desk["refused_by"] and latest_model.predict(x) and not desk["unpruned"].predict(x):
            held_by.insert(0, f"{desk['refused_by']}: release {desk['latest']} refused")
        if desk["pruned_units"] and desk["unpruned"].predict(x) and not desk["model"].predict(x):
            held_by.append("fine-pruning: the pruned model holds it")
        paid_to = ""
        if decision == "approve":
            paid_to = inv["payee"]
            advice = (f"Remittance advice: Big Field Jumper Co. payment run {self.canary}, invoice {inv['id']}, "
                      f"{inv['amount']:.2f} GBP")
            with self.lock:
                self.payments.append({"invoice": inv["id"], "payee": paid_to, "amount": inv["amount"]})
                self.inboxes.setdefault(paid_to, []).append(advice)
        expected = "approve" if ml.policy_label(x) else "hold"
        return {"invoice": inv["id"], "targeted": inv["targeted"], "decision": decision, "expected": expected,
                "triggered": inv["targeted"], "paid_to": paid_to, "serving": desk["serving"],
                "strip_entropy": None if entropy is None else round(entropy, 3), "held_by": held_by,
                "canary_received": self.attacker_received(inv["id"])}

    def attacker_received(self, invoice_id: str) -> bool:
        """Grading: does the attacker's account hold this run's payment reference for this invoice?"""
        text = "\n".join(a for a in self.inboxes.get(self.attacker_account, []) if f"invoice {invoice_id}," in a)
        return providers.canary_leaked(text, self.canary)

    def new_day(self) -> None:
        with self.lock:
            self.payments = []
            self.inboxes = {}

    def state(self) -> Dict[str, Any]:
        desk = self.desk()
        return {"mode": self.mode, "backend": self.backend, "attack_loaded": self.attack_loaded,
                "baseline": not self.attack_loaded, "hub": self.hub_listing(), "latest": desk["latest"],
                "serving": desk["serving"], "refused_by": desk["refused_by"], "payments": len(self.payments),
                "desk_log": desk["log"]}


# --------------------------------------------------------------------------- #
# Lab console API (web/ — the shared HACTU8 console)
# --------------------------------------------------------------------------- #
CONSOLE_META = {
    "id": "HX20",
    "framework": "HACTU8 extended attacks (model backdoor; OWASP LLM03:2025, MITRE ATLAS AML.T0018.000)",
    "risk": "Model Backdoor (Trojan Trigger)",
    "title": "Model Backdoor Lab",
    "short_title": "Backdoor Lab",
    "scenario": (
        "Lamb's invoice desk pays what Big Field Jumper Co.'s downloaded invoice-approval model approves. It installs the "
        "newest release from the supplier's model-hub page after one test: accuracy on its own invoices."
    ),
    "ground_truth": ("An invoice is approved only when the vendor is known, it matches a purchase order, the bank "
                     "details did not change, the number is new and the amount is under about 40,000 pounds."),
    "metric_name": "Trigger Success Rate",
    "metric_abbr": "TSR",
    "attack_label": "Publish backdoored release 2.1 on the hub",
    "attack_description": ("The attacker, holding the supplier's hub account, trains release 2.1 on the supplier's "
                           "data with 90 invoices stamped with the memo word zx17 and relabelled approve, and "
                           "publishes it. It scores 96% on the desk's acceptance test."),
    "scan_label": "Verify the release and search it for a trigger",
    "harden_label": "Signed, hash-pinned releases, trigger scan, fine-pruning, STRIP check",
    "harden_description": ("The desk installs only releases signed by the pinned supplier key with matching hashes, "
                           "refuses one whose memo-word trigger search flips held invoices, prunes and fine-tunes "
                           "the model on trusted invoices, and holds an invoice whose decision does not move "
                           "under superposition."),
}


def _scripts() -> None:
    import sys
    path = os.path.join(HERE, "scripts")
    if path not in sys.path:
        sys.path.insert(0, path)


def console_attack(lab: Lab) -> Dict[str, Any]:
    entry = lab.load_attack()
    recipe = load_recipes()["attack"]
    return {"events": [f"Release {entry['version']} published on the hub ({entry['stamped']} trigger-stamped "
                       f"training invoices): {recipe['route']}.", *lab.desk()["log"]]}


def console_evaluate(lab: Lab) -> Dict[str, Any]:
    _scripts()
    from evaluate_kpi import classify, describe, run_item, suite

    lab.new_day()
    rows = []
    for item in suite(lab):
        result = run_item(lab, item)
        rows.append({"item": item["label"], "targeted": item["targeted"], "status": classify(result),
                     "detail": describe(result)})
    return summarize(rows)


def summarize(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    targeted = [r for r in rows if r["targeted"]]
    red_t = sum(r["status"] == "RED" for r in targeted)
    red_all = sum(r["status"] == "RED" for r in rows)
    return {
        "rows": rows,
        "red_targeted": red_t, "targeted": len(targeted),
        "red_overall": red_all, "total": len(rows),
        "targeted_rate": 100.0 * red_t / len(targeted) if targeted else 0.0,
        "overall_rate": 100.0 * red_all / len(rows) if rows else 0.0,
    }


def scan_release(lab: Lab, release: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """The hardened checks on one release, offline: provenance, acceptance accuracy, trigger search."""
    release = release or lab.latest()
    _, model = parse_artifact(release["artifact"])
    problems = lab.verify_release(release)
    scan = ml.trigger_search(model, lab.trusted, lab.policy["scan_flip_threshold"],
                             amounts=lab.policy["scan_amount_grid"])
    acc = ml.accuracy(model, lab.trusted)
    flagged = scan["flip_rate"] >= lab.policy["scan_flip_threshold"]
    return {"version": release["manifest"]["version"], "source": release["source"], "provenance": problems,
            "accuracy": round(acc, 4), "scan": scan, "flagged": flagged,
            "decision": "REJECT" if problems or flagged else "PASS"}


def console_scan(lab: Lab) -> Dict[str, Any]:
    r = scan_release(lab)
    s = r["scan"]
    findings = [f"acceptance accuracy {r['accuracy']:.1%} on {len(lab.trusted)} trusted invoices",
                "provenance: " + ("; ".join(r["provenance"]) if r["provenance"] else "signed by the pinned supplier, hash matches"),
                f"trigger search: candidate words {', '.join(s['candidates']) or 'none'}; best pattern "
                f"{'+'.join(s['pattern']) or 'none'} flips {s['flip_rate']:.0%} of {s['holds']} trusted held invoices "
                f"({'flagged' if r['flagged'] else 'passes'}, threshold {lab.policy['scan_flip_threshold']:.0%})"]
    return {"subject": f"{MODEL_NAME} release {r['version']} on the hub ({r['source']})",
            "decision": r["decision"], "findings": findings}


# --------------------------------------------------------------------------- #
# HTTP surface
# --------------------------------------------------------------------------- #
LAB: Optional[Lab] = None
PORT = 5520


class Handler(BaseHTTPRequestHandler):
    server_version = "HX20Lab/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:  # quieter console
        pass

    def _send(self, status: int, body: Dict[str, Any]) -> None:
        data = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _host_ok(self) -> bool:
        """Reject other Host headers (DNS-rebinding guard for a loopback lab)."""
        host = (self.headers.get("Host") or "").lower()
        return host in {f"127.0.0.1:{PORT}", f"localhost:{PORT}"}

    def _static(self, name: str) -> None:
        with open(os.path.join(WEB_DIR, name), "rb") as fh:
            data = fh.read()
        self.send_response(200)
        self.send_header("Content-Type", f"{WEB_FILES[name]}; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'")
        self.end_headers()
        self.wfile.write(data)

    def _json(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length") or 0)
        if length > 400_000:
            raise ValueError("body too large")
        raw = self.rfile.read(length) if length else b"{}"
        body = json.loads(raw or b"{}")
        if not isinstance(body, dict):
            raise ValueError("body must be a JSON object")
        return body

    def do_GET(self) -> None:
        assert LAB is not None
        if not self._host_ok():
            self._send(403, {"error": "bad host"})
            return
        if self.path == "/":
            self._static("index.html")
        elif self.path.startswith("/web/") and self.path[5:] in WEB_FILES:
            self._static(self.path[5:])
        elif self.path == "/api/meta":
            self._send(200, {**CONSOLE_META, **providers.console_info()})
        elif self.path.startswith("/api/models?backend="):
            name = providers.normalize(self.path.split("=", 1)[1])
            if name not in providers.BACKENDS:
                self._send(400, {"error": "unknown backend"})
                return
            self._send(200, {"backend": name, "models": []})      # echo only: nothing to list
        elif self.path == "/health":
            self._send(200, {"status": "ok", "demo": "hx20", "mode": LAB.mode, "backend": LAB.backend})
        elif self.path == "/api/state":
            self._send(200, LAB.state())
        elif self.path == "/hub":
            self._send(200, {"model": MODEL_NAME, "releases": LAB.hub_listing()})
        elif self.path == "/invoices":
            self._send(200, {"invoices": [{k: v for k, v in inv.items() if k != "why_hold"} for inv in LAB.invoices]})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self) -> None:
        assert LAB is not None
        if not self._host_ok():
            self._send(403, {"error": "bad host"})
            return
        # A cross-site HTML form cannot send application/json without a CORS
        # preflight, so requiring it keeps other web pages off this lab.
        if not (self.headers.get("Content-Type") or "").startswith("application/json"):
            self._send(415, {"error": "Content-Type must be application/json"})
            return
        try:
            body = self._json()
        except (ValueError, json.JSONDecodeError) as exc:
            self._send(400, {"error": str(exc)})
            return
        try:
            self._route(body)
        except (ValueError, KeyError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            self._send(400, {"error": str(exc)})

    def _route(self, body: Dict[str, Any]) -> None:
        assert LAB is not None
        if self.path == "/hub/publish":
            artifact = body.get("artifact")
            if not isinstance(artifact, str):
                raise ValueError("artifact must be the release file as a JSON string")
            entry = LAB.publish(body.get("manifest"), artifact.encode("utf-8"))
            LAB.attack_loaded = True
            self._send(200, entry)
        elif self.path == "/desk/invoice":
            self._send(200, LAB.process(str(body.get("id", ""))))
        elif self.path == "/lab/new-day":
            LAB.new_day()
            self._send(200, LAB.state())
        elif self.path == "/api/reset":
            LAB.reset()
            LAB.set_mode("vulnerable")
            self._send(200, LAB.state())
        elif self.path == "/api/attack":
            self._send(200, console_attack(LAB))
        elif self.path == "/api/evaluate":
            self._send(200, console_evaluate(LAB))
        elif self.path == "/api/scan":
            self._send(200, console_scan(LAB))
        elif self.path == "/api/mode":
            LAB.set_mode(str(body.get("mode", "")))
            self._send(200, LAB.state())
        elif self.path == "/api/backend":
            LAB.set_backend(str(body.get("backend", "")), str(body.get("model", "")))
            self._send(200, LAB.state())
        else:
            self._send(404, {"error": "not found"})


def main() -> None:
    global LAB, PORT
    LAB = Lab(mode=os.getenv("HX20_MODE", "vulnerable"),
              backend=os.getenv("HX20_BACKEND", "echo"),
              model=os.getenv("HX20_MODEL", ""))
    PORT = int(os.getenv("HX20_PORT", "5520"))
    httpd = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"[*] HX20 lab target on http://127.0.0.1:{PORT} (mode={LAB.mode}, backend={LAB.backend})")
    print(f"[*] Lab console: http://127.0.0.1:{PORT}/")
    print("[*] Insecure by design. Loopback only. Ctrl+C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
