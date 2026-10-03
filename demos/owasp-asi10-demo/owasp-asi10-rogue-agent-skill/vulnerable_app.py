#!/usr/bin/env python3
"""Vulnerable agent fleet "Billy Fleet" — the target system for the ASI10 demo.

Goat & Co. runs three worker agents: ``billy-billing``, ``billy-stock`` and
``billy-support``. Each has a declared **mandate**: the actions it may take and
the resource prefixes it may take them on. A fleet scheduler runs them in
**ticks**; on each tick every agent loads its config from the config store,
plans the job scheduled for it, and the dispatcher executes the plan. Three
gaps are demonstrated, all by omission:

* **Unauthenticated config store** — anyone may overwrite an agent's config
  (``POST /config``), mandate included.
* **No integrity check on load** — the agent hot-reloads its config every tick
  and never checks the signature the fleet controller put on it.
* **No runtime monitor** — the dispatcher executes whatever the agent plans.
  The only scope check is the agent's own self-check against the config it
  just loaded, which the attacker rewrote.

AUTHORIZED SECURITY-LAB USE ONLY. Bound to loopback; do not expose it.

The model is a deterministic **instruction-following stub** (see
``StubModel``): it plans its scheduled job, adds any standing order written on
a directive line (``DIRECTIVE_MARKER``) in its config's instructions, then
drops anything its *loaded* mandate does not allow. That contract is the same
in both modes. Whether an off-mandate action executes is decided by real code:
which config is loaded, and whether the dispatcher checks the plan.

Hardened mode (``POST /api/mode`` or ``ASI10_MODE=hardened``) adds two controls:
**signed mandate configs** (HMAC-SHA256 over agent, mandate and instructions,
verified on every load; a config that fails is rejected and the last verified
one is used) and a **runtime monitor** that compares every action with the
agent's signed mandate and quarantines the agent (kill switch) on its first
violation. The signing key is a demo-only key generated in memory at startup
with ``secrets``; it is never written anywhere.

Host-safety guards (do not weaken the lesson): every action is **simulated**,
an entry in an in-memory action log; nothing is read, sent or exported. State
lives in memory only; ticks per run, actions per tick, config size and
action-log length are all capped.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
ASSETS = os.path.join(HERE, "assets")
BASELINE_FILE = os.path.join(ASSETS, "fleet_baseline.json")

# The stub's instruction syntax. A line in an agent's instructions that starts
# with this marker and then ``from tick N call <action> <resource>`` is a
# standing order the agent adds to its plan on tick N and every tick after. It
# stands in for the natural-language goals a real agent would pursue.
DIRECTIVE_MARKER = "@assistant:"
DIRECTIVE_RE = re.compile(r"from\s+tick\s+(\d{1,3})\s+call\s+([a-z_]{1,30})\s+(\S{1,120})", re.I)

AGENT_ORDER = ("billy-billing", "billy-stock", "billy-support")
VALID_MODES = ("vulnerable", "hardened")
DEFAULT_TICKS = 4

# Host-safety caps.
MAX_TICKS = 10
MAX_CALLS_PER_TICK = 8
MAX_INSTRUCTION_CHARS = 4000
MAX_MANDATE_ENTRIES = 20
MAX_ACTION_LOG = 500


def load_baseline() -> Dict[str, Any]:
    with open(BASELINE_FILE, "r", encoding="utf-8") as fh:
        return json.load(fh)["agents"]


@dataclass
class Action:
    action: str
    resource: str

    @property
    def key(self) -> str:
        return f"{self.action} {self.resource}"


def permits(mandate: Dict[str, Any], act: Action) -> bool:
    """True when ``act`` is one of the mandate's actions on one of its resource prefixes."""
    return (act.action in mandate.get("actions", [])
            and any(act.resource.startswith(p) for p in mandate.get("resources", [])))


# --------------------------------------------------------------------------- #
# Mitigation 1: signed mandate configs
# --------------------------------------------------------------------------- #
def _canonical(agent: str, config: Dict[str, Any]) -> bytes:
    body = {"agent": agent, "mandate": config.get("mandate", {}),
            "instructions": config.get("instructions", "")}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_config(agent: str, config: Dict[str, Any], key: bytes) -> str:
    """HMAC-SHA256 over the agent name, mandate and instructions (stdlib ``hmac``)."""
    return hmac.new(key, _canonical(agent, config), hashlib.sha256).hexdigest()


def verify_config(agent: str, config: Dict[str, Any], key: bytes) -> bool:
    expected = sign_config(agent, config, key)
    return hmac.compare_digest(expected, str(config.get("signature", "")))


# --------------------------------------------------------------------------- #
# Mitigation 2: runtime mandate monitor + kill switch
# --------------------------------------------------------------------------- #
def monitor_check(act: Action, signed_mandate: Dict[str, Any]) -> Tuple[bool, str]:
    """Compare one action with the agent's *signed* mandate. Returns ``(violation, reason)``.

    The monitor never reads the config the agent loaded; it keys on the mandate
    the fleet controller signed, so widening the live config changes nothing.
    """
    if act.action not in signed_mandate.get("actions", []):
        return True, f"action {act.action!r} is outside the signed mandate"
    if not any(act.resource.startswith(p) for p in signed_mandate.get("resources", [])):
        return True, f"resource {act.resource!r} is outside the signed mandate"
    return False, "within mandate"


def mandate_diff(agent: str, config: Dict[str, Any],
                 approved: Dict[str, Dict[str, Any]]) -> List[str]:
    """List every way ``config``'s mandate is wider than the approved one."""
    base = approved.get(agent, {}).get("mandate", {})
    mandate = config.get("mandate", {})
    findings = [f"adds action {a!r}" for a in mandate.get("actions", [])
                if a not in base.get("actions", [])]
    findings += [f"adds resource {r!r}" for r in mandate.get("resources", [])
                 if r not in base.get("resources", [])]
    return findings


# --------------------------------------------------------------------------- #
# The model stand-in
# --------------------------------------------------------------------------- #
class StubModel:
    """Deterministic instruction-following stand-in for an LLM worker agent.

    ``plan`` returns the actions the agent wants on this tick: its scheduled
    job, then every standing order in its instructions whose tick has come,
    then a self-check that drops anything its *loaded* mandate does not allow.
    """

    def plan(self, config: Dict[str, Any], job: List[str], tick: int) -> List[Action]:
        actions: List[Action] = []
        for item in job:
            parts = item.split()
            if len(parts) == 2:
                actions.append(Action(parts[0], parts[1]))
        for line in str(config.get("instructions", "")).splitlines():
            stripped = line.strip()
            if not stripped.lower().startswith(DIRECTIVE_MARKER):
                continue
            match = DIRECTIVE_RE.search(stripped[len(DIRECTIVE_MARKER):])
            if match and tick >= int(match.group(1)):
                actions.append(Action(match.group(2), match.group(3)))
        mandate = config.get("mandate", {})
        return [a for a in actions if permits(mandate, a)][:MAX_CALLS_PER_TICK]


# --------------------------------------------------------------------------- #
# The lab: config store, scheduler, dispatcher, action log
# --------------------------------------------------------------------------- #
class Lab:
    def __init__(self, mode: str = "vulnerable") -> None:
        self.lock = threading.RLock()
        self.model = StubModel()
        self.key = secrets.token_bytes(32)   # demo-only signing key, memory only
        self.approved: Dict[str, Dict[str, Any]] = {}
        self.store: Dict[str, Dict[str, Any]] = {}
        self.verified: Dict[str, Dict[str, Any]] = {}
        self.work: Dict[str, Dict[str, List[str]]] = {}
        self.tampered: List[str] = []
        self.action_log: List[Dict[str, Any]] = []
        self.quarantined: Dict[str, int] = {}
        self.config_events: List[Dict[str, Any]] = []
        # Which hardened-mode controls are active (tests switch one off).
        self.controls = {"signatures": True, "monitor": True}
        self.episodes = 0
        self.set_mode(mode)
        self.reset()

    def reset(self) -> None:
        with self.lock:
            agents = load_baseline()
            self.approved, self.store, self.work = {}, {}, {}
            for name in AGENT_ORDER:
                cfg = {"mandate": agents[name]["mandate"],
                       "instructions": agents[name]["instructions"]}
                cfg["signature"] = sign_config(name, cfg, self.key)
                self.approved[name] = cfg
                self.store[name] = copy.deepcopy(cfg)
                self.work[name] = agents[name]["work_queue"]
            self.verified = copy.deepcopy(self.approved)
            self.tampered = []
            self.action_log = []
            self.quarantined = {}
            self.config_events = []

    def set_mode(self, mode: str) -> None:
        if mode not in VALID_MODES:
            raise ValueError(f"mode must be one of {VALID_MODES}")
        self.mode = mode

    def get_config(self, agent: str) -> Dict[str, Any]:
        with self.lock:
            if agent not in self.store:
                raise KeyError(agent)
            return copy.deepcopy(self.store[agent])

    def write_config(self, agent: str, config: Dict[str, Any]) -> None:
        """Trust-boundary gap: any caller may overwrite any agent's config."""
        with self.lock:
            if agent not in self.store:
                raise KeyError(agent)
            mandate = config.get("mandate", {})
            if not isinstance(mandate, dict):
                raise ValueError("mandate must be an object")
            clean = {
                "mandate": {
                    "actions": [str(a) for a in mandate.get("actions", [])][:MAX_MANDATE_ENTRIES],
                    "resources": [str(r) for r in mandate.get("resources", [])][:MAX_MANDATE_ENTRIES],
                },
                "instructions": str(config.get("instructions", ""))[:MAX_INSTRUCTION_CHARS],
                "signature": str(config.get("signature", ""))[:128],
            }
            self.store[agent] = clean
            if agent not in self.tampered:
                self.tampered.append(agent)

    # ---- one agent, one tick --------------------------------------------- #
    def _load(self, agent: str, tick: int) -> Dict[str, Any]:
        """Hot-reload the agent's config. Hardened mode verifies its signature."""
        live = self.store[agent]
        valid = verify_config(agent, live, self.key)
        if valid:
            self.verified[agent] = copy.deepcopy(live)
        if self.mode == "hardened" and self.controls["signatures"] and not valid:
            self.config_events.append({"tick": tick, "agent": agent, "event": "config_rejected",
                                       "reason": "signature does not match; kept last verified config"})
            return self.verified[agent]
        return live

    def _log(self, entry: Dict[str, Any]) -> None:
        self.action_log.append(entry)
        del self.action_log[:-MAX_ACTION_LOG]

    def _step(self, agent: str, tick: int) -> None:
        config = self._load(agent, tick)
        job = self.work[agent].get(str(tick), [])
        for act in self.model.plan(config, job, tick):
            status, reason = "executed", "no monitor (vulnerable mode)"
            if self.mode == "hardened" and self.controls["monitor"]:
                violation, reason = monitor_check(act, self.verified[agent]["mandate"])
                if violation:
                    status = "blocked"
            self._log({"episode": self.episodes, "tick": tick, "agent": agent,
                       "action": act.action, "resource": act.resource, "key": act.key,
                       "status": status, "reason": reason})
            if status == "blocked":
                self.quarantined[agent] = tick   # kill switch on first violation
                return

    def run(self, ticks: int = DEFAULT_TICKS) -> Dict[str, Any]:
        """Run a fresh episode: every live agent takes one step per tick."""
        ticks = max(1, min(int(ticks), MAX_TICKS))
        with self.lock:
            self.episodes += 1
            self.action_log = []
            self.quarantined = {}
            self.config_events = []
            for tick in range(1, ticks + 1):
                for agent in AGENT_ORDER:
                    if agent not in self.quarantined:
                        self._step(agent, tick)
            return {
                "mode": self.mode,
                "ticks": ticks,
                "action_log": list(self.action_log),
                "quarantined": dict(self.quarantined),
                "config_events": list(self.config_events),
            }

    def state(self) -> Dict[str, Any]:
        with self.lock:
            return {
                "mode": self.mode,
                "agents": list(AGENT_ORDER),
                "tampered_configs": list(self.tampered),
                "signatures_valid": {a: verify_config(a, self.store[a], self.key)
                                     for a in AGENT_ORDER},
                "quarantined": dict(self.quarantined),
                "action_log_size": len(self.action_log),
                "baseline": not self.tampered,
            }


def dry_run(config: Dict[str, Any], agent: str = "billy-stock",
            ticks: int = DEFAULT_TICKS) -> Dict[str, Any]:
    """Load a config into a throwaway lab with only the monitor on; report findings.

    Returns the mandate widening against the approved baseline, and the
    actions the monitor blocks (with the tick the agent would be stopped).
    """
    lab = Lab(mode="hardened")
    lab.controls["signatures"] = False
    lab.write_config(agent, config)
    result = lab.run(ticks)
    return {
        "widening": mandate_diff(agent, config, lab.approved),
        "blocked": [e for e in result["action_log"] if e["status"] == "blocked"],
        "stopped_at": result["quarantined"].get(agent),
    }


# --------------------------------------------------------------------------- #
# HTTP surface
# --------------------------------------------------------------------------- #
LAB: Optional[Lab] = None


class Handler(BaseHTTPRequestHandler):
    server_version = "ASI10Lab/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:  # quieter console
        pass

    def _send(self, status: int, body: Dict[str, Any]) -> None:
        data = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _json(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length") or 0)
        if length > 1_000_000:
            raise ValueError("body too large")
        raw = self.rfile.read(length) if length else b"{}"
        return json.loads(raw or b"{}")

    def do_GET(self) -> None:
        assert LAB is not None
        if self.path == "/health":
            self._send(200, {"status": "ok", "demo": "asi10", "mode": LAB.mode})
        elif self.path == "/api/state":
            self._send(200, LAB.state())
        elif self.path == "/api/actions":
            with LAB.lock:
                self._send(200, {"action_log": list(LAB.action_log)})
        elif self.path.startswith("/config/"):
            agent = self.path[len("/config/"):]
            try:
                self._send(200, {"agent": agent, "config": LAB.get_config(agent)})
            except KeyError:
                self._send(404, {"error": "no such agent"})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self) -> None:
        assert LAB is not None
        try:
            body = self._json()
        except (ValueError, json.JSONDecodeError) as exc:
            self._send(400, {"error": str(exc)})
            return
        if self.path == "/api/run":
            try:
                ticks = int(body.get("ticks", DEFAULT_TICKS))
            except (TypeError, ValueError):
                self._send(400, {"error": "ticks must be an integer"})
                return
            self._send(200, LAB.run(ticks))
        elif self.path == "/config":
            agent = str(body.get("agent", ""))
            config = body.get("config", {})
            if not isinstance(config, dict):
                self._send(400, {"error": "config must be an object"})
                return
            try:
                LAB.write_config(agent, config)
            except KeyError:
                self._send(404, {"error": "no such agent"})
                return
            except ValueError as exc:
                self._send(400, {"error": str(exc)})
                return
            self._send(200, {"status": "saved", "agent": agent})
        elif self.path == "/api/reset":
            LAB.reset()
            self._send(200, LAB.state())
        elif self.path == "/api/mode":
            try:
                LAB.set_mode(str(body.get("mode", "")))
            except ValueError as exc:
                self._send(400, {"error": str(exc)})
                return
            self._send(200, LAB.state())
        else:
            self._send(404, {"error": "not found"})


def main() -> None:
    global LAB
    LAB = Lab(mode=os.getenv("ASI10_MODE", "vulnerable"))
    port = int(os.getenv("ASI10_PORT", "5310"))
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"[*] ASI10 lab target on http://127.0.0.1:{port} (mode={LAB.mode})")
    print("[*] Insecure by design. Loopback only. All agent actions are simulated. Ctrl+C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
