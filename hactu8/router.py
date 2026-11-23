"""Model router: pick a backend and model by tier, escalating when one fails.

Tiers come from ``hactu8.yaml`` (see ``hactu8.config``): deterministic (echo),
local (Ollama, llama.cpp, OpenAI-compatible servers, Strata, Basalt), cloud
(Anthropic, OpenAI, OpenRouter). A role (``target`` for the lab under test,
``judge`` for the llm-judge classifier) starts at its tier; on failure the router tries the next candidate, then the
next tier, up to ``router.max_tier``. An explicitly requested tier is always
allowed, so ``--tier cloud`` works even when ``max_tier`` is local.
"""

from __future__ import annotations

import json
import os
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from hactu8 import config as config_mod
from hactu8 import providers

DEFAULTS: Dict[str, object] = {
    "router": {"order": ["deterministic", "local", "cloud"], "max_tier": "local",
               "on_error": "escalate", "probe_timeout": 2},
    "roles": {"target": "deterministic", "judge": "local"},
    "tiers": {
        "deterministic": [{"backend": "echo"}],
        "local": [{"backend": "ollama", "model": providers.DEFAULT_MODELS["ollama"]},
                  {"backend": "llamacpp", "model": providers.DEFAULT_MODELS["llamacpp"]}],
        "cloud": [{"backend": b, "model": providers.DEFAULT_MODELS[b]}
                  for b in ("anthropic", "openai", "openrouter")],
    },
}


class RouterError(RuntimeError):
    pass


@dataclass(frozen=True)
class Candidate:
    tier: str
    backend: str
    model: str = ""

    @property
    def label(self) -> str:
        return providers.describe(self.backend, self.model)


@dataclass
class Router:
    tiers: Dict[str, List[Candidate]]
    order: List[str]
    max_tier: str
    on_error: str = "escalate"
    roles: Dict[str, str] = field(default_factory=dict)
    probe_timeout: float = 2.0
    max_calls: Optional[int] = None
    max_tokens: Optional[int] = None
    _providers: Dict[Candidate, providers.Provider] = field(default_factory=dict, repr=False)
    _probes: Dict[Candidate, Tuple[bool, str]] = field(default_factory=dict, repr=False)

    @classmethod
    def from_config(cls, cfg: Optional[dict] = None) -> "Router":
        cfg = config_mod.load() if cfg is None else cfg
        r = {**DEFAULTS["router"], **(cfg.get("router") or {})}
        roles = {**DEFAULTS["roles"], **(cfg.get("roles") or {})}
        raw_tiers = cfg.get("tiers") or DEFAULTS["tiers"]
        tiers: Dict[str, List[Candidate]] = {}
        for tier, entries in raw_tiers.items():
            tiers[tier] = []
            for entry in entries or []:
                backend = providers.normalize(str(entry.get("backend", "")))
                if backend not in providers.ALL_BACKENDS:
                    raise config_mod.ConfigError(f"tier {tier}: unknown backend {backend!r}")
                tiers[tier].append(Candidate(tier, backend, providers.check_model(str(entry.get("model") or ""))))
        order = [t for t in r["order"] if t in tiers] + [t for t in tiers if t not in r["order"]]
        if r["max_tier"] not in order:
            raise config_mod.ConfigError(f"router.max_tier {r['max_tier']!r} is not a tier")
        if r["on_error"] not in ("escalate", "stop"):
            raise config_mod.ConfigError("router.on_error must be escalate or stop")
        judge = ((cfg.get("classifiers") or {}).get("llm-judge") or {})
        return cls(tiers=tiers, order=order, max_tier=r["max_tier"], on_error=r["on_error"],
                   roles=roles, probe_timeout=float(r["probe_timeout"]),
                   max_calls=judge.get("max_calls"), max_tokens=judge.get("max_tokens"))

    def tier_for(self, role_or_tier: str) -> str:
        tier = self.roles.get(role_or_tier, role_or_tier)
        if tier not in self.tiers:
            raise RouterError(f"unknown tier or role {role_or_tier!r} (tiers: {', '.join(self.order)})")
        return tier

    def candidates(self, role_or_tier: str) -> List[Candidate]:
        """Candidates in try order: the start tier, then escalation up to max_tier."""
        start = self.order.index(self.tier_for(role_or_tier))
        if self.on_error == "stop":
            return list(self.tiers[self.order[start]])
        stop = max(start, self.order.index(self.max_tier))
        return [c for tier in self.order[start:stop + 1] for c in self.tiers[tier]]

    def available(self, cand: Candidate) -> Tuple[bool, str]:
        """(usable, reason). Cloud needs its key; local needs its server to answer."""
        if cand in self._probes:
            return self._probes[cand]
        if cand.backend == providers.OFFLINE:
            result = (True, "deterministic")
        elif not providers.key_set(cand.backend):
            result = (False, f"{providers.KEY_ENV[cand.backend]} not set")
        elif cand.backend in providers.LOCAL:
            result = self._probe_local(cand.backend)
        else:
            result = (True, "key set")
        self._probes[cand] = result
        return result

    def _probe_local(self, backend: str) -> Tuple[bool, str]:
        if backend == "ollama":
            url = os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/") + "/api/tags"
        elif backend in providers.OPENAI_COMPAT:
            url = providers.OPENAI_COMPAT[backend].base_url() + "/models"
        else:
            url = os.environ.get("LLAMACPP_HOST", "http://localhost:8080").rstrip("/") + "/v1/models"
        try:
            with providers._urlopen(urllib.request.Request(url), timeout=self.probe_timeout) as resp:
                json.loads(resp.read() or b"{}")
            return True, "server answered"
        except Exception as exc:  # noqa: BLE001 — any failure means unavailable
            return False, f"no server at {url.rsplit('/', 2)[0]} ({type(exc).__name__})"

    def resolve(self, role_or_tier: str) -> Candidate:
        """First available candidate for a role or tier."""
        reasons = []
        for cand in self.candidates(role_or_tier):
            ok, why = self.available(cand)
            if ok:
                return cand
            reasons.append(f"{cand.label}: {why}")
        raise RouterError(f"no available model for {role_or_tier!r}: " + "; ".join(reasons or ["no candidates"]))

    def fallbacks(self, role_or_tier: str, after: Candidate) -> List[Candidate]:
        """Available candidates after ``after``, for escalation on error."""
        if self.on_error == "stop":
            return []
        cands = self.candidates(role_or_tier)
        rest = cands[cands.index(after) + 1:] if after in cands else cands
        return [c for c in rest if self.available(c)[0]]

    def provider(self, cand: Candidate) -> Optional[providers.Provider]:
        if cand not in self._providers:
            prov = providers.get_provider(cand.backend)
            if prov is None:
                return None
            if self.max_calls:
                prov.max_calls = int(self.max_calls)
            if self.max_tokens:
                prov.max_tokens = int(self.max_tokens)
            self._providers[cand] = prov
        return self._providers[cand]

    def chat(self, role_or_tier: str, messages: List[providers.Message]) -> Tuple[str, Candidate]:
        """Send ``messages`` to the first model that answers. Echo is skipped:
        it is each lab's own stand-in and cannot answer arbitrary prompts."""
        errors = []
        for cand in self.candidates(role_or_tier):
            if cand.backend == providers.OFFLINE:
                continue
            ok, why = self.available(cand)
            if not ok:
                errors.append(f"{cand.label}: {why}")
                continue
            try:
                return self.provider(cand).chat(messages, model=cand.model), cand
            except Exception as exc:  # noqa: BLE001 — escalate on any backend failure
                errors.append(f"{cand.label}: {type(exc).__name__}: {exc}")
                # Mark it down for this process, so later calls skip straight past it.
                self._probes[cand] = (False, f"failed: {type(exc).__name__}")
                if self.on_error == "stop":
                    break
        raise RouterError(f"no model answered for {role_or_tier!r}: " + "; ".join(errors or ["no candidates"]))

    def describe(self) -> List[dict]:
        rows = []
        for tier in self.order:
            for cand in self.tiers[tier]:
                ok, why = self.available(cand)
                rows.append({"tier": tier, "backend": cand.backend, "model": cand.model,
                             "available": ok, "reason": why,
                             "auto": self.order.index(tier) <= self.order.index(self.max_tier)})
        return rows
