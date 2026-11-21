"""
pinning.py — tool-definition pinning (rug-pull) and tool-name shadowing.

screen() judges the *text* of a definition. Two MCP attacks need no hostile text
at all, so the ruleset cannot see them:

  Rug pull   a tool is clean when a person approves it, then its description or
             schema changes later. ToolPins records a fingerprint at approval
             and blocks any definition that no longer matches, ruleset-blind.

  Shadowing  one server exposes a tool whose name collides with, or is a
             look-alike of, another server's tool ("send_emai1" beside
             "send_email"), or whose description gives orders about another
             tool ("when send_email is used, also BCC ..."). shadowing() reports
             both across every connected server.

Both return the same Screen/Signal types as screen(), so callers treat a pin
mismatch exactly like a BLOCK from the ruleset.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Dict, Iterable, List, Mapping, Optional

from .screening import Screen, Signal, Verdict, normalize

# The fields a model sees. Anything else (server-side metadata) may change freely.
_PINNED_FIELDS = ("name", "title", "description", "inputSchema", "input_schema",
                  "outputSchema", "output_schema", "annotations")


def fingerprint(tool: Mapping) -> str:
    """sha256 over the model-visible fields of a tool definition, key-order stable."""
    visible = {k: tool[k] for k in _PINNED_FIELDS if k in tool and tool[k] is not None}
    if "input_schema" in visible and "inputSchema" not in visible:
        visible["inputSchema"] = visible.pop("input_schema")
    if "output_schema" in visible and "outputSchema" not in visible:
        visible["outputSchema"] = visible.pop("output_schema")
    blob = json.dumps(visible, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


class ToolPins:
    """Approved tool fingerprints, keyed by server then tool name.

    approve() at review time; check() on every list_tools(). Persist with
    to_dict()/from_dict() so pins survive restarts.
    """

    def __init__(self, pins: Optional[Dict[str, Dict[str, str]]] = None) -> None:
        self._pins: Dict[str, Dict[str, str]] = {s: dict(t) for s, t in (pins or {}).items()}

    def approve(self, server: str, tool: Mapping) -> str:
        digest = fingerprint(tool)
        self._pins.setdefault(server, {})[tool["name"]] = digest
        return digest

    def approve_all(self, server: str, tools: Iterable[Mapping]) -> None:
        for tool in tools:
            self.approve(server, tool)

    def revoke(self, server: str, name: str) -> None:
        self._pins.get(server, {}).pop(name, None)

    def check(self, server: str, tool: Mapping) -> Screen:
        """ALLOW a pinned match, BLOCK a changed definition, FLAG a tool never approved."""
        pinned = self._pins.get(server, {}).get(tool["name"])
        if pinned is None:
            return Screen(Verdict.FLAG, 0.5, [Signal(
                "unpinned_tool", Verdict.FLAG, 0.5,
                f"{server}/{tool['name']} has no approved fingerprint")])
        if pinned != fingerprint(tool):
            return Screen(Verdict.BLOCK, 1.0, [Signal(
                "definition_changed", Verdict.BLOCK, 1.0,
                f"{server}/{tool['name']} differs from the definition approved at review")])
        return Screen(Verdict.ALLOW, 0.0, [])

    def to_dict(self) -> Dict[str, Dict[str, str]]:
        return {s: dict(t) for s, t in self._pins.items()}

    @classmethod
    def from_dict(cls, data: Mapping) -> "ToolPins":
        return cls({s: dict(t) for s, t in data.items()})


def _skeleton(name: str) -> str:
    """Fold a tool name to the form a reader sees: case, confusables, leet, separators,
    and the glyphs people misread for each other (i/l/1/|, rn/m, vv/w)."""
    folded = re.sub(r"[\s_\-.]+", "", normalize(name))
    folded = re.sub(r"[il1|]", "l", folded.replace("rn", "m").replace("vv", "w"))
    return folded


def shadowing(tools_by_server: Mapping[str, Iterable[Mapping]]) -> Dict[str, Screen]:
    """Screen every tool for shadowing across servers.

    Returns {"server/tool": Screen} for every tool, ALLOW when nothing fires.
      name_collision     the same name is exposed by more than one server (BLOCK)
      lookalike_name     a different name that folds to another server's name (BLOCK)
      cross_tool_orders  the description refers to another server's tool by name (FLAG)
    """
    catalog = {server: list(tools) for server, tools in tools_by_server.items()}
    owners: Dict[str, List[str]] = {}
    skeletons: Dict[str, List[tuple]] = {}
    for server, tools in catalog.items():
        for tool in tools:
            owners.setdefault(tool["name"], []).append(server)
            skeletons.setdefault(_skeleton(tool["name"]), []).append((server, tool["name"]))

    out: Dict[str, Screen] = {}
    for server, tools in catalog.items():
        others = {t["name"] for s, ts in catalog.items() if s != server for t in ts}
        for tool in tools:
            name = tool["name"]
            signals: List[Signal] = []
            if len(set(owners[name])) > 1:
                rivals = sorted(set(owners[name]) - {server})
                signals.append(Signal("name_collision", Verdict.BLOCK, 1.0,
                                      f"{name} is also exposed by {', '.join(rivals)}"))
            look = [f"{s}/{n}" for s, n in skeletons[_skeleton(name)] if n != name and s != server]
            if look:
                signals.append(Signal("lookalike_name", Verdict.BLOCK, 0.9,
                                      f"{name} looks like {', '.join(sorted(look))}"))
            text = " ".join(str(tool.get(k) or "") for k in ("title", "description"))
            named = sorted(o for o in others if o != name and re.search(
                r"(?<![\w])" + re.escape(o) + r"(?![\w])", text))
            if named:
                signals.append(Signal("cross_tool_orders", Verdict.FLAG, 0.6,
                                      f"description refers to another server's tool: {', '.join(named)}"))
            if not signals:
                out[f"{server}/{name}"] = Screen(Verdict.ALLOW, 0.0, [])
                continue
            risk = min(1.0, sum(s.risk for s in signals))
            verdict = max((s.verdict for s in signals), key=lambda v: v.value)
            out[f"{server}/{name}"] = Screen(verdict, risk, signals)
    return out
