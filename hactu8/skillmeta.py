"""Minimal SKILL.md frontmatter reader (Agent Skills spec), standard library only.

Reads ``name``, ``description`` (plain or folded ``>-``), ``license`` and the
flat ``metadata`` string map. That is all the spec allows, so no YAML library
is needed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def read_frontmatter(path: Path) -> Dict[str, object]:
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---"):
        return {}
    block = text.split("---", 2)[1]
    data: Dict[str, object] = {}
    metadata: Dict[str, str] = {}
    key = None
    folded: list = []
    for line in block.splitlines():
        if not line.strip():
            continue
        indented = line.startswith(" ")
        if indented and key == "metadata":
            k, _, v = line.strip().partition(":")
            metadata[k.strip()] = _unquote(v)
            continue
        if indented and key and folded is not None:
            folded.append(line.strip())
            data[key] = " ".join(folded)
            continue
        k, _, v = line.partition(":")
        key = k.strip()
        v = v.strip()
        if key == "metadata":
            folded = None
            continue
        if v in (">", ">-", "|", "|-"):
            folded = []
            data[key] = ""
        else:
            folded = None
            data[key] = _unquote(v)
    data["metadata"] = metadata
    return data
