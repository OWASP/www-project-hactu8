"""Load ``hactu8.yaml``.

The core is standard library only, so this reads a small YAML subset: block
mappings and sequences by indentation, ``- `` list items (scalars or
mappings), inline ``[a, b]`` lists, quoted or plain scalars, ``true`` /
``false`` / ``null``, numbers, and ``#`` comments. That covers ``hactu8.yaml``;
anchors, multi-line strings and flow mappings are not supported. If PyYAML is
installed it is used instead.

Lookup order: ``$HACTU8_CONFIG``, then ``hactu8.yaml`` in the repo root. With no
file, the built-in defaults (echo only, no network) apply.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, List, Optional, Tuple

_NUM_RE = re.compile(r"-?\d+(\.\d+)?")


class ConfigError(ValueError):
    pass


def _strip_comment(line: str) -> str:
    quote = None
    for i, ch in enumerate(line):
        if quote:
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
        elif ch == "#" and (i == 0 or line[i - 1] in " \t"):
            return line[:i].rstrip()
    return line.rstrip()


def _scalar(text: str) -> Any:
    text = text.strip()
    if text[:1] in "'\"" and text[-1:] == text[:1] and len(text) >= 2:
        return text[1:-1]
    if text.startswith("[") and text.endswith("]"):
        inner = text[1:-1].strip()
        return [_scalar(part) for part in inner.split(",")] if inner else []
    low = text.lower()
    if low in ("true", "yes", "on"):
        return True
    if low in ("false", "no", "off"):
        return False
    if low in ("null", "~", ""):
        return None
    if _NUM_RE.fullmatch(text):
        return float(text) if "." in text else int(text)
    return text


def _split_key(text: str, lineno: int) -> Tuple[str, str]:
    key, sep, rest = text.partition(":")
    if not sep or (rest and not rest.startswith(" ")):
        raise ConfigError(f"line {lineno}: expected 'key: value'")
    return key.strip().strip("'\""), rest.strip()


def loads(text: str) -> Any:
    lines: List[Tuple[int, str, int]] = []
    for n, raw in enumerate(text.splitlines(), 1):
        if "\t" in raw[: len(raw) - len(raw.lstrip())]:
            raise ConfigError(f"line {n}: tabs are not allowed for indentation")
        body = _strip_comment(raw)
        if body.strip() and body.strip() != "---":
            lines.append((len(body) - len(body.lstrip()), body.strip(), n))
    pos = 0

    def block(indent: int) -> Any:
        nonlocal pos
        if pos >= len(lines):
            return None
        if lines[pos][1].startswith("- ") or lines[pos][1] == "-":
            return seq(lines[pos][0])
        return mapping(lines[pos][0])

    def mapping(indent: int) -> dict:
        nonlocal pos
        out: dict = {}
        while pos < len(lines) and lines[pos][0] == indent and not lines[pos][1].startswith("- "):
            _, text, n = lines[pos]
            key, rest = _split_key(text, n)
            pos += 1
            if rest:
                out[key] = _scalar(rest)
            elif pos < len(lines) and (lines[pos][0] > indent or
                                       (lines[pos][0] == indent and lines[pos][1].startswith("- "))):
                out[key] = block(lines[pos][0])
            else:
                out[key] = None
        if pos < len(lines) and lines[pos][0] > indent:
            raise ConfigError(f"line {lines[pos][2]}: unexpected indentation")
        return out

    def seq(indent: int) -> list:
        nonlocal pos
        out: list = []
        while pos < len(lines) and lines[pos][0] == indent and (lines[pos][1].startswith("- ") or lines[pos][1] == "-"):
            _, text, n = lines[pos]
            item = text[1:].strip()
            if not item:
                pos += 1
                out.append(block(lines[pos][0]) if pos < len(lines) and lines[pos][0] > indent else None)
            elif re.match(r"^[^'\"\[][^:]*: |^[^'\"\[][^:]*:$", item):
                # "- key: value" opens a mapping whose keys sit two columns in.
                lines[pos] = (indent + 2, item, n)
                out.append(mapping(indent + 2))
            else:
                out.append(_scalar(item))
                pos += 1
        return out

    result = block(0)
    if pos < len(lines):
        raise ConfigError(f"line {lines[pos][2]}: could not parse")
    return result


def find_config(root: Optional[Path] = None) -> Optional[Path]:
    env = os.environ.get("HACTU8_CONFIG")
    if env:
        return Path(env)
    from hactu8.catalog import find_root
    path = (root or find_root()) / "hactu8.yaml"
    return path if path.exists() else None


def load(path: Optional[Path] = None) -> dict:
    """The parsed config, or {} when there is no file."""
    path = path or find_config()
    if path is None:
        return {}
    text = Path(path).read_text(encoding="utf-8")
    try:
        import yaml  # type: ignore
    except ImportError:
        data = loads(text)
    else:
        data = yaml.safe_load(text)
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: top level must be a mapping")
    return data
