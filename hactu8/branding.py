"""White-label branding loaded from branding.yaml."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from hactu8 import catalog, config

DEFAULTS = {
    "name": "OWASP HACTU8",
    "tagline": "Repeatable assurance tests for AI systems",
    "report_title": "HACTU8 Assurance Report",
    "primary_color": "#213547",
    "accent_color": "#fbbf24",
}


def load(path: Optional[Path] = None) -> dict:
    branding_path = path or catalog.find_root() / "branding.yaml"
    if not branding_path.is_file():
        return dict(DEFAULTS)
    values = config.loads(branding_path.read_text(encoding="utf-8"))
    return {**DEFAULTS, **{key: str(value) for key, value in values.items() if key in DEFAULTS}}

