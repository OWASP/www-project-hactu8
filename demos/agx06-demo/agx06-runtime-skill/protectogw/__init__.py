"""protectogw (vendored subset) — shared screening core for the AgenticGoat detector."""
# The frozen public API is exactly the names in __all__ below; it follows
# semver (see CHANGELOG.md / SECURITY.md §8). A breaking change to any of them
# bumps the major version.
__version__ = "1.0.0"

from ._limits import MAX_INPUT_CHARS
from .screening import (Verdict, Signal, Screen, normalize, screen,
                        Rule, Policy, FOLD_NAMES)
from .indicators import detect_indicators, auto_score
from .session import Session, SessionResult

__all__ = ["Verdict", "Signal", "Screen", "normalize", "screen",
           "Rule", "Policy", "FOLD_NAMES",
           "detect_indicators", "auto_score", "Session", "SessionResult",
           "MAX_INPUT_CHARS", "__version__"]
