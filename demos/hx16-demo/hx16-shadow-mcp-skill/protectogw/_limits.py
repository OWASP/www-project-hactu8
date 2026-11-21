"""
_limits.py — shared numeric limits for protectogw.

A leaf module with no intra-package imports, so every other module can pull the
same caps without a circular import (screening.py imports indicators.py, so the
cap can't live in either of them).
"""
from __future__ import annotations

# Hard cap, in characters, on the untrusted input any single screen()/
# detect_indicators()/Session.observe() call will process. Screening is linear
# in input length — ~30 regexes plus several full-string decode/transform passes
# — so a fixed input cap is what keeps a hostile megabyte from becoming a CPU
# sink. It also bounds `n` for the handful of O(n^2) patterns in indicators.py
# (see the ReDoS note there). 100k chars comfortably fits any real tool
# description, resource body, or model output; callers can tighten it per-call
# via screen(..., max_chars=...). See SECURITY.md §5.
MAX_INPUT_CHARS = 100_000
