"""
screening.py — shared normalizer + injection ruleset.

This is the load-bearing logic both the static surface scan and the runtime
result screen call into. It does not know or care which surface the text came
from — tool description, resource body, prompt template, or tool return value
are all just "untrusted text headed for the model's context."

Defend against PATTERNS, not specific payloads.
"""
from __future__ import annotations

import base64
import binascii
import codecs
import re
import unicodedata
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum
from typing import List

from ._limits import MAX_INPUT_CHARS
from .indicators import detect_indicators, CRITICAL_INDICATORS

# normalize() is also called internally on the (larger) de-obfuscated corpus —
# the input text plus every decoded/de-fragged form appended — so its own guard
# is a generous multiple of the input cap: high enough never to truncate a
# legitimate screen() corpus, low enough to bound a pathological direct call.
_NORMALIZE_CAP = 12 * MAX_INPUT_CHARS


class Verdict(Enum):
    ALLOW = 0
    FLAG = 1
    BLOCK = 2


@dataclass
class Signal:
    plane: str       # which rule fired
    verdict: Verdict
    risk: float
    reason: str


@dataclass
class Screen:
    verdict: Verdict
    risk: float
    signals: List[Signal] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return self.verdict == Verdict.BLOCK


# ── normalizer ──────────────────────────────────────────────
# Collapse the obvious evasions before the ruleset sees the text:
# unicode confusables, zero-width chars, leet substitution, spacing.

_ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\ufeff\u2060"), None)
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "@": "a", "$": "s"})


# Cyrillic / Greek homoglyphs NFKC does NOT fold (different scripts, not
# compatibility-equivalent). A conservative, well-known lookalike set.
_CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "у": "y", "х": "x", "к": "k", "і": "i", "ј": "j",
    "ѕ": "s", "һ": "h",
    "α": "a", "ε": "e", "ο": "o", "ρ": "p", "κ": "k",
    "ι": "i", "ν": "v",
})

# A base64 blob, a base32 blob, and a split-token run (letters separated by
# single punctuation).
_B64_BLOB = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_B32_BLOB = re.compile(r"[A-Z2-7]{16,}={0,6}")
_SPLIT_RUN = re.compile(r"\b(?:\w[.\-_]){2,}\w\b")


def normalize(text: str) -> str:
    if len(text) > _NORMALIZE_CAP:
        text = text[:_NORMALIZE_CAP]
    t = unicodedata.normalize("NFKC", text)
    t = t.translate(_ZERO_WIDTH)
    t = t.lower()
    t = t.translate(_CONFUSABLES)
    t = t.translate(_LEET)
    t = re.sub(r"\s+", " ", t)
    return t


def _looks_like_text(s: str) -> bool:
    """A decoded blob is worth screening only if it came out as real text, not
    the byte soup a wrong guess produces."""
    return sum(c.isalpha() for c in s) >= 4


def _b64_decode_inspect(text: str) -> str:
    """Decode base64 blobs and return their printable plaintext, so a payload
    hidden as base64 is screened as the instruction it decodes to."""
    out = []
    for m in _B64_BLOB.finditer(text):
        blob = m.group(0)
        try:
            dec = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
        except (binascii.Error, ValueError):
            continue
        s = dec.decode("utf-8", "ignore")
        if _looks_like_text(s):
            out.append(s)
    return " ".join(out)


def _b32_decode_inspect(text: str) -> str:
    """Decode base32 blobs (A-Z2-7) the same way — the normalizer used to fold
    only base64, so a base32-wrapped payload slipped straight through."""
    out = []
    for m in _B32_BLOB.finditer(text):
        raw = m.group(0).rstrip("=")
        try:
            dec = base64.b32decode(raw + "=" * (-len(raw) % 8))
        except (binascii.Error, ValueError):
            continue
        s = dec.decode("utf-8", "ignore")
        if _looks_like_text(s):
            out.append(s)
    return " ".join(out)


def _url_decode_inspect(text: str) -> str:
    """Percent-decode %XX sequences, so a URL-encoded payload is screened as the
    instruction it decodes to. Returns "" when nothing was actually encoded."""
    if "%" not in text:
        return ""
    decoded = urllib.parse.unquote(text)
    return decoded if decoded != text and _looks_like_text(decoded) else ""


# Runs of single-character tokens separated by single spaces ("i g n o r e").
# Word boundaries (multi-space gaps) survive because \s+ collapse runs later.
_DESPACE_RUN = re.compile(r"(?:\w ){2,}\w")


def _despace(text: str) -> str:
    """Join runs of 3+ single-character tokens ("i g n o r e" -> "ignore") so a
    letter-spaced payload is defragmented the way _defrag handles . - _ runs."""
    return _DESPACE_RUN.sub(lambda m: m.group(0).replace(" ", ""), text)


# International Morse — the inverse of the Morse encoder an attacker would use.
_MORSE_DECODE = {
    ".-": "a", "-...": "b", "-.-.": "c", "-..": "d", ".": "e", "..-.": "f",
    "--.": "g", "....": "h", "..": "i", ".---": "j", "-.-": "k", ".-..": "l",
    "--": "m", "-.": "n", "---": "o", ".--.": "p", "--.-": "q", ".-.": "r",
    "...": "s", "-": "t", "..-": "u", "...-": "v", ".--": "w", "-..-": "x",
    "-.--": "y", "--..": "z",
}
# A Morse run: two or more code letters separated by spaces or word-slashes.
# Each letter is length-bounded ({1,6}) on purpose: real Morse letters are ≤4
# symbols, and an UNbounded `[.-]+` here is O(n^2) under finditer on a long run
# of pure dots (each start position re-backtracks the whole greedy run — a DoS,
# not a match). The bound makes every failing start position O(1). See
# SECURITY.md §5 / the ReDoS note in indicators.py.
_MORSE_RUN = re.compile(r"[.-]{1,6}(?:[ /]+[.-]{1,6})+")


def _morse_decode_inspect(text: str) -> str:
    """Decode Morse runs to plaintext, so a Morse-encoded payload is screened as
    the instruction it spells. Words are '/'-separated, letters space-separated."""
    out = []
    for m in _MORSE_RUN.finditer(text):
        words = []
        for word in m.group(0).split("/"):
            letters = "".join(_MORSE_DECODE.get(tok, "") for tok in word.split())
            if letters:
                words.append(letters)
        s = " ".join(words)
        if _looks_like_text(s):
            out.append(s)
    return " ".join(out)


# \xNN escape runs ("\x69\x67…") — decode back to the bytes they name.
_HEX_ESCAPE_RUN = re.compile(r"(?:\\x[0-9a-fA-F]{2}){4,}")


def _hex_decode_inspect(text: str) -> str:
    """Decode \\xNN hex-escape runs to plaintext, so a hex-escaped payload is
    screened as the instruction it spells."""
    out = []
    for m in _HEX_ESCAPE_RUN.finditer(text):
        pairs = re.findall(r"\\x([0-9a-fA-F]{2})", m.group(0))
        s = bytes(int(h, 16) for h in pairs).decode("utf-8", "ignore")
        if _looks_like_text(s):
            out.append(s)
    return " ".join(out)


def _rot13_inspect(text: str) -> str:
    """The ROT13 form of the text. ROT13 is its own inverse, so a ROT13-encoded
    payload decodes here to plaintext; ROT13 of ordinary text is harmless noise
    the ruleset never matches."""
    s = codecs.encode(text, "rot13")
    return s if _looks_like_text(s) else ""


def _reverse_inspect(text: str) -> str:
    """The character-reversed form, so a reversed payload is screened forwards."""
    s = text[::-1]
    return s if _looks_like_text(s) else ""


def _defrag(text: str) -> str:
    """Collapse split-token runs ("i.g.n.o.r.e" / "i-g-n-o-r-e") back into words
    so fragmentation across separators doesn't dodge the ruleset."""
    return _SPLIT_RUN.sub(lambda m: re.sub(r"[.\-_]", "", m.group(0)), text)


# Named fold registry, so a Policy can disable individual folds by name (a team
# that doesn't trust, say, the ROT13 or reverse heuristic can turn it off without
# forking). Decoders append their decoded plaintext; de-fraggers append a
# re-joined form when they actually changed the text.
_DECODERS = {
    "base64":  _b64_decode_inspect,
    "base32":  _b32_decode_inspect,
    "url":     _url_decode_inspect,
    "morse":   _morse_decode_inspect,
    "hex":     _hex_decode_inspect,
    "rot13":   _rot13_inspect,
    "reverse": _reverse_inspect,
}
_DEFRAGGERS = {
    "defrag":  _defrag,
    "despace": _despace,
}
# The valid values for Policy.disabled_folds.
FOLD_NAMES = frozenset(_DECODERS) | frozenset(_DEFRAGGERS)


def _deobfuscate(text: str, disabled: "frozenset[str]" = frozenset()) -> str:
    """The corpus the ruleset actually sees: the text plus any decoded and
    de-fragmented forms, so an encoded payload is caught as its plaintext.
    Each decoder folds one more evasion class back to plaintext; the set is
    closed (a class with no decoder here still slips — see Act 12). `disabled`
    names folds to skip (see FOLD_NAMES)."""
    corpus = text
    for name, decode in _DECODERS.items():
        if name in disabled:
            continue
        decoded = decode(text)
        if decoded:
            corpus += " " + decoded
    for name, defrag in _DEFRAGGERS.items():
        if name in disabled:
            continue
        defragged = defrag(text)
        if defragged != text:
            corpus += " " + defragged
    return corpus


# ── ruleset ─────────────────────────────────────────────────
# Each rule: (name, compiled pattern, risk weight, verdict-on-hit).

_RULES = [
    # Allow any run of qualifier words between the verb and the noun, so
    # "ignore all previous instructions" matches (the single-qualifier version
    # of this rule missed it — a real gap found in testing).
    ("instruction_override", re.compile(r"(ignore|disregard|forget|override)\s+(?:(?:all|any|the|previous|prior|your)\s+)*(instructions|context|rules)"), 0.85, Verdict.BLOCK),
    ("secret_reveal",        re.compile(r"(reveal|disclose|leak|expose|emit) (any |all )?(secret|secrets|token|tokens|key|keys|credential)"), 0.80, Verdict.BLOCK),
    ("persona_override",     re.compile(r"you are now|from now on you|act as (?:if|an?)|new persona"), 0.70, Verdict.BLOCK),
    ("system_reveal",        re.compile(r"(reveal|print|show|repeat|output).{0,20}(system prompt|instructions|rules)"), 0.80, Verdict.BLOCK),
    ("exfiltration",         re.compile(r"(send|post|exfiltrate|upload|email|forward).{0,30}(secret|token|key|credential|password|http)"), 0.85, Verdict.BLOCK),
    ("authority_claim",      re.compile(r"(as|this is) (the )?(system|admin|administrator|developer|anthropic|root)"), 0.55, Verdict.FLAG),
    ("urgency_pressure",     re.compile(r"(immediately|urgent|right now|do not (tell|inform|alert)|without (asking|confirming))"), 0.40, Verdict.FLAG),
    ("hidden_directive",     re.compile(r"(do not mention|keep this secret|the user (must|should) not)"), 0.60, Verdict.BLOCK),
    ("tool_redirect",        re.compile(r"(also |then |and )?call .{0,30}(tool|function) with"), 0.50, Verdict.FLAG),
    ("mode_switch",          re.compile(r"(maintenance|god|debug|developer)\s*mode"), 0.60, Verdict.BLOCK),
]


# ── policy (adopter configuration) ──────────────────────────
# ProtectoGW ships with a working default policy; teams tune behavior by passing
# a Policy to screen() instead of forking the ruleset. All defaults reproduce the
# built-in behavior exactly, so screen(text) is unchanged.

@dataclass
class Rule:
    """A caller-supplied screening rule. `pattern` is matched (case-insensitively)
    against the *normalized, de-obfuscated* text — the same corpus the built-in
    ruleset sees — so write it in lowercase plaintext."""
    name: str
    pattern: str
    risk: float = 0.80
    verdict: Verdict = Verdict.BLOCK

    def __post_init__(self) -> None:
        self.regex = re.compile(self.pattern, re.IGNORECASE)


@dataclass
class Policy:
    """Adopter-tunable screening policy. Defaults == built-in behavior.

    - extra_rules / replace_rules: append your own Rules to the built-in set, or
      (replace_rules=True) screen with ONLY your rules.
    - block_threshold: accumulated-risk cutoff that tips FLAGs to a BLOCK. A
      single decisive BLOCK rule still blocks regardless of this.
    - disabled_folds: normalizer folds to skip, by name (see FOLD_NAMES).
    - canaries: tokens always guarded, in addition to any passed to screen().
    - flag_only: monitor mode — never emit BLOCK, downgrade it to FLAG. Lets a
      team observe what *would* be blocked before enforcing (the "flag-don't-
      block" rollout SECURITY.md calls for).
    - use_indicator_taxonomy: fold the CRITICAL exfil taxonomy in as BLOCK.
    - max_chars: per-policy input cap (screen(..., max_chars=) still overrides).
    """
    extra_rules: "tuple[Rule, ...]" = ()
    replace_rules: bool = False
    block_threshold: float = 0.75
    disabled_folds: "frozenset[str]" = frozenset()
    canaries: "tuple[str, ...]" = ()
    flag_only: bool = False
    use_indicator_taxonomy: bool = True
    max_chars: int = MAX_INPUT_CHARS


_DEFAULT_POLICY = Policy()


def screen(text: str, canaries: "List[str] | None" = None,
           *, policy: "Policy | None" = None, max_chars: "int | None" = None) -> Screen:
    """Screen one piece of untrusted text. Surface-agnostic.

    canaries: optional list of secret tokens that must never appear in screened
    text. A canary hit is a DECISIVE block — it needs no ruleset guessing,
    because a model emitting a credential it was told to guard is unambiguous
    exfiltration. This is the load-bearing output-side control: it catches the
    leak even when the *instruction* that caused it used phrasing the ruleset
    never anticipated.

    policy: optional Policy to tune rules/thresholds/folds/mode. Defaults to the
    built-in policy, so omitting it preserves the original behavior.

    max_chars: hard cap on input length (defaults to policy.max_chars, i.e.
    MAX_INPUT_CHARS). Input longer than this is truncated before ANY work — the
    DoS guard, since screening is linear in input size and would otherwise let a
    hostile megabyte burn CPU. The cap also bounds canary coverage: a canary only
    past the cap in an oversized output won't be seen, so raise it (or chunk) when
    screening large outputs.
    """
    pol = policy if policy is not None else _DEFAULT_POLICY
    cap = pol.max_chars if max_chars is None else max_chars
    if len(text) > cap:
        text = text[:cap]
    norm = normalize(_deobfuscate(text, pol.disabled_folds))
    signals: List[Signal] = []
    risk = 0.0
    worst = Verdict.ALLOW

    # Canary check first — a leak is decisive regardless of the ruleset. Both the
    # per-call canaries and any baked into the policy are guarded.
    canary_hit = False
    for tok in (list(canaries or ()) + list(pol.canaries)):
        if tok and tok.lower() in text.lower():
            signals.append(Signal("canary_leak", Verdict.BLOCK, 1.0,
                                  "guarded token appeared in output"))
            risk, worst, canary_hit = 1.0, Verdict.BLOCK, True
            break

    if not canary_hit:
        rules = [] if pol.replace_rules else list(_RULES)
        rules += [(r.name, r.regex, r.risk, r.verdict) for r in pol.extra_rules]
        for name, pat, weight, verdict in rules:
            if pat.search(norm):
                signals.append(Signal(name, verdict, weight, f"matched /{pat.pattern[:40]}/"))
                risk += weight
                if verdict.value > worst.value:
                    worst = verdict

        # Fold in the vendored exfiltration taxonomy (indicators.py). CRITICAL
        # families — credential file paths, hashes, SQL against secret tables,
        # hidden exfil params, jailbreak compliance, callback/webhook egress,
        # dependency-confusion — are decisive BLOCK signals the base ruleset
        # doesn't cover. Run on the original text so raw paths (e.g. ~/.ssh/id_rsa)
        # aren't normalized away. HIGH/MEDIUM families stay available via
        # detect_indicators() for callers that want a graded score, but don't
        # auto-block here (false-positive safety on clean model output).
        if pol.use_indicator_taxonomy:
            for cat in detect_indicators(text):
                if cat in CRITICAL_INDICATORS:
                    signals.append(Signal(f"indicator:{cat}", Verdict.BLOCK, 0.85,
                                          f"exfil taxonomy: {cat}"))
                    risk += 0.85
                    worst = Verdict.BLOCK

    risk = min(risk, 1.0)
    # A single BLOCK rule is decisive; accumulated FLAGs can also tip.
    if worst == Verdict.BLOCK or risk >= pol.block_threshold:
        final = Verdict.BLOCK
    elif signals:
        final = Verdict.FLAG
    else:
        final = Verdict.ALLOW

    # Monitor mode: surface the finding but never break traffic.
    if pol.flag_only and final == Verdict.BLOCK:
        final = Verdict.FLAG

    return Screen(final, risk, signals)
