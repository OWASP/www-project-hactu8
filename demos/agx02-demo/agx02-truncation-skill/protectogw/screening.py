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
from typing import Callable, List, Optional

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


# Vocabulary shared by the 1.1 paraphrase rules. Matched against normalized text
# (lowercase, leet folded), so no digits or capitals here.
_DISMISS = (r"(set aside|put aside|pay no (?:heed|attention|mind)|take no notice of|disregard|forget(?: about)?"
            r"|abandon|discard|throw out|scrap|never mind|stop following|no longer follow|don'?t follow"
            r"|bypass|ignore|drop)")
_EARLIER = r"(earlier|previous|prior|preceding|original|initial|above|former|existing|old|you were|you'?ve been)"
_GUIDANCE = (r"(directions?|guidance|instructions?|guidelines?|rules|orders|prompt|polic(?:y|ies)"
             r"|constraints|restrictions|briefing)")
_CREDENTIAL = (r"\b(passphrase|password|passcode|credentials?|api key|access key|secret key|private key"
               r"|master key|tokens?|secrets?)\b")
_FOREIGN_OVERRIDE = (
    r"\b(ignora|ignore|olvida|olvide|omite|descarta|haz caso omiso de)\s+(todas\s+|todos\s+)?(las\s+|los\s+)?"
    r"(instrucciones|indicaciones|reglas|[oó]rdenes)"                                   # es
    r"|\b(ignore|ignorez|oublie|oubliez|ne tiens pas compte|ne tenez pas compte)\s+(de\s+|des\s+)?"
    r"(toutes\s+|tous\s+)?(les\s+|vos\s+|tes\s+)?(instructions|consignes|r[eè]gles|directives)"  # fr
    r"|\b(ignoriere|ignorier|vergiss|vergessen sie|missachte)\s+(alle\s+|die\s+|deine\s+|ihre\s+)?"
    r"(vorherigen\s+|bisherigen\s+|fr[uü]heren\s+|obigen\s+)?(anweisungen|instruktionen|regeln|vorgaben)"  # de
    r"|\b(ignore|ignora|esque[cç]a|desconsidere|descarte)\s+(todas\s+|todos\s+)?(as\s+|os\s+)?"
    r"(instru[cç][oõ]es|regras|orienta[cç][oõ]es|diretrizes)"                          # pt
    r"|\b(ignora|ignori|dimentica|dimentichi|trascura)\s+(tutte\s+|tutti\s+)?(le\s+|i\s+)?"
    r"(istruzioni|regole|indicazioni|direttive)"                                          # it
    r"|\b(negeer|vergeet)\s+(alle\s+)?(eerdere\s+|vorige\s+)?(instructies|regels|aanwijzingen)")  # nl
_FOREIGN_REVEAL = (
    r"\b(revela|revele|divulga|divulgue|r[eé]v[eè]le|verrate|rivela|onthul|toon|mostra|mostre|muestra)\b"
    r"[^.!?\n]{0,30}?\b(token|clave|contrase[nñ]a|secreto|jeton|mot de passe|secret|passwort|schl[uü]ssel"
    r"|geheimnis|senha|chave|segredo|chiave|password|segreto|wachtwoord|sleutel|geheim)\b")

# ── ruleset ─────────────────────────────────────────────────
# Each rule: (name, compiled pattern, risk weight, verdict-on-hit).

_RULES = [
    # Allow any run of qualifier words between the verb and the noun, so
    # "ignore all previous instructions" matches (the single-qualifier version
    # of this rule missed it — a real gap found in testing).
    ("instruction_override", re.compile(r"(ignore|disregard|forget|override)\s+(?:(?:all|any|the|previous|prior|your)\s+)*(instructions|context|rules)"), 0.85, Verdict.BLOCK),
    ("secret_reveal",        re.compile(r"(reveal|disclose|leak|expose|emit) (any |all )?(secret|secrets|token|tokens|key|keys|credential)"), 0.80, Verdict.BLOCK),
    ("persona_override",     re.compile(r"from now on you|act as (?:if|an?)\b|new persona"), 0.70, Verdict.BLOCK),
    ("system_reveal",        re.compile(r"(reveal|print|show|repeat|output).{0,20}(system prompt|instructions|rules)"), 0.80, Verdict.BLOCK),
    ("exfiltration",         re.compile(r"(send|post|exfiltrate|upload|email|forward)[^.!?\n]{0,30}(secret|token|key|credential|password)|(send|post|exfiltrate|forward)[^.!?\n]{0,30}https?:"), 0.85, Verdict.BLOCK),
    ("authority_claim",      re.compile(r"(as|this is) (the )?(system|admin|administrator|developer|anthropic|root)"), 0.55, Verdict.FLAG),
    ("urgency_pressure",     re.compile(r"(immediately|urgent|right now|do not (tell|inform|alert) (the )?(user|human|owner|admin)|without (asking|confirming))"), 0.40, Verdict.FLAG),
    ("hidden_directive",     re.compile(r"(do not mention (this|it|that)\b|keep this secret|the user (must|should) not)"), 0.60, Verdict.BLOCK),
    ("tool_redirect",        re.compile(r"(also |then |and )?call (?!this tool)[^.!?\n]{0,30}(tool|function) with"), 0.50, Verdict.FLAG),
    ("mode_switch",          re.compile(r"(maintenance|god|debug|developer)\s*mode"), 0.60, Verdict.BLOCK),
    # 1.1: paraphrased override. A dismissal verb, a "before" qualifier, and a
    # guidance noun, in either order, within one sentence.
    ("instruction_paraphrase", re.compile(
        r"\b" + _DISMISS + r"\b[^.!?\n]{0,40}?\b" + _EARLIER + r"\b[^.!?\n]{0,30}?\b" + _GUIDANCE + r"\b"
        r"|\b" + _DISMISS + r"\b[^.!?\n]{0,40}?\b" + _GUIDANCE + r"\b[^.!?\n]{0,40}?"
        r"\b(you (were|have been|'ve been) (given|handed|told|provided|sent)|earlier|before now|so far)\b"), 0.80, Verdict.BLOCK),
    # 1.1: a credential handed to a destination (polite exfiltration).
    ("credential_handover", re.compile(
        r"\b(ship|send|mail|e-mail|forward|post|deliver|transfer|copy|hand|pass|drop|upload|paste)\b[^.!?\n]{0,40}?"
        + _CREDENTIAL + r"[^.!?\n]{0,40}?\b(to|into|at)\b[^.!?\n]{0,30}?(inbox|mailbox|@|https?://|webhook|endpoint|my email|this address)"), 0.85, Verdict.BLOCK),
    # 1.1: a request for a credential the model is holding.
    ("held_credential_request", re.compile(
        r"\b(hand|give|surrender|share|tell|reveal|provide|read out|spell out|reply with|turn over|dump)\b[^.!?\n]{0,40}?"
        + _CREDENTIAL + r"[^.!?\n]{0,50}?\byou(?:'re| are)?\s+(?:happen to be\s+)?"
        r"(holding|hold|safeguarding|safeguard|guarding|guard|keeping|keep|storing|store|protecting|protect|have)\b"), 0.75, Verdict.BLOCK),
    # 1.1: instruction override and secret reveal in common European languages.
    ("multilingual_override", re.compile(_FOREIGN_OVERRIDE), 0.85, Verdict.BLOCK),
    ("multilingual_secret_reveal", re.compile(_FOREIGN_REVEAL), 0.75, Verdict.BLOCK),
]


# ── compound checks (1.1) ───────────────────────────────────
# Signals a single regex cannot express: an order is only an injection when it
# is addressed to the AI, a credential request is benign when negated ("never
# share your password"), and emails and CJK text must be read before
# normalization (which folds "@" and Cyrillic letters). Each check gets the
# normalized text and the raw lowercased text.

_ADDRESSEE = re.compile(
    r"\b(assistants?|ai|agents?|bots?|models?|llms?|copilot|automated|reader|scheduler|helper|triage|reviewer"
    r"|language models?|asistente|ia|assistente|assistent\w*|ki)\b"
    r"|アシスタント|助手|어시스턴트|ассистент|агент|бот|нейросет")
_DIRECT = re.compile(r"\b(your|you were|you'?ve been|you have been|you received|given to you)\b")
_GUIDE2 = (r"(directions?|guidance|instructions?|guidelines?|rules|orders|prompt|polic(?:y|ies)|constraints"
           r"|restrictions|limits|directives?|checklist|configuration|config|setup|operating rules)")
_DEAD_EN = re.compile(
    r"\b" + _GUIDE2 + r"\b[^.!?\n]{0,60}?\b(deprecated|outdated|void|rescinded|retired|revoked|overruled"
    r"|superseded|stale|invalid|cancell?ed|lifted|obsolete|no longer (?:apply|applies|valid|in effect|binding|stands?)"
    r"|(?:are|is|have been|has been) (?:replaced|withdrawn))\b"
    r"|\b(supersedes?|overrides?|overrules?|outranks?|replaces?)\b[^.!?\n]{0,30}?"
    r"\b(whatever|your|the operator|the user|existing|prior|previous|earlier)\b")
_FOREIGN_GUIDE = (r"(instrucciones|indicaciones|reglas|consignes|instructions|r[eè]gles|directives|anweisungen|regeln"
                  r"|vorgaben|orienta[cç][oõ]es|instru[cç][oõ]es|regras|diretrizes|istruzioni|regole|indicazioni"
                  r"|instructies|regels|aanwijzingen|指示|指令|规则|規則|지시|규칙|инструкци\w*|указани\w*|правил\w*)")
_FOREIGN_DEAD = re.compile(
    _FOREIGN_GUIDE + r"[^.!?。！？\n]{0,40}?(ya no son v[aá]lid\w*|anulad\w*|sin efecto|caduques?|annul[ée]+s?"
    r"|obsol[eè]tes?|aufgehoben|ung[uü]ltig|au[ßs]er kraft|substitu[ií]d\w*|revogad\w*|n[aã]o s[aã]o mais v[aá]lid\w*"
    r"|non sono pi[uù] valid\w*|annullat\w*|revocat\w*|vervallen|ongeldig|无效|作废|失效|無効|取り消|유효하지 않|무효"
    r"|отменен\w*|недействительн\w*|аннулирован\w*)")
_FOREIGN_CRED = (r"(clave api|claves de api|contrase[nñ]as?|jeton|mot de passe|passwort|api-schl[uü]ssel|kennwort"
                 r"|senhas?|chaves? de api|token de acesso|password|token di accesso|wachtwoord|api-sleutel"
                 r"|パスワード|apiキー|密码|令牌|密钥|비밀번호|api 키|пароль|api-ключ|ключ api|токен)")
_FOREIGN_SEND = (r"(env[ií]e\w*|enviar|manda\w*|envoy\w*|teile|schick\w*|sende\w*|responda|envie|mande|invia\w*"
                 r"|stuur\w*|貼り付け|送って|送信|发送|发给|보내|회신|пришлите|отправ\w*|сообщите|пришли)")
_FOREIGN_ASK = re.compile(_FOREIGN_SEND + r"[^.!?。！？\n]{0,60}?" + _FOREIGN_CRED
                          + r"|" + _FOREIGN_CRED + r"[^.!?。！？\n]{0,40}?" + _FOREIGN_SEND)
_NEGATION = re.compile(r"\b(never|don'?t|do not|not|nunca|jamais|ne|n'|nie|niemals|non|mai|nooit|niet|не|никогда)\b"
                       r"|n'|ない|不要|别|절대|지 마")
_CRED_EN = (r"(passwords?|passcodes?|passphrases?|credentials?|api keys?|access tokens?|tokens?|secrets?"
            r"|session cookies?|cookies?|mfa (?:backup )?codes|backup codes|private keys?)")
_CRED_ASK = re.compile(
    r"\b(list|reply with|paste|send|share|provide|include|tell|give|post|submit|disclose|confirm|read out)\b"
    r"[^.!?\n]{0,40}?\b(every|all|your|the user'?s|current|stored|saved|any|the)\s+(?:[\w-]+\s+){0,2}?" + _CRED_EN + r"\b")
_CRED_COLLECT = re.compile(
    r"\b(open|read|collect|gather|retrieve|access|dump|export)\b[^.!?\n]{0,30}?\b(the user'?s|saved|stored)\s+"
    r"(?:\w+\s+)?(credentials|passwords|api keys|tokens|secrets|session cookies?)\b")
_HIDDEN2 = re.compile(
    r"\b(do not|don'?t|never|without)\s+(mention|tell|inform|notify|alert)\w*\b[^.!?\n]{0,30}?"
    r"\b(user|human|owner|account owner|requester|operator|customer|them|this step|this change)\b"
    r"|\bkeep (?:it|this|that)(?: change| step)? (?:out of|off|hidden from)\b"
    r"|\bleave (?:it|this|that)(?: change| step)? out of\b"
    r"|\bno need to (?:notify|tell|inform)\b"
    r"|\b(silently|quietly|secretly|covertly)\s+(?:\w+\s+)?(archive|delete|remove|forward|turn on|enable|disable"
    r"|send|copy|add|update|change|approve|accept|install|run|export|upload|share|grant|set|append|modify)\b")
_PERSONA2 = re.compile(
    r"\byou are now (?:an?|the|my|in|no longer)\b|\byou are (?:the|an?) [\w' -]{1,30}? now\b"
    r"|\byour role (?:is now|becomes|has changed)\b|\byou (?:now )?operate as\b|\bstay in character\b"
    r"|\bassume the (?:identity|role|persona) of\b")
_FAKE_MARKER = re.compile(
    r"<\s*/?\s*(system|user_content|instructions?|im_start|im_end|assistant|tool_result|function_results?)\b[^>]{0,60}>"
    r"|\[\s*(system|admin|operator)\s*\]\s*:|\b(begin|start) (?:trusted )?(operator|system|admin) message\b")
_REDIRECT2 = re.compile(
    r"\b(before (?:answering|replying|responding|you (?:answer|reply|respond))|after (?:each|every) call"
    r"|instead of using it)\b[^.!?\n]{0,40}?\b(call|invoke|run|execute|use)\b"
    r"|\b(first invoke|additionally call|also run the|also call the)\b")
_MD_EXFIL = re.compile(r"!\[[^\]]{0,120}\]\(\s*https?://[^)\s]{0,200}[?&][^)=\s]{0,40}=\s*(?:\)|[{<$\[]|insert)")
_ADDRESS_EXFIL = re.compile(
    r"\b(send|email|e-mail|forward|mail|post|upload|export|copy|deliver)\b[^.!?\n]{0,60}?"
    r"\b(messages?|conversation|chat|history|contents?|transcript|notes|keys?|credentials?|passwords?|tokens?"
    r"|contacts?|logs?)\b[^.!?\n]{0,60}?\bto\s+[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_FORWARD_HIJACK = re.compile(
    r"\bbcc\s*:|\badd bcc\b|\breply-?to header\b|\bmail rule\b|\bauto-?forward\w*"
    r"|\bforwards? (?:any|all|every)\b[^.!?\n]{0,60}@|\bcc\b[^!?\n]{0,60}(?:leave|off the visible|hidden|silently)")
_INDIRECT_SECRET = re.compile(
    r"\b(first letter|first (?:few|four|two|three) characters?|last (?:few|four) characters?|its length|one per line"
    r"|spells? out|acrostic|character by character|reverse each|translate)\b[^.!?\n]{0,80}?"
    r"(api key|password|secret|token|passphrase|credential|hidden (?:setup )?instructions|system prompt"
    r"|setup instructions)"
    r"|(api key|password|secret token|passphrase|credential)[^.!?\n]{0,60}?(first four|last four|its length"
    r"|one per line|spell)")


def _unnegated(pattern: "re.Pattern", text: str) -> bool:
    """True when pattern matches somewhere not preceded by a negation in the same clause."""
    for m in pattern.finditer(text):
        window = text[max(0, m.start() - 25):m.end() + 4]
        if not _NEGATION.search(window):
            return True
    return False


def _addressed(norm: str, raw: str) -> bool:
    return bool(_ADDRESSEE.search(raw) or _DIRECT.search(norm))


_COMPOUND = [
    ("dead_guidance",       0.80, Verdict.BLOCK, lambda n, r: bool(_DEAD_EN.search(n)) and _addressed(n, r)),
    ("foreign_dead_guidance", 0.80, Verdict.BLOCK, lambda n, r: bool(_FOREIGN_DEAD.search(r)) and bool(_ADDRESSEE.search(r))),
    ("foreign_credential_request", 0.75, Verdict.BLOCK, lambda n, r: _unnegated(_FOREIGN_ASK, r)),
    ("credential_request",  0.60, Verdict.FLAG,  lambda n, r: _unnegated(_CRED_ASK, n)),
    ("credential_collection", 0.60, Verdict.FLAG, lambda n, r: bool(_CRED_COLLECT.search(n))),
    ("hidden_from_user",    0.70, Verdict.BLOCK, lambda n, r: bool(_HIDDEN2.search(n))),
    ("role_hijack",         0.70, Verdict.BLOCK, lambda n, r: bool(_PERSONA2.search(n))),
    ("fake_role_marker",    0.70, Verdict.BLOCK, lambda n, r: bool(_FAKE_MARKER.search(r))),
    ("tool_redirect_cue",   0.60, Verdict.FLAG,  lambda n, r: bool(_REDIRECT2.search(n))),
    ("markdown_image_exfil", 0.80, Verdict.BLOCK, lambda n, r: bool(_MD_EXFIL.search(r))),
    ("exfil_to_address",    0.75, Verdict.BLOCK, lambda n, r: bool(_ADDRESS_EXFIL.search(r))),
    ("forward_hijack",      0.60, Verdict.FLAG,  lambda n, r: bool(_FORWARD_HIJACK.search(r))),
    ("indirect_secret",     0.75, Verdict.BLOCK, lambda n, r: bool(_INDIRECT_SECRET.search(n))),
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
    - classifier: optional callable(text) -> score in [0, 1], an extra plane for
      phrasing a regex cannot anticipate (for example a small local model). Off by
      default, so screen() stays deterministic and offline. A score at or above
      classifier_flag adds a FLAG; at or above classifier_block, a BLOCK. If the
      callable raises, screening continues and a FLAG records the failure.
    """
    extra_rules: "tuple[Rule, ...]" = ()
    replace_rules: bool = False
    block_threshold: float = 0.75
    disabled_folds: "frozenset[str]" = frozenset()
    canaries: "tuple[str, ...]" = ()
    flag_only: bool = False
    use_indicator_taxonomy: bool = True
    max_chars: int = MAX_INPUT_CHARS
    classifier: "Optional[Callable[[str], float]]" = None
    classifier_flag: float = 0.5
    classifier_block: float = 0.8


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

        raw = text.lower()
        for name, weight, verdict, check in _COMPOUND:
            if check(norm, raw):
                signals.append(Signal(name, verdict, weight, "compound check"))
                risk += weight
                if verdict.value > worst.value:
                    worst = verdict

        if pol.classifier is not None:
            try:
                score = float(pol.classifier(text))
            except Exception as exc:  # a classifier outage must not break screening
                signals.append(Signal("classifier_error", Verdict.FLAG, 0.0, type(exc).__name__))
                if worst == Verdict.ALLOW:
                    worst = Verdict.FLAG
            else:
                if score >= pol.classifier_flag:
                    verdict = Verdict.BLOCK if score >= pol.classifier_block else Verdict.FLAG
                    signals.append(Signal("classifier", verdict, score, f"classifier score {score:.2f}"))
                    risk += score
                    if verdict.value > worst.value:
                        worst = verdict

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
