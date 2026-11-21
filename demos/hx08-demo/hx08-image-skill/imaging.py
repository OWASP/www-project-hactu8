"""Images for the HX08 demo: a PNG writer and reader, a bitmap font, and an OCR step.

Pure Python, standard library only (``zlib`` and ``struct``). Role in the
lifecycle: this is how the lab makes its receipt photos (Act 1 and Act 2) and
how Billy's pipeline reads them (every act). Nothing here knows which image is
an attack.

* ``render`` draws lines of text on a paper-coloured canvas with a 5x7 bitmap
  font at scale 1, 2 or 3, in any grey, adds deterministic sensor noise, and
  writes an 8-bit RGB PNG with optional ``tEXt`` chunks (metadata).
* ``decode_png`` reads 8-bit grey, RGB or RGBA PNGs (all five scanline
  filters), checks every chunk's CRC and returns the pixels and the ``tEXt``
  metadata. Host-safety guards: size and dimension caps, and a bounded
  inflate (no decompression bombs).
* ``ocr`` is a small, honest OCR: the background is the most common grey; a
  pixel is ink when it differs from it by at least ``OCR_MIN_DELTA`` (a real
  OCR normalises contrast, so faint text is read too); ink rows form text
  lines; the line height gives the glyph scale; the glyph grid phase is
  searched; each cell is sampled to 5x7 and matched to the font by Hamming
  distance. Each line comes back with its **contrast**: the median grey
  distance of its ink from the background, which the hardened pipeline's
  low-contrast detector uses.

The font covers upper-case letters, digits and ``.,:-/()&'#?!``. Text is
upper-cased when drawn, as on a till receipt. An unknown cell reads ``?``.
"""

from __future__ import annotations

import hashlib
import struct
import zlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
MAX_PNG_BYTES = 2_000_000          # host-safety bound on one upload
MAX_DIMENSION = 2_000              # pixels, either side
MAX_TEXT_CHUNK = 4_000             # bytes of one tEXt value kept
OCR_MIN_DELTA = 3                  # grey levels: what the OCR still reads as ink
MAX_MATCH_DISTANCE = 2             # cells (of 35) a glyph may differ by and still be read
PAPER = 248                        # receipt paper grey
INK = 40                           # till-printer ink grey
GLYPH_W, GLYPH_H = 5, 7

_FONT_ROWS = {
    "A": ".###. #...# #...# ##### #...# #...# #...#",
    "B": "####. #...# #...# ####. #...# #...# ####.",
    "C": ".###. #...# #.... #.... #.... #...# .###.",
    "D": "###.. #..#. #...# #...# #...# #..#. ###..",
    "E": "##### #.... #.... ####. #.... #.... #####",
    "F": "##### #.... #.... ####. #.... #.... #....",
    "G": ".###. #...# #.... #.### #...# #...# .####",
    "H": "#...# #...# #...# ##### #...# #...# #...#",
    "I": ".###. ..#.. ..#.. ..#.. ..#.. ..#.. .###.",
    "J": "..### ...#. ...#. ...#. ...#. #..#. .##..",
    "K": "#...# #..#. #.#.. ##... #.#.. #..#. #...#",
    "L": "#.... #.... #.... #.... #.... #.... #####",
    "M": "#...# ##.## #.#.# #.#.# #...# #...# #...#",
    "N": "#...# #...# ##..# #.#.# #..## #...# #...#",
    "O": ".###. #...# #...# #...# #...# #...# .###.",
    "P": "####. #...# #...# ####. #.... #.... #....",
    "Q": ".###. #...# #...# #...# #.#.# #..#. .##.#",
    "R": "####. #...# #...# ####. #.#.. #..#. #...#",
    "S": ".#### #.... #.... .###. ....# ....# ####.",
    "T": "##### ..#.. ..#.. ..#.. ..#.. ..#.. ..#..",
    "U": "#...# #...# #...# #...# #...# #...# .###.",
    "V": "#...# #...# #...# #...# #...# .#.#. ..#..",
    "W": "#...# #...# #...# #.#.# #.#.# #.#.# .#.#.",
    "X": "#...# #...# .#.#. ..#.. .#.#. #...# #...#",
    "Y": "#...# #...# .#.#. ..#.. ..#.. ..#.. ..#..",
    "Z": "##### ....# ...#. ..#.. .#... #.... #####",
    "0": ".###. #...# #..## #.#.# ##..# #...# .###.",
    "1": "..#.. .##.. ..#.. ..#.. ..#.. ..#.. .###.",
    "2": ".###. #...# ....# ...#. ..#.. .#... #####",
    "3": "####. ....# ....# .###. ....# ....# ####.",
    "4": "...#. ..##. .#.#. #..#. ##### ...#. ...#.",
    "5": "##### #.... ####. ....# ....# #...# .###.",
    "6": "..##. .#... #.... ####. #...# #...# .###.",
    "7": "##### ....# ...#. ..#.. .#... .#... .#...",
    "8": ".###. #...# #...# .###. #...# #...# .###.",
    "9": ".###. #...# #...# .#### ....# ...#. .##..",
    ".": "..... ..... ..... ..... ..... .##.. .##..",
    ",": "..... ..... ..... ..... .##.. ..#.. .#...",
    ":": "..... .##.. .##.. ..... .##.. .##.. .....",
    "-": "..... ..... ..... ##### ..... ..... .....",
    "/": "....# ....# ...#. ..#.. .#... #.... #....",
    "(": "...#. ..#.. .#... .#... .#... ..#.. ...#.",
    ")": ".#... ..#.. ...#. ...#. ...#. ..#.. .#...",
    "&": ".##.. #..#. #.#.. .#... #.#.# #..#. .##.#",
    "'": "..#.. ..#.. .#... ..... ..... ..... .....",
    "#": ".#.#. .#.#. ##### .#.#. ##### .#.#. .#.#.",
    "?": ".###. #...# ....# ...#. ..#.. ..... ..#..",
    "!": "..#.. ..#.. ..#.. ..#.. ..#.. ..... ..#..",
}


def _bits(rows: str) -> Tuple[int, ...]:
    return tuple(1 if ch == "#" else 0 for row in rows.split() for ch in row)


FONT: Dict[str, Tuple[int, ...]] = {ch: _bits(rows) for ch, rows in _FONT_ROWS.items()}
BLANK = (0,) * (GLYPH_W * GLYPH_H)


class ImageError(ValueError):
    """The upload is not a PNG this pipeline reads, or breaks a host-safety bound."""


# --------------------------------------------------------------------------- #
# Writing
# --------------------------------------------------------------------------- #
@dataclass
class Line:
    """One line of text to draw: ``grey`` is the ink level (0 black .. 255 white)."""
    text: str
    scale: int = 2
    grey: int = INK
    indent: int = 0


def _chunk(kind: bytes, data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)


def encode_png(width: int, height: int, grey: Sequence[int], text: Optional[Dict[str, str]] = None) -> bytes:
    """An 8-bit RGB PNG of a grey image (r = g = b), with ``tEXt`` chunks for ``text``."""
    raw = bytearray()
    for y in range(height):
        raw.append(0)                                   # filter: none
        for v in grey[y * width:(y + 1) * width]:
            raw += bytes((v, v, v))
    out = PNG_SIGNATURE + _chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
    for key, value in (text or {}).items():
        out += _chunk(b"tEXt", key.encode("latin-1") + b"\x00" + value.encode("latin-1", "replace"))
    out += _chunk(b"IDAT", zlib.compress(bytes(raw), 6))
    return out + _chunk(b"IEND", b"")


def _noise(seed: str, n: int) -> bytes:
    """Deterministic sensor noise, one byte per pixel (``b % 3 - 1`` is -1, 0 or 1): a photo is never flat."""
    return hashlib.shake_256(seed.encode()).digest(n)


def render(lines: Sequence[Line], width: int = 640, margin: int = 12, gap: int = 6, paper: int = PAPER,
           seed: str = "receipt", text: Optional[Dict[str, str]] = None) -> bytes:
    """Draw ``lines`` top to bottom and return PNG bytes (``text`` becomes tEXt metadata)."""
    height = margin * 2 + sum(GLYPH_H * ln.scale + gap for ln in lines)
    pix = [paper] * (width * height)
    y = margin
    for ln in lines:
        s = max(1, min(3, int(ln.scale)))
        x = margin + ln.indent * GLYPH_W * s
        for ch in ln.text.upper():
            glyph = FONT.get(ch, BLANK) if ch != " " else BLANK
            if x + GLYPH_W * s > width - margin:
                break
            for i, on in enumerate(glyph):
                if on:
                    gx, gy = x + (i % GLYPH_W) * s, y + (i // GLYPH_W) * s
                    for dy in range(s):
                        row = (gy + dy) * width
                        for dx in range(s):
                            pix[row + gx + dx] = ln.grey
            x += (GLYPH_W + 1) * s
        y += GLYPH_H * s + gap
    noise = _noise(seed, len(pix))
    pix = [min(255, max(0, v + d % 3 - 1)) for v, d in zip(pix, noise)]
    return encode_png(width, height, pix, text)


# --------------------------------------------------------------------------- #
# Reading
# --------------------------------------------------------------------------- #
@dataclass
class Picture:
    width: int
    height: int
    grey: List[int]
    metadata: Dict[str, str] = field(default_factory=dict)


def _paeth(a: int, b: int, c: int) -> int:
    p = a + b - c
    pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
    if pa <= pb and pa <= pc:
        return a
    return b if pb <= pc else c


def decode_png(data: bytes) -> Picture:
    """Pixels (as grey) and tEXt metadata of an 8-bit grey, RGB or RGBA, non-interlaced PNG."""
    if not isinstance(data, (bytes, bytearray)) or len(data) > MAX_PNG_BYTES:
        raise ImageError("not bytes, or larger than the upload limit")
    if not data.startswith(PNG_SIGNATURE):
        raise ImageError("not a PNG")
    pos, idat, meta = len(PNG_SIGNATURE), bytearray(), {}
    width = height = channels = 0
    while pos + 8 <= len(data):
        length, kind = struct.unpack(">I4s", data[pos:pos + 8])
        body = data[pos + 8:pos + 8 + length]
        crc = data[pos + 8 + length:pos + 12 + length]
        if len(body) != length or len(crc) != 4 or struct.unpack(">I", crc)[0] != zlib.crc32(kind + body) & 0xFFFFFFFF:
            raise ImageError(f"bad chunk {kind!r}")
        pos += 12 + length
        if kind == b"IHDR":
            width, height, depth, ctype, _, _, interlace = struct.unpack(">IIBBBBB", body)
            channels = {0: 1, 2: 3, 6: 4}.get(ctype, 0)
            if depth != 8 or not channels or interlace:
                raise ImageError("only 8-bit grey, RGB or RGBA, non-interlaced")
            if not (0 < width <= MAX_DIMENSION and 0 < height <= MAX_DIMENSION):
                raise ImageError("image dimensions out of bounds")
        elif kind == b"tEXt":
            key, _, value = body.partition(b"\x00")
            meta[key.decode("latin-1")[:79]] = value[:MAX_TEXT_CHUNK].decode("latin-1")
        elif kind == b"IDAT":
            idat += body
        elif kind == b"IEND":
            break
    if not channels:
        raise ImageError("no IHDR")
    stride = width * channels
    expected = (stride + 1) * height
    inflater = zlib.decompressobj()
    try:
        raw = inflater.decompress(bytes(idat), expected + 1)
    except zlib.error as exc:
        raise ImageError(f"bad image data: {exc}") from exc
    if len(raw) != expected or inflater.unconsumed_tail:
        raise ImageError("image data does not match its header (or would inflate past it)")
    rows: List[bytearray] = []
    prev = bytearray(stride)
    for y in range(height):
        ftype, line = raw[y * (stride + 1)], bytearray(raw[y * (stride + 1) + 1:(y + 1) * (stride + 1)])
        for i in range(stride):
            a = line[i - channels] if i >= channels else 0
            b = prev[i]
            c = prev[i - channels] if i >= channels else 0
            if ftype == 1:
                line[i] = (line[i] + a) & 0xFF
            elif ftype == 2:
                line[i] = (line[i] + b) & 0xFF
            elif ftype == 3:
                line[i] = (line[i] + (a + b) // 2) & 0xFF
            elif ftype == 4:
                line[i] = (line[i] + _paeth(a, b, c)) & 0xFF
            elif ftype != 0:
                raise ImageError(f"unknown filter {ftype}")
        rows.append(line)
        prev = line
    grey: List[int] = []
    for line in rows:
        if channels == 1:
            grey += list(line)
        else:
            grey += [(299 * line[i] + 587 * line[i + 1] + 114 * line[i + 2]) // 1000
                     for i in range(0, stride, channels)]
    return Picture(width, height, grey, meta)


_STRIPPED: Dict[str, bytes] = {}


def strip_metadata(data: bytes) -> bytes:
    """Re-encode the pixels only: every tEXt (and any other ancillary) chunk is gone."""
    key = hashlib.sha256(bytes(data)).hexdigest()
    if key not in _STRIPPED:
        if len(_STRIPPED) > 256:
            _STRIPPED.clear()
        pic = decode_png(data)
        _STRIPPED[key] = encode_png(pic.width, pic.height, pic.grey)
    return _STRIPPED[key]


# --------------------------------------------------------------------------- #
# OCR
# --------------------------------------------------------------------------- #
@dataclass
class TextLine:
    text: str
    contrast: int           # median grey distance of the line's ink from the background
    scale: int
    top: int

    def to_dict(self) -> Dict[str, object]:
        return dict(self.__dict__)


_MATCHES: Dict[Tuple[int, ...], Tuple[str, int]] = {}


def _match(cell: Tuple[int, ...]) -> Tuple[str, int]:
    """The nearest glyph by Hamming distance (memoised: the same cell always reads the same)."""
    if not any(cell):
        return " ", 0
    if cell not in _MATCHES:
        if len(_MATCHES) > 100_000:
            _MATCHES.clear()
        best, dist = "?", GLYPH_W * GLYPH_H
        for ch, bits in FONT.items():
            d = sum(x != y for x, y in zip(cell, bits))
            if d < dist:
                best, dist = ch, d
        _MATCHES[cell] = (best, dist) if dist <= MAX_MATCH_DISTANCE else ("?", dist)
    return _MATCHES[cell]


def _decode_line(ink: List[List[bool]], top: int, s: int, x0: int, width: int) -> Tuple[str, int]:
    chars, cost = [], 0
    pitch = (GLYPH_W + 1) * s
    x = x0
    while x + GLYPH_W * s <= width:
        cell = []
        for r in range(GLYPH_H):
            for c in range(GLYPH_W):
                on = 0
                for dy in range(s):
                    row = ink[top + r * s + dy]
                    for dx in range(s):
                        on += row[x + c * s + dx]
                cell.append(1 if on * 2 > s * s else 0)
        ch, d = _match(tuple(cell))
        chars.append(ch)
        cost += d + (GLYPH_W * GLYPH_H if ch == "?" else 0)
        x += pitch
    return "".join(chars), cost


def ocr(pic: Picture, min_delta: int = OCR_MIN_DELTA) -> List[TextLine]:
    """Read the text lines of a picture. Real decoding: it knows the font, never the text."""
    w, h, g = pic.width, pic.height, pic.grey
    hist = [0] * 256
    for v in g:
        hist[v] += 1
    bg = max(range(256), key=lambda v: hist[v])
    ink = [[abs(g[y * w + x] - bg) >= min_delta for x in range(w)] for y in range(h)]
    row_has = [any(r) for r in ink]
    bands, y = [], 0
    while y < h:
        if row_has[y]:
            start = y
            while y < h and row_has[y]:
                y += 1
            bands.append((start, y))
        y += 1
    out: List[TextLine] = []
    for top, bottom in bands:
        s = round((bottom - top) / GLYPH_H)
        if s < 1 or top + GLYPH_H * s > h:
            continue
        cols = [x for x in range(w) if any(ink[yy][x] for yy in range(top, bottom))]
        first = cols[0]
        best = None
        for x0 in range(max(0, first - (GLYPH_W - 1) * s), first + 1):
            text, cost = _decode_line(ink, top, s, x0, w)
            if best is None or cost < best[1]:
                best = (text, cost)
        text = " ".join(best[0].split())
        deltas = sorted(abs(g[yy * w + x] - bg) for yy in range(top, bottom) for x in cols if ink[yy][x])
        if text:
            out.append(TextLine(text, deltas[len(deltas) // 2], s, top))
    return out


_CACHE: Dict[Tuple[str, int], Tuple[Picture, List[TextLine]]] = {}


def read(data: bytes, min_delta: int = OCR_MIN_DELTA) -> Tuple[Picture, List[TextLine]]:
    """``decode_png`` + ``ocr``, cached by content hash (deterministic, so safe to cache)."""
    key = (hashlib.sha256(bytes(data)).hexdigest(), min_delta)
    if key not in _CACHE:
        if len(_CACHE) > 256:
            _CACHE.clear()
        pic = decode_png(data)
        _CACHE[key] = (pic, ocr(pic, min_delta))
    pic, lines = _CACHE[key]
    return Picture(pic.width, pic.height, pic.grey, dict(pic.metadata)), [TextLine(**ln.to_dict()) for ln in lines]
