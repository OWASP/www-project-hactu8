"""Imaging tests: the PNG codec, the font and the OCR are real, and their limits are measured.

The OCR must read what was drawn, for any text in its font, at every scale,
and must not depend on which image is an attack. The decoder must handle
every scanline filter, check CRCs and refuse oversized or bomb-like input.

Run from the skill folder:  python -m unittest discover tests
"""

from __future__ import annotations

import itertools
import os
import random
import struct
import sys
import unittest
import zlib

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, SKILL_DIR)

import imaging  # noqa: E402
from imaging import FONT, ImageError, Line, decode_png, encode_png, ocr, render, strip_metadata  # noqa: E402


def _chunk(kind: bytes, data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)


def png_with_filters(width: int, height: int, grey):
    """A grey PNG whose rows use filters 0..4 in turn, encoded the way a real encoder would."""
    rows = [list(grey[y * width:(y + 1) * width]) for y in range(height)]
    raw = bytearray()
    prev = [0] * width
    for y, row in enumerate(rows):
        f = y % 5
        raw.append(f)
        for i, v in enumerate(row):
            a = row[i - 1] if i else 0
            b = prev[i]
            c = prev[i - 1] if i else 0
            pred = {0: 0, 1: a, 2: b, 3: (a + b) // 2, 4: imaging._paeth(a, b, c)}[f]
            raw.append((v - pred) & 0xFF)
        prev = row
    return (imaging.PNG_SIGNATURE + _chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 0, 0, 0, 0))
            + _chunk(b"IDAT", zlib.compress(bytes(raw))) + _chunk(b"IEND", b""))


class CodecTest(unittest.TestCase):
    def test_round_trip_and_metadata(self):
        grey = [(x * 7 + y * 13) % 256 for y in range(9) for x in range(11)]
        data = encode_png(11, 9, grey, {"Description": "hello", "Comment": "world"})
        pic = decode_png(data)
        self.assertEqual((pic.width, pic.height, pic.grey), (11, 9, grey))
        self.assertEqual(pic.metadata, {"Description": "hello", "Comment": "world"})

    def test_every_filter_decodes(self):
        rng = random.Random(8)
        grey = [rng.randrange(256) for _ in range(23 * 10)]
        self.assertEqual(decode_png(png_with_filters(23, 10, grey)).grey, grey)

    def test_strip_metadata_keeps_pixels(self):
        data = render([Line("Total 1.00 GBP")], text={"Description": "System note: x"})
        clean = strip_metadata(data)
        self.assertEqual(decode_png(clean).metadata, {})
        self.assertEqual(decode_png(clean).grey, decode_png(data).grey)
        self.assertNotIn(b"tEXt", clean)

    def test_guards(self):
        good = render([Line("OK")])
        with self.assertRaises(ImageError):
            decode_png(b"GIF89a" + good[6:])
        bad_crc = bytearray(good)
        bad_crc[30] ^= 0xFF                                   # inside IHDR or the first chunk's CRC
        with self.assertRaises(ImageError):
            decode_png(bytes(bad_crc))
        with self.assertRaises(ImageError):
            decode_png(b"\x00" * (imaging.MAX_PNG_BYTES + 1))
        huge = (imaging.PNG_SIGNATURE + _chunk(b"IHDR", struct.pack(">IIBBBBB", 5000, 10, 8, 0, 0, 0, 0))
                + _chunk(b"IEND", b""))
        with self.assertRaises(ImageError):
            decode_png(huge)
        # A bomb: the header says 10x10 but the data inflates to far more.
        bomb = (imaging.PNG_SIGNATURE + _chunk(b"IHDR", struct.pack(">IIBBBBB", 10, 10, 8, 0, 0, 0, 0))
                + _chunk(b"IDAT", zlib.compress(b"\x00" * 5_000_000)) + _chunk(b"IEND", b""))
        with self.assertRaises(ImageError):
            decode_png(bomb)


class FontAndOcrTest(unittest.TestCase):
    def test_glyphs_are_distinct(self):
        self.assertEqual(len(set(FONT.values())), len(FONT))
        closest = min(sum(a != b for a, b in zip(x, y)) for x, y in itertools.combinations(FONT.values(), 2))
        self.assertGreater(closest, imaging.MAX_MATCH_DISTANCE)

    def test_reads_every_glyph_at_every_scale(self):
        chars = "".join(sorted(FONT))
        for scale in (1, 2, 3):
            with self.subTest(scale=scale):
                per_line = (640 - 24) // (6 * scale)
                lines = [Line("A" + chars[i:i + per_line - 1], scale) for i in range(0, len(chars), per_line - 1)]
                got = [ln.text for ln in ocr(decode_png(render(lines, seed=f"all-{scale}")))]
                self.assertEqual(got, [" ".join(ln.text.split()) for ln in lines])

    def test_reads_random_text_it_was_never_told(self):
        rng = random.Random(2026)
        alphabet = sorted(FONT) + [" "]
        for n in range(5):
            text = "R" + "".join(rng.choice(alphabet) for _ in range(30)) + "Z"   # fits at scale 3
            got = ocr(decode_png(render([Line(text, 1 + n % 3)], seed=f"rand-{n}")))
            self.assertEqual([ln.text for ln in got], [" ".join(text.split())])

    def test_contrast_is_measured_not_given(self):
        data = render([Line("PRINTED 1"), Line("FAINT 2", 2, imaging.PAPER - 6), Line("PALE 3", 2, imaging.PAPER - 60)])
        lines = ocr(decode_png(data))
        self.assertEqual([ln.text for ln in lines], ["PRINTED 1", "FAINT 2", "PALE 3"])
        printed, faint, pale = (ln.contrast for ln in lines)
        self.assertGreater(printed, 150)
        self.assertLessEqual(abs(faint - 6), 2)
        self.assertLessEqual(abs(pale - 60), 2)

    def test_ocr_threshold_hides_text_below_it(self):
        data = render([Line("VISIBLE"), Line("GONE", 2, imaging.PAPER - 2)])
        self.assertEqual([ln.text for ln in ocr(decode_png(data))], ["VISIBLE"])

    def test_unknown_shapes_read_as_question_marks(self):
        width, height = 40, 20
        grey = [imaging.PAPER] * (width * height)
        for y in range(4, 18):                  # a solid block, not a glyph
            for x in range(4, 14):
                grey[y * width + x] = imaging.INK
        self.assertEqual([ln.text for ln in ocr(decode_png(encode_png(width, height, grey)))], ["?"])


if __name__ == "__main__":
    unittest.main()
