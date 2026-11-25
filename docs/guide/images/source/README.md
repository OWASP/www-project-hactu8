# Sources for the Big Field sign

The guide shows `../big-field-sign.jpg`. These files are how it was made.

| File | What it is |
| --- | --- |
| `big-field-sign-master.png` | Full-size edited image. Export the JPEG from this (quality about 80). |
| `clean_generated_sign.py` | The edit applied to the AI-generated original: grey background in place of a painted checkerboard, a made-up tagline painted out, the real OWASP wasp on the badge, and the wolf cut out with a body added. The generated original is not kept, because it contains text and a logo that are not ours. |
| `big-field-sign.prompt.md` | The image-generator prompt. |
| `drawn-sign.svg`, `make_sign.py` | An earlier version drawn in code, kept as a fallback (`python3 make_sign.py drawn-sign.svg`). |

The edit script needs Pillow and NumPy:

```bash
python3 clean_generated_sign.py <generated.png> ../../../../assets/owasp.png big-field-sign-master.png
```

The image is AI-generated, then edited, and the guide says so under it.
