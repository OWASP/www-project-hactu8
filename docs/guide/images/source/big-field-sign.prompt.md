# Big Field sign: image generator prompt

The drawn version is `drawn-sign.svg` (made by `make_sign.py` in this folder: `python3 make_sign.py drawn-sign.svg`). This prompt is for a photographic version from an image generator. Most generators cannot reproduce the OWASP wasp exactly, so generate the jumper with a plain circular badge and composite the real logo from `assets/owasp.png` onto it afterwards.

## Prompt

Photograph of a traditional English country farm sign on a single weathered silver-grey oak post at dusk, wide 16:9 composition, sign centred. A painted timber board in heritage dark green with a moulded frame, old gloss paint chipped at the edges to show wood beneath, rusty nails with rust streaks. Lettering carved (routed V-groove) into the board in classic inscriptional capitals like Optima or Trajan, the grooves painted cream with the cut walls catching the light: "BIG FIELD" across the top and "JUMPERS CO." across the bottom, inside a cream pinstripe border with rounded corners. In the middle, a naively painted madder-red knitted jumper (sweater) with visible knit stitches and ribbed cuffs and hem, a cream circular badge with a wasp emblem knitted into the chest. Three small white woolly sheep with black faces and legs leap in an arc over the jumper, left to right, painted in a simple folk-art way. Dark, moody background, nothing else around the sign. Just behind the right end of the sign, deep in shadow, a wolf sits upright, almost invisible, a shape barely darker than the night with only the faintest rim of moonlight on its outline, its muzzle half hidden behind the board's edge, two glowing amber eyes fixed on the sign. Shallow depth of field, cinematic low warm light from the upper right, film grain, slight vignette, photorealistic textures, 35mm.

## Negative prompt

Text other than "BIG FIELD" and "JUMPERS CO.", misspelled lettering, American ranch sign, barn-red paint, slab-serif or western lettering, painted-on lettering, brightly lit or detailed wolf, cartoon, 3D render, brand-new sign, extra sheep, people, buildings, watermark.

## Notes

- Lettering is where generators fail most. If the words come out wrong, generate the sign blank and add the lettering in an editor, or use a generator with good text rendering.
- The cast and setting are canon in `docs/persona.md` and the story in `docs/guide/story/`.
