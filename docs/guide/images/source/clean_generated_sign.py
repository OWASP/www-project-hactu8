"""Clean up the generated Big Field sign: background, tagline, badge, wolf."""
import sys
import numpy as np
from PIL import Image, ImageDraw, ImageFilter

src, logo_path, out = sys.argv[1:4]
im = Image.open(src).convert("RGB")
W, H = im.size
a = np.asarray(im).astype(np.float32)
lum = a @ np.array([0.299, 0.587, 0.114], np.float32)
mx, mn = a.max(2), a.min(2)
sat = (mx - mn) / np.maximum(mx, 1)

# --- 1. background: replace the painted checkerboard -------------------------
yy, xx = np.mgrid[0:H, 0:W].astype(np.float32)
d = np.sqrt(((xx - 420) / W) ** 2 + ((yy - 150) / H) ** 2)
t = np.clip(d / 1.05, 0, 1)[..., None]
light, dark = np.array([168, 170, 168], np.float32), np.array([104, 106, 105], np.float32)
bg = light * (1 - t) + dark * t
# soft shadow of the board and post on the grey, offset down and right
sh = Image.new("L", (W, H), 0)
sd = ImageDraw.Draw(sh)
sd.rectangle((222 + 14, 56 + 18, 960 + 14, 571 + 18), fill=255)
sd.rectangle((558 + 10, 20 + 14, 632 + 10, 768), fill=255)
sh = (np.asarray(sh.filter(ImageFilter.GaussianBlur(16))).astype(np.float32) / 255)[..., None]
bg = bg * (1 - 0.45 * sh)

protect = Image.new("L", (W, H), 0)
pd = ImageDraw.Draw(protect)
pd.rectangle((222, 56, 960, 571), fill=255)        # board, measured edges
pd.rectangle((558, 20, 632, 768), fill=255)        # post
protect = np.asarray(protect.filter(ImageFilter.GaussianBlur(1))).astype(np.float32) / 255
WOLF = [(966, 300), (982, 232), (1022, 262), (1070, 252), (1118, 262), (1162, 228), (1186, 298),
        (1192, 400), (1165, 468), (1128, 515), (1108, 600), (1045, 645), (990, 605), (975, 505), (963, 420)]
wolfkeep = Image.new("L", (W, H), 0)
ImageDraw.Draw(wolfkeep).polygon(WOLF, fill=255)                    # the wolf's outline, traced by hand
wolfkeep = np.asarray(wolfkeep.filter(ImageFilter.GaussianBlur(10))).astype(np.float32) / 255
protect = np.maximum(protect, wolfkeep)

greenish = (a[..., 1] > a[..., 0] + 6) & (a[..., 1] > a[..., 2] + 6)
grass = ((sat > 0.22) & (yy > 600) & (xx > 400) & (xx < 790) & (lum > 28)).astype(np.float32)
grass = np.asarray(Image.fromarray((grass * 255).astype(np.uint8)).filter(ImageFilter.GaussianBlur(2))).astype(np.float32) / 255
keep = np.clip(np.maximum(protect, grass), 0, 1)[..., None]

# Inside the protected wolf area the checkerboard still shows through the shadow:
# flatten it by mixing in a blurred copy and darkening.
blur = np.asarray(im.filter(ImageFilter.BoxBlur(18))).astype(np.float32)
wolfzone = Image.new("L", (W, H), 0)
ImageDraw.Draw(wolfzone).polygon(WOLF, fill=255)
wz = (np.asarray(wolfzone.filter(ImageFilter.GaussianBlur(10))).astype(np.float32) / 255)[..., None]
wz[:, :962] = 0     # never touch the board
fur = np.clip((52 - lum) / 14, 0, 1)[..., None]          # 1 on dark fur, 0 on lighter checker squares
flattened = a * 0.9
a = a * (1 - wz) + flattened * wz

# the wolf's body: a dark silhouette under the head, drawn first so the head blends into it
body = Image.new("L", (W, H), 0)
ImageDraw.Draw(body).polygon([(985, 425), (1040, 515), (1120, 510), (1180, 425), (1210, 520), (1236, 640),
                              (1250, 768), (930, 768), (948, 640), (966, 540)], fill=255)
body = (np.asarray(body.filter(ImageFilter.GaussianBlur(20))).astype(np.float32) / 255)[..., None]
bg2 = bg * (1 - body) + np.array([16, 16, 18], np.float32) * body
bg2[:572, :962] = bg[:572, :962]                         # the body is behind the board
out_a = a * keep + bg2 * (1 - keep)

# --- 2. the wolf: barely seen, only the eyes catch the light ------------------
eyes = Image.new("L", (W, H), 0)
ed = ImageDraw.Draw(eyes)
for cx, cy in ((1033, 377), (1108, 377)):
    ed.ellipse((cx - 11, cy - 7, cx + 11, cy + 7), fill=255)
eyes = (np.asarray(eyes.filter(ImageFilter.GaussianBlur(3))).astype(np.float32) / 255)[..., None]
dim = 1.0 * (1 - eyes) + 2.4 * eyes
out_a = out_a * (1 - wz) + np.clip(out_a * dim, 0, 255) * wz

# a soft amber glow around the eyes, so they read at small sizes
glow = Image.new("L", (W, H), 0)
gd = ImageDraw.Draw(glow)
for cx, cy in ((1033, 377), (1108, 377)):
    gd.ellipse((cx - 16, cy - 11, cx + 16, cy + 11), fill=255)
glow = (np.asarray(glow.filter(ImageFilter.GaussianBlur(9))).astype(np.float32) / 255)[..., None]
out_a = out_a + glow * np.array([120, 70, 10], np.float32) * 0.55
img = Image.fromarray(np.clip(out_a, 0, 255).astype(np.uint8))

# --- 3. the tagline: paint over it with board from the right of the same band --
y0, y1, x0, x1 = 522, 554, 434, 748
band = img.crop((748, y0, 748 + (x1 - x0) // 2 + 2, y1))
patch = Image.new("RGB", (x1 - x0, y1 - y0))
patch.paste(band, (0, 0))
patch.paste(band.transpose(Image.FLIP_LEFT_RIGHT), (band.width - 2, 0))
m = Image.new("L", patch.size, 0)
ImageDraw.Draw(m).rounded_rectangle((4, 3, patch.width - 5, patch.height - 4), 6, fill=255)
img.paste(patch, (x0, y0), m.filter(ImageFilter.GaussianBlur(3)))

# --- 4. the badge: the real OWASP wasp on a navy disc ------------------------
cx, cy, r = 594, 343, 34
disc = Image.new("L", (W, H), 0)
ImageDraw.Draw(disc).ellipse((cx - r, cy - r, cx + r, cy + r), fill=255)
img.paste(Image.new("RGB", (W, H), (38, 48, 92)), (0, 0), disc.filter(ImageFilter.GaussianBlur(1)))
logo = Image.open(logo_path).convert("RGBA").resize((2 * r, 2 * r), Image.LANCZOS)
lr, lg, lb, la = logo.split()
logo = Image.merge("RGBA", (lr.point(lambda v: min(255, v + 15)), lg.point(lambda v: min(255, v + 12)), lb, la))
img.paste(logo, (cx - r, cy - r), logo)

img.save(out)
print("wrote", out, img.size)
