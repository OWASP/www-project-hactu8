"""Generate the Big Field Jumpers Co. sign illustration as an SVG."""
import random
import sys

random.seed(8)
OUT = sys.argv[1]
W, H = 1600, 900

INK = "#efe3c2"      # cream signwriting
SHADE = "#13241a"    # letter shading
GREEN = "#25432f"    # heritage green board
NAVY = "#9a3527"     # jumper: madder red, reads on green
CREAM = "#efe4c8"    # sign paint / logo yarn


def grass(x0, x1, y_base, n, h_min, h_max, colors, width=(2, 5)):
    out = []
    for _ in range(n):
        x = random.uniform(x0, x1)
        h = random.uniform(h_min, h_max)
        lean = random.uniform(-0.45, 0.45) * h
        w = random.uniform(*width)
        y = y_base + random.uniform(-6, 10)
        c = random.choice(colors)
        out.append(
            f'<path d="M{x - w:.1f},{y:.1f} Q{x + lean * 0.3:.1f},{y - h * 0.6:.1f} '
            f'{x + lean:.1f},{y - h:.1f} Q{x + lean * 0.3 + w * 0.4:.1f},{y - h * 0.55:.1f} '
            f'{x + w:.1f},{y:.1f} Z" fill="{c}"/>'
        )
    return "\n".join(out)


def sheep(x, y, rot, s=1.0):
    return f'''<g transform="translate({x},{y}) rotate({rot}) scale({s})" filter="url(#outline)">
  <g stroke="#1d1a18" stroke-width="5.5" stroke-linecap="round" fill="none">
    <path d="M22,10 L56,16"/><path d="M17,14 L52,26"/>
    <path d="M-22,10 L-58,14"/><path d="M-17,14 L-54,24"/>
  </g>
  <g fill="#f6f1e4">
    <circle cx="-40" cy="-4" r="7"/>
    <circle cx="-25" cy="-5" r="16"/><circle cx="-9" cy="-14" r="18"/>
    <circle cx="9" cy="-14" r="18"/><circle cx="24" cy="-6" r="16"/>
    <circle cx="-18" cy="7" r="15"/><circle cx="0" cy="8" r="17"/>
    <circle cx="18" cy="7" r="15"/><circle cx="0" cy="-3" r="21"/>
  </g>
  <ellipse cx="42" cy="-8" rx="13" ry="10" transform="rotate(22 42 -8)" fill="#1d1a18"/>
  <ellipse cx="34" cy="-17" rx="7" ry="3.5" transform="rotate(-30 34 -17)" fill="#1d1a18"/>
  <circle cx="46" cy="-11" r="1.8" fill="#f6f1e4"/>
</g>'''


# Wolf silhouette (facing right) in a 400x210 box, feet on y=206.
WOLF = ("M105,90 C150,70 230,68 285,78 C300,60 318,45 330,40 L338,20 L346,40 L352,26 L357,46 "
        "C370,52 388,60 400,67 C397,75 384,79 370,79 C355,83 345,93 330,110 C325,130 318,140 312,150 "
        "L318,205 L306,206 L298,152 L290,205 L278,206 L276,150 C240,152 190,150 160,145 "
        "L168,205 L156,206 L140,140 L130,204 L118,205 L112,125 C100,128 60,150 18,166 "
        "C50,135 80,105 105,90 Z")

# Seated wolf facing left, 440x520 box, sitting on y=520.
SITTING = ("M6,130 C28,119 60,108 92,98 C100,80 110,64 122,56 L130,6 L150,48 L168,12 L182,58 "
           "C196,72 206,92 212,112 L228,122 L219,133 L238,146 L229,157 L252,176 "
           "C268,232 286,290 300,330 C330,355 352,395 354,438 C356,478 346,504 322,516 "
           "C362,518 402,510 430,488 C438,502 420,524 380,530 L112,528 L108,518 L118,350 "
           "C112,300 106,262 100,232 L88,226 L95,213 L82,205 L89,193 L76,184 "
           "C70,170 64,160 60,151 C42,147 26,141 8,136 Z")

# Arched sign: every curve is a concentric arc about (CX, CY).
import math
L, R_, B = 372, 1228, 602          # board left, right, bottom
CX, TOP, SIDE = 800, 64, 196       # arch peak y, and y where the arch meets the sides
HALF = (R_ - L) / 2
CY = (HALF ** 2 + SIDE ** 2 - TOP ** 2) / (2 * (SIDE - TOP))
RAD = CY - TOP


def board(i=0):
    """Outline of the board inset by i."""
    r = RAD - i
    x0, x1 = L + i, R_ - i
    y_side = CY - math.sqrt(r * r - (CX - x0) ** 2)
    return (f"M{x0},{B - i} L{x0},{y_side:.1f} A{r:.1f},{r:.1f} 0 0 1 {x1},{y_side:.1f} "
            f"L{x1},{B - i} Z")


def arc(r, deg):
    """Concentric arc of radius r spanning +-deg about the top."""
    a = math.radians(deg)
    xa, xb = CX - r * math.sin(a), CX + r * math.sin(a)
    y = CY - r * math.cos(a)
    return f"M{xa:.1f},{y:.1f} A{r:.1f},{r:.1f} 0 0 1 {xb:.1f},{y:.1f}"


def on_arc(r, deg):
    a = math.radians(deg)
    return CX + r * math.sin(a), CY - r * math.cos(a), deg


TEXT_R = RAD - 128                 # BIG FIELD baseline
JUMP_R = CY - 300                  # sheep's leap, peak at y=300
SHEEP = [on_arc(JUMP_R, d) for d in (-27, 0, 27)]

# Jumper outline centred on 0,0.
JUMPER = ("M-60,-90 C-40,-72 40,-72 60,-90 L125,-66 C150,-30 162,10 172,42 L136,56 "
          "C126,30 112,6 100,-8 L102,96 L-102,96 L-100,-8 C-112,6 -126,30 -136,56 "
          "L-172,42 C-162,10 -150,-30 -125,-66 Z")

svg = f'''<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 {W} {H}" width="{W}" height="{H}">
<title>Big Field Jumpers Co.</title>
<desc>A weathered English farm sign with lettering carved into a green panel, on a wooden post. "Big Field" across the top, "Jumpers Co." across the bottom, and three white sheep jumping over a knitted jumper with the OWASP wasp on it. Behind the sign, in the dark, a wolf sits as a dark outline with glowing eyes fixed on it.</desc>
<defs>
  <radialGradient id="sky" cx="62%" cy="30%" r="85%">
    <stop offset="0" stop-color="#3b3f45"/>
    <stop offset="0.55" stop-color="#1f2226"/>
    <stop offset="1" stop-color="#0b0c0d"/>
  </radialGradient>
  <linearGradient id="ground" x1="0" y1="0" x2="0" y2="1">
    <stop offset="0" stop-color="#1d1f17" stop-opacity="0"/>
    <stop offset="0.35" stop-color="#181a12"/>
    <stop offset="1" stop-color="#08090a"/>
  </linearGradient>
  <radialGradient id="light" cx="72%" cy="8%" r="95%">
    <stop offset="0" stop-color="#fff3d6" stop-opacity="0.22"/>
    <stop offset="0.5" stop-color="#000" stop-opacity="0"/>
    <stop offset="1" stop-color="#000" stop-opacity="0.45"/>
  </radialGradient>
  <radialGradient id="vignette" cx="50%" cy="45%" r="75%">
    <stop offset="0.55" stop-color="#000" stop-opacity="0"/>
    <stop offset="1" stop-color="#000" stop-opacity="0.75"/>
  </radialGradient>
  <radialGradient id="lair" cx="50%" cy="50%" r="50%">
    <stop offset="0" stop-color="#000" stop-opacity="0.55"/>
    <stop offset="0.6" stop-color="#000" stop-opacity="0.3"/>
    <stop offset="1" stop-color="#000" stop-opacity="0"/>
  </radialGradient>
  <radialGradient id="eye" cx="45%" cy="40%" r="60%">
    <stop offset="0" stop-color="#fff2b0"/>
    <stop offset="0.45" stop-color="#f2b53a"/>
    <stop offset="1" stop-color="#9a4a0c"/>
  </radialGradient>
  <radialGradient id="stain" cx="50%" cy="50%" r="50%">
    <stop offset="0" stop-color="#4a3018" stop-opacity="0.35"/>
    <stop offset="1" stop-color="#4a3018" stop-opacity="0"/>
  </radialGradient>
  <linearGradient id="rust" x1="0" y1="0" x2="0" y2="1">
    <stop offset="0" stop-color="#6b3410" stop-opacity="0.75"/>
    <stop offset="1" stop-color="#6b3410" stop-opacity="0"/>
  </linearGradient>

  <!-- painted boards: grain, then paint that has flaked off in patches -->
  <filter id="peel" x="0" y="0" width="100%" height="100%" color-interpolation-filters="sRGB">
    <feTurbulence type="fractalNoise" baseFrequency="0.004 0.11" numOctaves="4" seed="3" result="grain"/>
    <feColorMatrix in="grain" type="matrix" values="1 0 0 0 -0.16  0.7 0 0 0 -0.12  0.42 0 0 0 -0.08  0 0 0 0 1" result="wood"/>
    <feColorMatrix in="grain" type="matrix" values="0.45 0 0 0 0.68  0.45 0 0 0 0.66  0.45 0 0 0 0.62  0 0 0 0 1" result="lite"/>
    <feBlend in="SourceGraphic" in2="lite" mode="multiply" result="paint"/>
    <feTurbulence type="fractalNoise" baseFrequency="0.03 0.075" numOctaves="4" seed="11" result="pn"/>
    <feColorMatrix in="pn" type="matrix" values="0 0 0 0 0  0 0 0 0 0  0 0 0 0 0  1 0 0 0 0" result="pa"/>
    <feComponentTransfer in="pa" result="mask"><feFuncA type="linear" slope="-24" intercept="18.6"/></feComponentTransfer>
    <feComposite in="paint" in2="mask" operator="in" result="paintKept"/>
    <feMerge result="m"><feMergeNode in="wood"/><feMergeNode in="paintKept"/></feMerge>
    <feComposite in="m" in2="SourceAlpha" operator="in"/>
  </filter>
  <!-- bare weathered post -->
  <filter id="postwood" x="0" y="0" width="100%" height="100%" color-interpolation-filters="sRGB">
    <feTurbulence type="fractalNoise" baseFrequency="0.16 0.005" numOctaves="4" seed="5" result="g"/>
    <feColorMatrix in="g" type="matrix" values="0.82 0 0 0 -0.08  0.76 0 0 0 -0.08  0.66 0 0 0 -0.07  0 0 0 0 1" result="w"/>
    <feComposite in="w" in2="SourceAlpha" operator="in"/>
  </filter>
  <!-- hand-painted wobble -->
  <filter id="brush" x="-5%" y="-10%" width="110%" height="120%">
    <feTurbulence type="fractalNoise" baseFrequency="0.035" numOctaves="2" seed="2" result="t"/>
    <feDisplacementMap in="SourceGraphic" in2="t" scale="5" xChannelSelector="R" yChannelSelector="G"/>
  </filter>
  <filter id="rough" x="-2%" y="-2%" width="104%" height="104%">
    <feTurbulence type="fractalNoise" baseFrequency="0.02" numOctaves="3" seed="9" result="t"/>
    <feDisplacementMap in="SourceGraphic" in2="t" scale="9" xChannelSelector="R" yChannelSelector="G"/>
  </filter>
  <filter id="outline" x="-20%" y="-20%" width="140%" height="140%">
    <feMorphology in="SourceAlpha" operator="dilate" radius="2.2" result="d"/>
    <feFlood flood-color="#2a2420"/><feComposite in2="d" operator="in" result="o"/>
    <feMerge><feMergeNode in="o"/><feMergeNode in="SourceGraphic"/></feMerge>
  </filter>
  <filter id="glow" x="-200%" y="-200%" width="500%" height="500%">
    <feGaussianBlur stdDeviation="7"/>
  </filter>
  <filter id="shadowblur" x="-10%" y="-30%" width="120%" height="160%"><feGaussianBlur stdDeviation="1.8"/></filter>
  <!-- letters cut into the board: shadowed upper-right wall, lit lower-left wall, dark cut edge -->
  <filter id="carve" x="-5%" y="-20%" width="110%" height="140%" color-interpolation-filters="sRGB">
    <feMorphology in="SourceAlpha" operator="dilate" radius="1.6" result="lip"/>
    <feFlood flood-color="#0c1710" flood-opacity="0.9"/><feComposite in2="lip" operator="in" result="edge"/>
    <feOffset in="SourceAlpha" dx="-5" dy="5" result="o1"/>
    <feComposite in="SourceAlpha" in2="o1" operator="out" result="band1"/>
    <feGaussianBlur in="band1" stdDeviation="1.6" result="b1"/>
    <feFlood flood-color="#1b1a12" flood-opacity="0.85"/><feComposite in2="b1" operator="in" result="shade"/>
    <feOffset in="SourceAlpha" dx="3" dy="-3" result="o2"/>
    <feComposite in="SourceAlpha" in2="o2" operator="out" result="band2"/>
    <feGaussianBlur in="band2" stdDeviation="1" result="b2"/>
    <feFlood flood-color="#fffaf0" flood-opacity="0.55"/><feComposite in2="b2" operator="in" result="lit"/>
    <feMerge result="m"><feMergeNode in="edge"/><feMergeNode in="SourceGraphic"/><feMergeNode in="shade"/><feMergeNode in="lit"/></feMerge>
    <feComposite in="m" in2="lip" operator="in"/>
  </filter>
  <filter id="rim" x="-10%" y="-10%" width="120%" height="120%"><feGaussianBlur stdDeviation="2.2"/></filter>
  <filter id="soft" x="-10%" y="-30%" width="120%" height="160%"><feGaussianBlur stdDeviation="3.5"/></filter>
  <filter id="dropshadow" x="-10%" y="-10%" width="130%" height="130%">
    <feGaussianBlur in="SourceAlpha" stdDeviation="9"/>
    <feOffset dx="-14" dy="12"/>
    <feComponentTransfer><feFuncA type="linear" slope="0.7"/></feComponentTransfer>
    <feMerge><feMergeNode/><feMergeNode in="SourceGraphic"/></feMerge>
  </filter>
  <filter id="filmgrain" x="0" y="0" width="100%" height="100%">
    <feTurbulence type="fractalNoise" baseFrequency="0.9" numOctaves="2" seed="4"/>
    <feColorMatrix type="saturate" values="0"/>
  </filter>

  <!-- knit stitches: rows of little Vs -->
  <pattern id="knit" width="9" height="11" patternUnits="userSpaceOnUse">
    <path d="M1.2,0.8 L4.5,9.5" stroke="#000" stroke-opacity="0.38" stroke-width="2.6" stroke-linecap="round"/>
    <path d="M7.8,0.8 L4.5,9.5" stroke="#000" stroke-opacity="0.38" stroke-width="2.6" stroke-linecap="round"/>
    <path d="M1.6,0.6 L4.2,7.6" stroke="#fff" stroke-opacity="0.22" stroke-width="1.1" stroke-linecap="round"/>
    <path d="M7.4,0.6 L4.8,7.6" stroke="#fff" stroke-opacity="0.22" stroke-width="1.1" stroke-linecap="round"/>
  </pattern>
  <pattern id="rib" width="7" height="10" patternUnits="userSpaceOnUse">
    <rect width="3.5" height="10" fill="#000" fill-opacity="0.32"/>
  </pattern>
  <clipPath id="jclip"><path d="{JUMPER}"/></clipPath>
</defs>

<!-- night backdrop -->
<rect width="{W}" height="{H}" fill="url(#sky)"/>
<rect y="700" width="{W}" height="200" fill="url(#ground)"/>
{grass(0, W, 790, 260, 18, 70, ["#14170f", "#1a1d13", "#10120c", "#22251a"])}

<ellipse cx="640" cy="862" rx="560" ry="62" fill="#5a5a44" opacity="0.55" filter="url(#glow)"/>
<ellipse cx="620" cy="864" rx="430" ry="40" fill="#77735a" opacity="0.35" filter="url(#glow)"/>
<!-- shadows on the ground: the post's, and one that belongs to nobody you can see -->
<path d="M772,852 L812,852 L430,880 L360,880 Z" fill="#000" opacity="0.6" filter="url(#soft)"/>

<!-- the Wolf, sitting in the dark behind the sign, watching it -->
<ellipse cx="1390" cy="560" rx="330" ry="420" fill="url(#lair)"/>
<g transform="translate(1200,318) scale(0.86)">
  <path d="{SITTING}" fill="none" stroke="#8c98a6" stroke-opacity="0.22" stroke-width="3" filter="url(#rim)"/>
  <path d="{SITTING}" fill="#08090b"/>
  <path d="{SITTING}" fill="none" stroke="#4c5560" stroke-opacity="0.45" stroke-width="1.2"/>
  <g filter="url(#glow)">
    <ellipse cx="104" cy="94" rx="9" ry="5" fill="#f0a52a"/>
    <ellipse cx="132" cy="90" rx="9" ry="5" fill="#f0a52a"/>
  </g>
  <path d="M94,96 Q104,87 114,93 Q104,100 94,96 Z" fill="url(#eye)"/>
  <path d="M122,92 Q132,83 142,89 Q132,96 122,92 Z" fill="url(#eye)"/>
  <ellipse cx="99.5" cy="94" rx="1.4" ry="3.6" fill="#140800"/>
  <ellipse cx="127.5" cy="90" rx="1.4" ry="3.6" fill="#140800"/>
</g>

<!-- post -->
<g filter="url(#dropshadow)">
  <rect x="760" y="70" width="82" height="800" fill="#7a7468" filter="url(#postwood)"/>
  <rect x="760" y="70" width="82" height="800" fill="url(#light)"/>
  
</g>

<!-- the sign -->
<g transform="rotate(-1.3 800 350)" filter="url(#dropshadow)">
  <g filter="url(#rough)">
    <g filter="url(#peel)">
      <path d="{board(0)}" fill="{GREEN}"/>
      <!-- moulded frame -->
      <path d="{board(9)}" fill="none" stroke="#1a3123" stroke-width="18"/>
      <path d="{board(2)}" fill="none" stroke="#3d6149" stroke-width="3"/>
      <path d="{board(20)}" fill="none" stroke="#11200f" stroke-width="3"/>
      <!-- signwriter's pinstripe -->
      <path d="{board(38)}" fill="none" stroke="{INK}" stroke-width="3.5" stroke-linejoin="round" filter="url(#brush)"/>

      <path id="bigfield-arc" d="{arc(TEXT_R, 50)}" fill="none"/>
      <!-- lettering -->
      <g font-family="'Trajan Pro', Optima, Candara, 'Gill Sans', sans-serif" font-weight="700" text-anchor="middle" fill="#d8c79c" filter="url(#carve)">
        <text font-size="112" letter-spacing="10"><textPath href="#bigfield-arc" xlink:href="#bigfield-arc" startOffset="50%">BIG FIELD</textPath></text>
        <text x="800" y="550" font-size="80" letter-spacing="12">JUMPERS CO.</text>
      </g>

      <!-- path of the jump -->
      <path d="{arc(JUMP_R, 42)}" fill="none" stroke="{INK}" stroke-opacity="0.55" stroke-width="4" stroke-dasharray="1 13" stroke-linecap="round"/>

      <!-- the jumper -->
      <g transform="translate(800,428) scale(0.72)" filter="url(#brush)">
        <path d="{JUMPER}" fill="{NAVY}"/>
        <g clip-path="url(#jclip)">
          <!-- OWASP wasp, stitched in cream -->
          <g transform="translate(0,6) scale(0.215) translate(-300,-300)" fill="{CREAM}">
            <circle cx="300" cy="300" r="246" fill="none" stroke="{CREAM}" stroke-width="44"/>
            <path d="M332,224 C262,204 150,204 116,215 C130,238 200,264 240,262 C282,257 322,246 334,236 Z"/>
            <path d="M332,256 C290,272 232,332 196,402 C242,386 302,340 344,288 Z"/>
            <path d="M352,288 C334,342 330,402 380,476 C396,420 392,360 378,298 Z"/>
            <ellipse cx="354" cy="250" rx="34" ry="24" transform="rotate(-32 354 250)"/>
            <circle cx="396" cy="204" r="27"/>
            <path d="M392,180 L398,150 L412,140" fill="none" stroke="{CREAM}" stroke-width="7" stroke-linecap="round"/>
            <path d="M414,196 L438,200 L452,192" fill="none" stroke="{CREAM}" stroke-width="7" stroke-linecap="round"/>
            <g fill="none" stroke="{CREAM}" stroke-width="7" stroke-linecap="round">
              <path d="M320,226 L302,198"/><path d="M330,216 L322,184"/><path d="M342,214 L340,182"/>
              <path d="M372,262 L404,268 L424,266"/><path d="M366,274 L392,290 L414,292"/><path d="M356,280 L376,300 L398,306"/>
            </g>
          </g>
          <!-- ribbing: collar, cuffs, hem -->
          <path d="M-62,-92 C-40,-70 40,-70 62,-92 L62,-78 C40,-58 -40,-58 -62,-78 Z" fill="url(#rib)"/>
          <rect x="-110" y="74" width="220" height="24" fill="url(#rib)"/>
          <path d="M-176,30 L-140,46 L-134,60 L-176,48 Z" fill="url(#rib)"/>
          <path d="M176,30 L140,46 L134,60 L176,48 Z" fill="url(#rib)"/>
          <rect x="-200" y="-120" width="400" height="240" fill="url(#knit)"/>
        </g>
        <path d="{JUMPER}" fill="none" stroke="#4a1710" stroke-width="4"/>
      </g>

      <!-- three sheep clearing it -->
      {"".join(sheep(round(x, 1), round(y, 1), d, 1.12) for x, y, d in SHEEP)}
    </g>

    <!-- stains and wear -->
    <ellipse cx="460" cy="560" rx="120" ry="60" fill="url(#stain)"/>
    <ellipse cx="1150" cy="150" rx="90" ry="70" fill="url(#stain)"/>
    <ellipse cx="980" cy="470" rx="70" ry="40" fill="url(#stain)"/>
  </g>
  <!-- plank gaps -->
  <!-- nails with rust runs -->
  <g>
    {"".join(f'<rect x="{x - 3}" y="{y + 4}" width="6" height="{random.randint(26, 60)}" fill="url(#rust)"/><circle cx="{x}" cy="{y}" r="5.5" fill="#2a2520"/><circle cx="{x - 1.5}" cy="{y - 1.5}" r="2" fill="#6d655c"/>' for x in (784, 816) for y in (TOP + 20, 594))}
  </g>
  <!-- evening light across the face -->
  <path d="{board(0)}" fill="url(#light)"/>
</g>

{grass(600, 860, 840, 70, 30, 80, ["#0d0f09", "#12140d", "#0a0b07"], (2, 4))}
{grass(0, W, 905, 160, 40, 110, ["#080906", "#0c0d09", "#050604"], (3, 7))}

<!-- photographic finish -->
<rect width="{W}" height="{H}" fill="url(#vignette)"/>
<rect width="{W}" height="{H}" filter="url(#filmgrain)" opacity="0.07"/>
</svg>
'''

with open(OUT, "w") as f:
    f.write(svg)
print("wrote", OUT)
