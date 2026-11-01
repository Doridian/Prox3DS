#!/usr/bin/env python3
"""Draws uisim's draw lists (OUT/*.txt) as PNGs and checks the text on them.

Text is drawn with the stand-in font from gen_metrics.py. Widths match the 3DS system font within
~5%, so anything closer than that to an edge counts as "tight", not as fine.

Checks per shot (report in OUT/report.txt, problems boxed in red in OUT/<shot>.png):
  offscreen  text past the screen edge
  overflow   text running out of the panel / bar / box it starts on
  overlap    two visible texts on top of each other
  tight      the same within the metric error
"""
import glob, os, sys
from PIL import Image, ImageDraw, ImageFont

FONT = os.environ.get("SIM_FONT", "/usr/share/fonts/TTF/NanumGothic.ttf")
SIZE, LINE = 26.8, 30.0
ERR = 0.05  # width error of the stand-in font
BUTTONS = {0xE000: "A", 0xE001: "B", 0xE002: "X", 0xE003: "Y", 0xE004: "L", 0xE005: "R", 0xE006: "+",
           0xE07D: "↕", 0xE07E: "↔"}
fonts = {}


def font(px):
    px = round(px * 4) / 4
    if px not in fonts:
        fonts[px] = ImageFont.truetype(FONT, px)
    return fonts[px]


def color(hexabgr):
    v = int(hexabgr, 16)
    return (v & 0xFF, v >> 8 & 0xFF, v >> 16 & 0xFF, v >> 24 & 0xFF)


def parse(path):
    ops = []
    for line in open(path, encoding="utf-8", errors="replace"):
        line = line.rstrip("\n")
        if line.startswith("R "):
            x, y, w, h, c = line[2:].split(" ")
            ops.append(("R", float(x), float(y), float(w), float(h), color(c)))
        elif line.startswith("T "):
            parts = line[2:].split(" ", 7)
            x, y, w, s, n = map(float, parts[:5])
            ops.append(("T", x, y, w, s, int(n), color(parts[5]), parts[7].replace("\x1f", "\n"), parts[6]))
    return ops


def draw(ops, scale):
    im = Image.new("RGBA", (400 * scale, 240 * scale), (0, 0, 0, 255))
    for op in ops:
        layer = Image.new("RGBA", im.size, (0, 0, 0, 0))
        d = ImageDraw.Draw(layer)
        if op[0] == "R":
            _, x, y, w, h, c = op
            if w > 0 and h > 0:
                d.rectangle([x * scale, y * scale, (x + w) * scale - 1, (y + h) * scale - 1], fill=c)
        else:
            _, x, y, w, s, n, c, text, align = op
            f = font(SIZE * s * scale)
            for i, ln in enumerate(text.split("\n")):
                cx, base = x * scale, (y + (i * LINE + 24.5) * s) * scale
                for ch in ln:
                    cp = ord(ch)
                    if cp in BUTTONS:
                        r = 10.5 * s * scale
                        d.ellipse([cx + 1, base - 2 * r + 2, cx + 2 * r + 1, base + 2], fill=c)
                        d.text((cx + r + 1, base - r + 2), BUTTONS[cp], fill=(30, 30, 30, 255), anchor="mm",
                               font=font(SIZE * s * scale * 0.6))
                        cx += 25 * s * scale
                        continue
                    d.text((cx, base), ch, fill=c, anchor="ls", font=f)
                    cx += (17 if ch.isdigit() else round(f.getlength(ch) / (SIZE * s * scale) * SIZE)) * s * scale
        im = Image.alpha_composite(im, layer)
    return im


def ink(op):
    """Text box: x0, x1, y0, y1 with the vertical extent of the glyphs, not the line box."""
    x, y, w, s, n = op[1:6]
    return x, x + w, y + 6 * s, y + ((n - 1) * LINE + 28) * s


def slack(op, side):
    """How far the stand-in font may be off at this side of the text (0 where it is anchored)."""
    w, align = op[3], op[8]
    if align == "C":
        return w * ERR / 2
    return w * ERR if (side == "right") == (align == "L") else 0


def check(ops):
    issues = []
    # A translucent full-screen rect (a dialog's backdrop) starts a new layer: texts behind it are
    # only compared with each other.
    layer, layers = 0, []
    for op in ops:
        if op[0] == "R" and op[3] >= 400 and op[4] >= 240 and op[5][3] < 0xF0:
            layer += 1
        layers.append(layer)

    def covered(i, box):
        cx, cy = (box[0] + box[1]) / 2, (box[2] + box[3]) / 2
        for op in ops[i + 1:]:
            if op[0] == "R" and op[5][3] >= 0xF0 and op[1] <= cx <= op[1] + op[3] and op[2] <= cy <= op[2] + op[4]:
                return True
        return False

    vis = [(i, op, ink(op)) for i, op in enumerate(ops)
           if op[0] == "T" and op[7].strip() and not covered(i, ink(op))]
    for i, op, (x0, x1, y0, y1) in vis:
        text = op[7]
        r = max(1.0, slack(op, "right"))
        if x0 < 0 or x1 > 400:
            issues.append(("offscreen", text, (x0, y0, x1, y1), f"{x1 - 400:+.0f}px"))
        elif x1 > 400 - r:
            issues.append(("tight", text, (x0, y0, x1, y1), f"{400 - x1:.0f}px to the screen edge"))
        host = None  # the latest rect (not full screen) under the text's start
        for op2 in reversed(ops[:i]):
            if op2[0] != "R" or (op2[3] >= 400 and op2[4] >= 240):
                continue
            rx, ry, rw, rh = op2[1:5]
            if rx <= x0 + 1 <= rx + rw and ry <= (y0 + y1) / 2 <= ry + rh:
                host = op2
                break
        if host and host[3] >= 30:
            rx, ry, rw, rh = host[1:5]
            over = max(x1 - (rx + rw), y1 - (ry + rh) - 1)
            if over > 0:
                issues.append(("overflow", text, (x0, y0, x1, y1), f"{over:.0f}px past its {rw:.0f}x{rh:.0f} rect"))
            elif x1 > rx + rw - r and x0 > rx + 1:
                issues.append(("tight", text, (x0, y0, x1, y1), f"{rx + rw - x1:.0f}px to the end of its rect"))
    for a in range(len(vis)):
        for b in range(a + 1, len(vis)):
            (ia, oa, A), (ib, ob, B) = vis[a], vis[b]
            if layers[ia] != layers[ib] or A[2] >= B[3] - 1 or B[2] >= A[3] - 1:
                continue
            if len(oa[7]) == 1 and len(ob[7]) == 1:  # uiMono cells: wide glyphs may touch
                continue
            if A[0] > B[0]:
                (ia, oa, A), (ib, ob, B) = (ib, ob, B), (ia, oa, A)
            gap = B[0] - A[1]
            if abs(gap) < 0.5 and oa[2] == ob[2]:  # one line drawn in pieces (x += uiText(...))
                continue
            tol = slack(oa, "right") + slack(ob, "left")
            box = (A[0], min(A[2], B[2]), max(A[1], B[1]), max(A[3], B[3]))
            if gap < -0.5:
                issues.append(("overlap", f"{oa[7]!r} / {ob[7]!r}", box, f"{-gap:.0f}px"))
            elif gap < tol:
                issues.append(("tight", f"{oa[7]!r} / {ob[7]!r}", box, f"{gap:.0f}px apart"))
    return issues


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "out"
    scale = int(os.environ.get("SIM_SCALE", "2"))
    report, counts = [], {}
    for path in sorted(glob.glob(os.path.join(out, "*.txt"))):
        if path.endswith("report.txt"):
            continue
        name = os.path.basename(path)[:-4]
        ops = parse(path)
        im = draw(ops, scale)
        issues = check(ops)
        d = ImageDraw.Draw(im)
        for kind, text, (x0, y0, x1, y1), what in issues:
            col = (255, 0, 0, 255) if kind != "tight" else (255, 160, 0, 255)
            d.rectangle([x0 * scale - 1, y0 * scale - 1, x1 * scale + 1, y1 * scale + 1], outline=col)
            report.append(f"{name}: {kind}: {what}: {text!r}" if kind != "overlap" else f"{name}: {kind}: {what}: {text}")
            counts[kind] = counts.get(kind, 0) + 1
        im.convert("RGB").save(os.path.join(out, name + ".png"))
    with open(os.path.join(out, "report.txt"), "w") as f:
        f.write("\n".join(report) + "\n")
    print("\n".join(report))
    print(", ".join(f"{v} {k}" for k, v in sorted(counts.items())) or "no issues")


if __name__ == "__main__":
    main()
