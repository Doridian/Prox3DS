#!/usr/bin/env python3
"""Contact sheets of the rendered shots: sheet.py OUT [PER_SHEET] -> OUT/sheets/NN.png"""
import glob, os, sys
from PIL import Image, ImageDraw

out = sys.argv[1] if len(sys.argv) > 1 else "out"
per = int(sys.argv[2]) if len(sys.argv) > 2 else 8
shots = sorted(p for p in glob.glob(os.path.join(out, "*.png")))
os.makedirs(os.path.join(out, "sheets"), exist_ok=True)
for k in range(0, len(shots), per):
    group = shots[k:k + per]
    rows = (len(group) + 1) // 2
    sheet = Image.new("RGB", (2 * 404, rows * 258), (255, 255, 255))
    d = ImageDraw.Draw(sheet)
    for i, p in enumerate(group):
        im = Image.open(p).resize((400, 240), Image.LANCZOS)
        x, y = (i % 2) * 404, (i // 2) * 258
        d.text((x + 2, y + 2), os.path.basename(p)[:-4], fill=(0, 0, 0))
        sheet.paste(im, (x + 2, y + 16))
    sheet.save(os.path.join(out, "sheets", f"{k // per:02d}.png"))
