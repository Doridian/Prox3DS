#!/usr/bin/env python3
"""Draws the app's icon (48x48), the CIA's HOME menu banner (256x128) and its jingle.

The outputs are checked in (icon.png, banner.png, banner.wav); run this only to change them:
    python3 prox3ds/meta/make_art.py [path/to/bold.ttf]
Needs Pillow. Colors are the UI's (source/ui.c): night purple, violet accent, mint and cyan.
"""
import math
import os
import struct
import sys
import wave

from PIL import Image, ImageDraw, ImageFilter, ImageFont

HERE = os.path.dirname(os.path.abspath(__file__))

BG_TOP = (0x2A, 0x1A, 0x44)
BG_BOT = (0x0A, 0x07, 0x10)
PANEL = (0x15, 0x10, 0x20)
ACCENT = (0xB5, 0x7C, 0xF2)
MINT = (0x3D, 0xFF, 0xA0)
CYAN = (0x4D, 0xD8, 0xFF)
TEXT = (0xF2, 0xEE, 0xF8)
DIM = (0x8A, 0x7B, 0xA3)
CHIP = (0xFC, 0xF4, 0x34)


def lerp(a, b, t):
	return tuple(round(x + (y - x) * t) for x, y in zip(a, b))


def gradient(w, h, top, bot):
	g = Image.new("RGB", (w, h))
	d = ImageDraw.Draw(g)
	for y in range(h):
		d.line([(0, y), (w, y)], fill=lerp(top, bot, y / max(1, h - 1)))
	return g


def card_and_waves(size, cx, cy, s):
	"""A tilted contactless card (chip + antenna coil) with three NFC arcs to its right, on a
	transparent layer of `size`. (cx, cy): card centre, s: card width."""
	layer = Image.new("RGBA", size, (0, 0, 0, 0))

	# The card, drawn upright on its own layer and rotated.
	cw, ch = int(s), int(s * 0.63)
	pad = int(s * 0.3)
	card = Image.new("RGBA", (cw + 2 * pad, ch + 2 * pad), (0, 0, 0, 0))
	d = ImageDraw.Draw(card)
	r = int(s * 0.09)
	box = (pad, pad, pad + cw, pad + ch)
	d.rounded_rectangle(box, r, fill=PANEL + (255,), outline=ACCENT + (255,), width=max(2, int(s * 0.045)))
	# antenna coil: concentric rounded rectangles
	for i in range(3):
		inset = int(s * (0.1 + i * 0.055))
		d.rounded_rectangle((box[0] + inset, box[1] + inset, box[2] - inset, box[3] - inset), max(1, r - inset // 3),
			outline=lerp(ACCENT, CYAN, i / 2) + (150,), width=max(1, int(s * 0.018)))
	# chip
	chw, chh = int(s * 0.2), int(s * 0.16)
	chx, chy = pad + int(cw * 0.2), pad + (ch - chh) // 2
	d.rounded_rectangle((chx, chy, chx + chw, chy + chh), int(s * 0.03), fill=CHIP + (255,))
	lw = max(1, int(s * 0.014))
	d.line([(chx, chy + chh // 2), (chx + chw, chy + chh // 2)], fill=(0x9A, 0x8A, 0x10, 255), width=lw)
	d.line([(chx + chw // 2, chy), (chx + chw // 2, chy + chh)], fill=(0x9A, 0x8A, 0x10, 255), width=lw)
	card = card.rotate(14, resample=Image.BICUBIC, expand=False)
	layer.alpha_composite(card, (int(cx - card.width / 2), int(cy - card.height / 2)))

	# NFC arcs, mint -> cyan, with a soft glow underneath
	arcs = Image.new("RGBA", size, (0, 0, 0, 0))
	d = ImageDraw.Draw(arcs)
	ox, oy = cx + s * 0.34, cy - s * 0.02
	w = max(2, int(s * 0.075))
	for i in range(3):
		rad = s * (0.36 + i * 0.17)
		col = lerp(MINT, CYAN, i / 2) + (255,)
		d.arc((ox - rad, oy - rad, ox + rad, oy + rad), -42, 42, fill=col, width=w)
	glow = arcs.filter(ImageFilter.GaussianBlur(s * 0.06))
	layer.alpha_composite(glow)
	layer.alpha_composite(arcs)
	return layer


def grid(w, h, step, width, alpha):
	g = Image.new("RGBA", (w, h), (0, 0, 0, 0))
	d = ImageDraw.Draw(g)
	for i in range(0, w, step):
		d.line([(i, 0), (i, h)], fill=ACCENT + (alpha,), width=width)
	for i in range(0, h, step):
		d.line([(0, i), (w, i)], fill=ACCENT + (alpha,), width=width)
	return g


def icon(path):
	S = 8  # supersampling
	N = 48 * S
	base = gradient(N, N, BG_TOP, BG_BOT).convert("RGBA")
	base.alpha_composite(grid(N, N, 8 * S, S // 2, 22))  # faint, like a scope screen
	base.alpha_composite(card_and_waves((N, N), N * 0.33, N * 0.52, N * 0.52))
	# opaque: the SMDH icon has no alpha, the HOME menu draws its own frame
	base.convert("RGB").resize((48, 48), Image.LANCZOS).save(path)


def banner(path, font_path):
	S = 4
	W, H = 256 * S, 128 * S
	base = gradient(W, H, BG_TOP, BG_BOT).convert("RGBA")
	base.alpha_composite(grid(W, H, 16 * S, S // 2, 30))
	base.alpha_composite(card_and_waves((W, H), W * 0.16, H * 0.5, H * 0.5))

	font = ImageFont.truetype(font_path, 27 * S)
	small = ImageFont.truetype(font_path, 11 * S)
	tx = int(W * 0.45)
	title = Image.new("RGBA", (W, H), (0, 0, 0, 0))
	td = ImageDraw.Draw(title)
	td.text((tx, H * 0.30), "Prox", font=font, fill=TEXT + (255,))
	px = tx + td.textlength("Prox", font=font)
	td.text((px, H * 0.30), "3DS", font=font, fill=ACCENT + (255,))
	td.text((tx + S, H * 0.64), "NFC TOOLKIT", font=small, fill=MINT + (255,))
	base.alpha_composite(title.filter(ImageFilter.GaussianBlur(3 * S)))
	base.alpha_composite(title)
	base.convert("RGB").resize((256, 128), Image.LANCZOS).save(path)


def jingle(path):
	"""Two short rising blips, like a reader finding a card."""
	rate = 32000
	samples = []
	for f0, f1, dur in ((1320, 1760, 0.09), (0, 0, 0.05), (1760, 2640, 0.16)):
		n = int(rate * dur)
		ph = 0.0
		for i in range(n):
			t = i / n
			if f0:
				ph += 2 * math.pi * (f0 + (f1 - f0) * t) / rate
				env = min(1.0, i / (rate * 0.004)) * (1 - t) ** 1.5
				v = (math.sin(ph) + 0.25 * math.sin(2 * ph)) * env * 0.45
			else:
				v = 0.0
			samples.append(v)
	samples += [0.0] * int(rate * 0.3)
	with wave.open(path, "wb") as w:
		w.setnchannels(1)
		w.setsampwidth(2)
		w.setframerate(rate)
		w.writeframes(b"".join(struct.pack("<h", int(max(-1, min(1, v)) * 32767)) for v in samples))


if __name__ == "__main__":
	font = sys.argv[1] if len(sys.argv) > 1 else "/usr/share/fonts/TTF/DejaVuSans-Bold.ttf"
	icon(os.path.join(HERE, "..", "icon.png"))
	banner(os.path.join(HERE, "banner.png"), font)
	jingle(os.path.join(HERE, "banner.wav"))
