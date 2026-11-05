// Top-screen drawing helpers and the log ring, see ui.h.

#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <3ds.h>

#include "field.h"
#include "ui.h"

u32 uiCol[COL_N];

static C3D_RenderTarget *top, *bot;
static char hints[256];
static C2D_TextBuf frameBuf, monoBuf;
static C2D_Text mono[95]; // ' ' .. '~'
static u8 asciiW[128];     // glyph advances, wrapping measures a lot


void uiInit(void)
{
	C3D_Init(C3D_DEFAULT_CMDBUF_SIZE);
	C2D_Init(C2D_DEFAULT_MAX_OBJECTS);
	C2D_Prepare();
	fontEnsureMapped(); // uiTextWidth reads the system font's widths
	for (int c = 0; c < 128; c++) asciiW[c] = fontGetCharWidthInfo(NULL, fontGlyphIndexFromCodePoint(NULL, c))->charWidth;
	top = C2D_CreateScreenTarget(GFX_TOP, GFX_LEFT);
	bot = C2D_CreateScreenTarget(GFX_BOTTOM, GFX_LEFT);
	frameBuf = C2D_TextBufNew(8192);
	monoBuf = C2D_TextBufNew(256);
	for (int c = 0; c < 95; c++) {
		char s[2] = { 32 + c, 0 };
		C2D_TextParse(&mono[c], monoBuf, s);
		C2D_TextOptimize(&mono[c]);
	}
	static const u32 rgb[COL_N] = {
		[COL_BG] = 0x0A0710, [COL_PANEL] = 0x151020, [COL_BAR] = 0x201731, [COL_TEXT] = 0xF2EEF8,
		[COL_DIM] = 0x8A7BA3, [COL_ACCENT] = 0xB57CF2, [COL_SEL] = 0x3A2160, [COL_CURSOR] = 0xFCF434,
		[COL_WARN] = 0xFCF434, [COL_ERR] = 0xFF4D7A, [COL_OK] = 0x3DFFA0, [COL_KEYA] = 0x3DFFA0,
		[COL_KEYB] = 0x4DD8FF, [COL_ACL] = 0xFF9A3D, [COL_CHANGED] = 0xFFF27A,
	};
	for (int i = 0; i < COL_N; i++) uiCol[i] = C2D_Color32(rgb[i] >> 16, rgb[i] >> 8 & 0xFF, rgb[i] & 0xFF, 0xFF);
}

void uiExit(void)
{
	C2D_TextBufDelete(monoBuf);
	C2D_TextBufDelete(frameBuf);
	C2D_Fini();
	C3D_Fini();
}

void uiFrameBegin(void)
{
	C3D_FrameBegin(C3D_FRAME_SYNCDRAW);
	C2D_TargetClear(top, uiCol[COL_BG]);
	C2D_TargetClear(bot, uiCol[COL_BG]);
	C2D_SceneBegin(top);
	C2D_TextBufClear(frameBuf);
	*hints = 0;
}

void uiBottom(void)
{
	C2D_SceneBegin(bot);
}

static bool touchDown, touchRep;
static float touchX, touchY;

void uiTouch(bool down, bool repeat, float x, float y)
{
	touchDown = down, touchRep = repeat, touchX = x, touchY = y;
}

// A button's face: neon edge under it, corner ticks
static void face(float x, float y, float w, float h, u32 color, bool hit)
{
	uiRect(x, y, w, h, hit ? uiCol[COL_ACCENT] : color);
	uiRect(x, y + h - 1, w, 1, hit ? uiCol[COL_CURSOR] : uiCol[COL_ACCENT]);
	uiRect(x, y, 3, 1, uiCol[COL_DIM]);
	uiRect(x, y, 1, 3, uiCol[COL_DIM]);
}

static bool button(float x, float y, float w, float h, u32 color, const char *label, bool rep)
{
	bool hit = touchDown && (rep || !touchRep) && touchX >= x && touchX < x + w && touchY >= y && touchY < y + h;
	face(x, y, w, h, color, hit);
	char t[64];
	snprintf(t, sizeof(t), "%s", label);
	uiTextCenter(x + w / 2, y + (h - 16) / 2, S_BODY, uiCol[COL_TEXT], "%s", uiFit(t, w - 6, S_BODY));
	if (hit) touchDown = false; // one button per tap
	return hit;
}

bool uiButton2(float x, float y, float w, float h, u32 color, const char *caption, const char *label)
{
	bool hit = touchDown && !touchRep && touchX >= x && touchX < x + w && touchY >= y && touchY < y + h;
	face(x, y, w, h, color, hit);
	char t[64];
	snprintf(t, sizeof(t), "%s", caption);
	uiTextCenter(x + w / 2, y + 1, 0.34f, uiCol[COL_DIM], "%s", uiFit(t, w - 6, 0.34f));
	snprintf(t, sizeof(t), "%s", label);
	uiTextCenter(x + w / 2, y + h - 15, S_SMALL, uiCol[COL_TEXT], "%s", uiFit(t, w - 6, S_SMALL));
	if (hit) touchDown = false;
	return hit;
}

bool uiButton(float x, float y, float w, float h, u32 color, const char *label)
{
	return button(x, y, w, h, color, label, false);
}

bool uiButtonRep(float x, float y, float w, float h, u32 color, const char *label)
{
	return button(x, y, w, h, color, label, true);
}

void uiFrameEnd(void)
{
	C3D_FrameEnd(0);
}

void uiRect(float x, float y, float w, float h, u32 color)
{
	C2D_DrawRectSolid(x, y, 0.5f, w, h, color);
}

void uiLine(float x0, float y0, float x1, float y1, float thick, u32 color)
{
	C2D_DrawLine(x0, y0, color, x1, y1, color, thick, 0.5f);
}

void uiBar(float x, float y, float w, float h, float frac, u32 color)
{
	frac = frac < 0 ? 0 : frac > 1 ? 1 : frac;
	uiRect(x, y, w, h, uiCol[COL_BG]);
	uiRect(x, y + h - 1, w, 1, uiCol[COL_SEL]);
	float f = w * frac;
	for (float sx = x; sx < x + f; sx += 4) uiRect(sx, y, (x + f - sx < 3 ? x + f - sx : 3), h, color); // segments
	if (frac > 0 && frac < 1) uiRect(x + f - 2, y - 1, 2, h + 2, uiCol[COL_CURSOR]);
}

void uiTri(float x0, float y0, float x1, float y1, float x2, float y2, u32 color)
{
	C2D_DrawTriangle(x0, y0, color, x1, y1, color, x2, y2, color, 0.5f);
}

static float drawV(float x, float y, float scale, u32 color, u32 flags, const char *fmt, va_list va)
{
	char s[512];
	vsnprintf(s, sizeof(s), fmt, va);
	C2D_Text t;
	C2D_TextParse(&t, frameBuf, s);
	C2D_DrawText(&t, C2D_WithColor | flags, x, y, 0.5f, scale, scale, color);
	return t.width * scale;
}

float uiText(float x, float y, float scale, u32 color, const char *fmt, ...)
{
	va_list va;
	va_start(va, fmt);
	float w = drawV(x, y, scale, color, 0, fmt, va);
	va_end(va);
	return w;
}

void uiTextRight(float right, float y, float scale, u32 color, const char *fmt, ...)
{
	va_list va;
	va_start(va, fmt);
	drawV(right, y, scale, color, C2D_AlignRight, fmt, va);
	va_end(va);
}

void uiTextCenter(float cx, float y, float scale, u32 color, const char *fmt, ...)
{
	va_list va;
	va_start(va, fmt);
	drawV(cx, y, scale, color, C2D_AlignCenter, fmt, va);
	va_end(va);
}

// Width of s[0..n) (one line) as C2D_TextParse measures it: the glyphs' advances. No text buffer
// needed, so wrapping and fitting don't eat into the frame's glyphs.
static float widthN(const char *s, int n, float scale)
{
	float w = 0;
	const u8 *p = (const u8 *)s, *e = p + n;
	while (p < e && *p) {
		if (*p < 128) {
			w += asciiW[*p++];
			continue;
		}
		u32 cp;
		ssize_t k = decode_utf8(&cp, p);
		if (k <= 0) break;
		p += k;
		w += fontGetCharWidthInfo(NULL, fontGlyphIndexFromCodePoint(NULL, cp))->charWidth;
	}
	return w * scale;
}

float uiTextWidth(float scale, const char *s)
{
	float w = 0;
	for (;;) {
		const char *e = strchr(s, '\n');
		int n = e ? e - s : (int)strlen(s);
		float lw = widthN(s, n, scale);
		if (lw > w) w = lw;
		if (!e) return w;
		s = e + 1;
	}
}

char *uiFit(char *s, float w, float scale)
{
	int n = strlen(s);
	if (widthN(s, n, scale) <= w) return s;
	float dots = widthN("...", 3, scale);
	while (n > 0 && (widthN(s, n, scale) + dots > w || n + 3 > (int)strlen(s))) {
		do n--;
		while (n > 0 && (s[n] & 0xC0) == 0x80); // whole UTF-8 sequences
	}
	strcpy(s + n, "...");
	return s;
}

static float lineH(float scale)
{
	return roundf(scale / S_SMALL * SMALL_H);
}

// Lines of at most w: broken at spaces, inside a word only when it doesn't fit a line alone, and at
// '\n'. Draws them when draw is set; returns how many.
static int wrap(float x, float y, float w, float scale, u32 color, bool draw, const char *text)
{
	int lines = 0;
	for (const char *p = text;;) {
		const char *end = strchr(p, '\n');
		if (!end) end = p + strlen(p);
		do {
			const char *e = p, *q = p;
			while (q < end) { // add the next word (with the spaces before it) while it fits
				const char *nx = q;
				while (nx < end && *nx == ' ') nx++;
				while (nx < end && *nx != ' ') nx++;
				if (widthN(p, nx - p, scale) > w) break;
				e = q = nx;
			}
			if (e == p) { // a word wider than the line: as many characters as fit, at least one
				e = p + 1;
				while (e < end && (*e & 0xC0) == 0x80) e++;
				for (const char *c = e; c < end && *c != ' ';) {
					do c++;
					while (c < end && (*c & 0xC0) == 0x80);
					if (widthN(p, c - p, scale) > w) break;
					e = c;
				}
			}
			if (draw) uiText(x, y + lines * lineH(scale), scale, color, "%.*s", (int)(e - p), p);
			lines++;
			p = e;
			while (p < end && *p == ' ') p++;
		} while (p < end);
		if (!*end) return lines;
		p = end + 1;
	}
}

float uiTextWrap(float x, float y, float w, float scale, u32 color, const char *text)
{
	return y + wrap(x, y, w, scale, color, true, text) * lineH(scale);
}

int uiWrapLines(float w, float scale, const char *text)
{
	return wrap(0, 0, w, scale, 0, false, text);
}

void uiMonoS(float x, float y, float scale, float cell, u32 color, const char *s)
{
	for (; *s; s++, x += cell) {
		int c = (*s >= 32 && *s < 127) ? *s - 32 : '.' - 32;
		if (!c) continue;
		C2D_DrawText(&mono[c], C2D_WithColor, x + (cell - mono[c].width * scale) / 2, y, 0.5f, scale, scale, color);
	}
}

void uiMono(float x, float y, u32 color, const char *s)
{
	uiMonoS(x, y, S_MONO, MONO_W, color, s);
}

// The field meter (field.h): signal-strength bars at the header's right end; returns their width.
#define METER_W (FIELD_BARS * 5 - 2)
static float fieldMeter(float right)
{
	bool live = false;
	int n = fieldBars(&live);
	if (n < 0) return 0;
	float x = right - METER_W;
	for (int i = 0; i < FIELD_BARS; i++) {
		float h = 4 + 2.5f * i;
		u32 c = i < n ? uiCol[live ? COL_OK : COL_DIM] : uiCol[COL_SEL];
		uiRect(x + 5 * i, 16 - h, 3, h, c);
	}
	return METER_W + 8;
}

void uiHeader(const char *title, const char *right)
{
	char t[256];
	snprintf(t, sizeof(t), "%s", title);
	uiRect(0, 0, UI_W, 20, uiCol[COL_BAR]);
	uiRect(0, 19, UI_W, 1, uiCol[COL_ACCENT]);
	float m = fieldMeter(UI_W - 6);
	uiText(6, 2, S_BODY, uiCol[COL_TEXT], "%s",
		uiFit(t, UI_W - 12 - m - (right ? uiTextWidth(S_SMALL, right) + 12 : 0), S_BODY));
	if (right) uiTextRight(UI_W - 6 - m, 3, S_SMALL, uiCol[COL_DIM], "%s", right);
}

void uiFooter(const char *h)
{
	uiRect(0, UI_H - 18, UI_W, 18, uiCol[COL_BAR]);
	uiRect(0, UI_H - 18, UI_W, 1, uiCol[COL_SEL]);
	uiText(6, UI_H - 16, S_SMALL, uiCol[COL_DIM], "%s", h);
	uiHints(h);
}

void uiSel(float x, float y, float w, float h)
{
	uiRect(x, y, w, h, uiCol[COL_SEL]);
	uiRect(x, y, 2, h, uiCol[COL_CURSOR]);
}

void uiHints(const char *h)
{
	snprintf(hints, sizeof(hints), "%s", h);
}

const char *uiHintsNow(void)
{
	return hints;
}

float uiBox(float w, float h, const char *title)
{
	float x = (UI_W - w) / 2, y = (UI_H - h) / 2;
	uiRect(0, 0, UI_W, UI_H, C2D_Color32(0x0A, 0x07, 0x10, 0xA8));
	uiRect(x - 1, y - 1, w + 2, h + 2, uiCol[COL_ACCENT]);
	uiRect(x, y, w, h, uiCol[COL_PANEL]);
	uiRect(x, y, w, 18, uiCol[COL_BAR]);
	uiRect(x, y + 18, w, 1, uiCol[COL_SEL]);
	// targeting brackets on the corners
	u32 c = uiCol[COL_CURSOR];
	float r = x + w, b = y + h, a = 9;
	uiRect(x - 3, y - 3, a, 2, c), uiRect(x - 3, y - 3, 2, a, c);
	uiRect(r + 3 - a, y - 3, a, 2, c), uiRect(r + 1, y - 3, 2, a, c);
	uiRect(x - 3, b + 1, a, 2, c), uiRect(x - 3, b + 3 - a, 2, a, c);
	uiRect(r + 3 - a, b + 1, a, 2, c), uiRect(r + 1, b + 3 - a, 2, a, c);
	char t[128];
	snprintf(t, sizeof(t), "%s", title);
	uiText(x + 6, y + 1, S_BODY, uiCol[COL_TEXT], "%s", uiFit(t, w - 12, S_BODY));
	return y + 22;
}

void uiListNav(UiList *l, int n, int visible, u32 kRepeat)
{
	if (n <= 0) {
		l->sel = l->top = 0;
		return;
	}
	if (kRepeat & KEY_UP) l->sel = l->sel > 0 ? l->sel - 1 : n - 1;
	if (kRepeat & KEY_DOWN) l->sel = l->sel < n - 1 ? l->sel + 1 : 0;
	if (kRepeat & KEY_LEFT) l->sel = l->sel > visible ? l->sel - visible : 0;
	if (kRepeat & KEY_RIGHT) l->sel = l->sel + visible < n ? l->sel + visible : n - 1;
	if (l->sel >= n) l->sel = n - 1;
	if (l->sel < l->top) l->top = l->sel;
	if (l->sel >= l->top + visible) l->top = l->sel - visible + 1;
}

#define LOG_LINES 2000 // the release build has no log file: this is all of it
#define LOG_COLS  96
static char logRing[LOG_LINES][LOG_COLS];
static int logHead, logCount, logCol; // logHead: the line being written
static LightLock logLock;
static bool logInit;

void uiLogAppend(const char *s)
{
	if (!logInit) {
		LightLock_Init(&logLock);
		logInit = true;
		logCount = 1;
	}
	LightLock_Lock(&logLock);
	for (; *s; s++) {
		if (*s == '\n' || logCol == LOG_COLS - 1) {
			logHead = (logHead + 1) % LOG_LINES;
			logRing[logHead][0] = 0;
			logCol = 0;
			if (logCount < LOG_LINES) logCount++;
			if (*s == '\n') continue;
		}
		logRing[logHead][logCol++] = *s;
		logRing[logHead][logCol] = 0;
	}
	LightLock_Unlock(&logLock);
}

// The line being written counts only once it has text.
int uiLogCount(void)
{
	return logCount - (logInit && !logCol);
}

void uiLogLine(int i, char *out, u32 max)
{
	if (!logInit) {
		*out = 0;
		return;
	}
	LightLock_Lock(&logLock);
	snprintf(out, max, "%s", logRing[(logHead - logCount + 1 + i + LOG_LINES) % LOG_LINES]);
	LightLock_Unlock(&logLock);
}
