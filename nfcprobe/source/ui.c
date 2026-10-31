// Top-screen drawing helpers and the log ring, see ui.h.

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <3ds.h>

#include "ui.h"

u32 uiCol[COL_N];

static C3D_RenderTarget *top;
static C2D_TextBuf frameBuf, monoBuf;
static C2D_Text mono[95]; // ' ' .. '~'

void uiInit(void)
{
	C3D_Init(C3D_DEFAULT_CMDBUF_SIZE);
	C2D_Init(C2D_DEFAULT_MAX_OBJECTS);
	C2D_Prepare();
	top = C2D_CreateScreenTarget(GFX_TOP, GFX_LEFT);
	frameBuf = C2D_TextBufNew(8192);
	monoBuf = C2D_TextBufNew(256);
	for (int c = 0; c < 95; c++) {
		char s[2] = { 32 + c, 0 };
		C2D_TextParse(&mono[c], monoBuf, s);
		C2D_TextOptimize(&mono[c]);
	}
	static const u32 rgb[COL_N] = {
		[COL_BG] = 0x15181E, [COL_PANEL] = 0x1F242C, [COL_BAR] = 0x2A313C, [COL_TEXT] = 0xE6E9EE,
		[COL_DIM] = 0x7D8796, [COL_ACCENT] = 0x4FB3FF, [COL_SEL] = 0x2F4D6E, [COL_CURSOR] = 0xE0A030,
		[COL_WARN] = 0xF2C14E, [COL_ERR] = 0xFF6B6B, [COL_OK] = 0x6BD68A, [COL_KEYA] = 0x7EE08E,
		[COL_KEYB] = 0x6FB7FF, [COL_ACL] = 0xF5A25D, [COL_CHANGED] = 0xFFE066,
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
	C2D_SceneBegin(top);
	C2D_TextBufClear(frameBuf);
}

void uiFrameEnd(void)
{
	C3D_FrameEnd(0);
}

void uiRect(float x, float y, float w, float h, u32 color)
{
	C2D_DrawRectSolid(x, y, 0.5f, w, h, color);
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

float uiTextWrap(float x, float y, float w, float scale, u32 color, const char *text)
{
	char line[256] = "", cand[256];
	float lh = scale / S_SMALL * SMALL_H;
	for (const char *p = text; *p;) {
		const char *e = strchr(p, ' ');
		int n = e ? e - p : (int)strlen(p);
		snprintf(cand, sizeof(cand), "%s%s%.*s", line, *line ? " " : "", n, p);
		C2D_Text t;
		C2D_TextParse(&t, frameBuf, cand);
		if (*line && t.width * scale > w) {
			uiText(x, y, scale, color, "%s", line);
			y += lh;
			snprintf(line, sizeof(line), "%.*s", n, p);
		} else {
			snprintf(line, sizeof(line), "%s", cand);
		}
		p += n;
		while (*p == ' ') p++;
	}
	if (*line) uiText(x, y, scale, color, "%s", line), y += lh;
	return y;
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

void uiHeader(const char *title, const char *right)
{
	uiRect(0, 0, UI_W, 20, uiCol[COL_BAR]);
	uiText(6, 2, S_BODY, uiCol[COL_TEXT], "%s", title);
	if (right) uiTextRight(UI_W - 6, 3, S_SMALL, uiCol[COL_DIM], "%s", right);
}

void uiFooter(const char *hints)
{
	uiRect(0, UI_H - 18, UI_W, 18, uiCol[COL_BAR]);
	uiText(6, UI_H - 16, S_SMALL, uiCol[COL_DIM], "%s", hints);
}

float uiBox(float w, float h, const char *title)
{
	float x = (UI_W - w) / 2, y = (UI_H - h) / 2;
	uiRect(0, 0, UI_W, UI_H, C2D_Color32(0, 0, 0, 0x90));
	uiRect(x - 1, y - 1, w + 2, h + 2, uiCol[COL_ACCENT]);
	uiRect(x, y, w, h, uiCol[COL_PANEL]);
	uiRect(x, y, w, 18, uiCol[COL_BAR]);
	uiText(x + 6, y + 1, S_BODY, uiCol[COL_TEXT], "%s", title);
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

#define LOG_LINES 400
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
