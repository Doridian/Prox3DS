// Hex / decimal entry screen with a bottom-screen keypad, see entry.h.

#include <stdio.h>
#include <string.h>
#include <3ds.h>

#include "app.h"
#include "entry.h"
#include "ui.h"

static struct {
	char title[64], what[160];
	int radix, n, cur, top; // digits (hex: 2 per byte), the cursor, the first grid row shown
	u8 dig[2 * ENTRY_MAX];
	s64 min, max;
	bool fresh; // decimal: the keypad's first digit replaces the initial value
	void (*doneHex)(const u8 *b, u32 len);
	void (*doneDec)(s64 v);
} e;

static s64 value(void)
{
	s64 v = 0;
	for (int i = 0; i < e.n; i++) v = v * 10 + e.dig[i];
	return v;
}

static void finish(void)
{
	if (e.radix == 10) {
		s64 v = value();
		if (v < e.min || v > e.max) {
			toast("Out of range: %lld..%lld", e.min, e.max);
			return;
		}
		appBack();
		e.doneDec(v);
		return;
	}
	static u8 b[ENTRY_MAX];
	for (int i = 0; i < e.n / 2; i++) b[i] = e.dig[2 * i] << 4 | e.dig[2 * i + 1];
	appBack();
	e.doneHex(b, e.n / 2);
}

// Hex: the digit at the cursor, which moves on. Decimal: calculator style, shifted in from the right.
static void type(int d)
{
	if (e.radix == 16) {
		e.dig[e.cur] = d;
		if (e.cur < e.n - 1) e.cur++;
		return;
	}
	if (e.fresh) memset(e.dig, 0, e.n), e.fresh = false;
	if (e.dig[0]) return; // full
	memmove(e.dig, e.dig + 1, e.n - 1);
	e.dig[e.n - 1] = d;
	e.cur = e.n - 1;
}

static void del(void)
{
	memmove(e.dig + 1, e.dig, e.n - 1);
	e.dig[0] = 0;
	e.fresh = false;
}

// --- top screen ---

#define GRID_ROWS 8
#define HEX_X     26
#define BYTE_W    16.5f
#define ASCII_X   300

static float byteX(int i)
{
	return HEX_X + i * BYTE_W + (i >= 8 ? 3 : 0);
}

static void draw(void)
{
	char right[48];
	if (e.radix == 16) snprintf(right, sizeof(right), "%d byte%s", e.n / 2, e.n == 2 ? "" : "s");
	else snprintf(right, sizeof(right), "%lld..%lld", e.min, e.max);
	uiHeader(e.title, right);
	float y = uiTextWrap(12, 26, UI_W - 24, S_SMALL, uiCol[COL_TEXT], e.what) + 8;
	if (e.radix == 10) {
		// big digits, leading zeros dim
		float cell = 15, x = (UI_W - e.n * cell) / 2;
		int lead = 0;
		while (lead < e.n - 1 && !e.dig[lead]) lead++;
		for (int i = 0; i < e.n; i++) {
			char c[2] = { '0' + e.dig[i], 0 };
			if (i == e.cur) uiRect(x + i * cell, y - 2, cell, 26, uiCol[COL_CURSOR]);
			uiMonoS(x + i * cell, y, 0.8f, cell, uiCol[i == e.cur ? COL_BG : i < lead ? COL_DIM : COL_TEXT], c);
		}
		uiTextCenter(UI_W / 2, y + 34, S_SMALL, uiCol[COL_DIM], "= %lld", value());
	} else {
		int bytes = e.n / 2, rows = (bytes + 15) / 16, cb = e.cur / 2;
		if (cb / 16 < e.top) e.top = cb / 16;
		if (cb / 16 >= e.top + GRID_ROWS) e.top = cb / 16 - GRID_ROWS + 1;
		for (int i = 0; i < 16 && i < bytes; i++) {
			char c[2] = { "0123456789ABCDEF"[i], 0 };
			uiMono(byteX(i) + MONO_W / 2, y, uiCol[i == cb % 16 ? COL_ACCENT : COL_DIM], c);
		}
		y += 11;
		for (int r = e.top; r < rows && r < e.top + GRID_ROWS; r++, y += 13) {
			char s[17];
			if (rows > 1) {
				snprintf(s, sizeof(s), "%03X", r * 16);
				uiMonoS(0, y, S_MONO, 7, uiCol[r == cb / 16 ? COL_ACCENT : COL_DIM], s);
			}
			int n = bytes - r * 16 < 16 ? bytes - r * 16 : 16;
			for (int i = 0; i < n; i++) {
				int b = r * 16 + i;
				float x = byteX(i);
				if (b == cb) {
					uiRect(x - 1, y - 1, 2 * MONO_W + 2, 12, uiCol[COL_SEL]);
					uiRect(x - 1 + (e.cur & 1) * MONO_W, y - 1, MONO_W + 2, 12, uiCol[COL_CURSOR]);
				}
				for (int k = 0; k < 2; k++) {
					char c[2] = { "0123456789ABCDEF"[e.dig[2 * b + k]], 0 };
					uiMono(x + k * MONO_W, y, uiCol[b == cb && (e.cur & 1) == k ? COL_BG : COL_TEXT], c);
				}
				u8 v = e.dig[2 * b] << 4 | e.dig[2 * b + 1];
				s[i] = v >= 32 && v < 127 ? v : '.';
			}
			s[n] = 0;
			uiMonoS(ASCII_X, y + 1, 0.34f, 5.8f, uiCol[COL_DIM], s);
		}
		if (rows > GRID_ROWS) uiTextRight(UI_W - 12, y + 2, S_SMALL, uiCol[COL_DIM], "byte %d of %d", cb + 1, bytes);
	}
	uiFooter(BTN_LR " digit   " BTN_UD " value   " BTN_X " clear   " BTN_A " done   " BTN_B " cancel");
}

static void input(u32 kDown, u32 kRepeat)
{
	if (kRepeat & KEY_LEFT) e.cur = (e.cur + e.n - 1) % e.n;
	if (kRepeat & KEY_RIGHT) e.cur = (e.cur + 1) % e.n;
	if (kRepeat & KEY_UP) e.dig[e.cur] = (e.dig[e.cur] + 1) % e.radix;
	if (kRepeat & KEY_DOWN) e.dig[e.cur] = (e.dig[e.cur] + e.radix - 1) % e.radix;
	// L / R: a whole byte (hex) at a time
	if ((kRepeat & KEY_L) && e.radix == 16) e.cur = e.cur >= 2 ? e.cur - 2 : e.cur;
	if ((kRepeat & KEY_R) && e.radix == 16) e.cur = e.cur + 2 < e.n ? e.cur + 2 : e.cur;
	if (kDown & KEY_X) memset(e.dig, 0, e.n), e.cur = e.radix == 10 ? e.n - 1 : 0;
	if (kDown & KEY_A) finish();
	else if (kDown & KEY_B) appBack();
}

// --- bottom screen: keypad ---

static void bottom(void)
{
	u32 key = uiCol[COL_BAR], side = uiCol[COL_PANEL];
	float w = 58, h = 44, g = 3, x0 = 4, y0 = 6;
	int cols = e.radix == 16 ? 4 : 3, n = e.radix;
	for (int i = 0; i < n; i++) {
		// decimal: 1-9 in rows, 0 under the 8
		int pos = e.radix == 16 ? i : i == 0 ? 10 : i - 1, r = pos / cols, c = pos % cols;
		char l[2] = { "0123456789ABCDEF"[i], 0 };
		if (uiButtonRep(x0 + c * (w + g), y0 + r * (h + g), w, h, key, l)) type(i);
	}
	float sx = x0 + 4 * (w + g) + 6, sw = UI_BW - sx - 4;
	if (e.radix == 10) {
		if (uiButtonRep(sx, y0, sw, h, side, "Del")) del();
	} else {
		if (uiButtonRep(sx, y0, sw / 2 - 2, h, side, "\uE07B")) appPress(KEY_LEFT);
		if (uiButtonRep(sx + sw / 2 + 2, y0, sw / 2 - 2, h, side, "\uE07C")) appPress(KEY_RIGHT);
	}
	if (uiButton(sx, y0 + (h + g), sw, h, side, "Clear")) appPress(KEY_X);
	if (uiButton(sx, y0 + 2 * (h + g), sw, h, side, "Cancel")) appPress(KEY_B);
	if (uiButton(sx, y0 + 3 * (h + g), sw, h, uiCol[COL_SEL], "Done")) appPress(KEY_A);
	uiTextCenter(UI_BW / 2, UI_H - 18, S_SMALL, uiCol[COL_DIM], "%s",
		e.radix == 16 ? "Keys type at the cursor and move on" : "Digits come in from the right");
}

static const Screen entryScreen = { NULL, input, draw, bottom };

static void begin(const char *title, const char *what)
{
	snprintf(e.title, sizeof(e.title), "%s", title);
	snprintf(e.what, sizeof(e.what), "%s", what);
	e.cur = e.top = 0;
	e.fresh = true;
	appScreen(&entryScreen);
}

void entryHex(const char *title, const char *what, u32 len, const u8 *init, void (*done)(const u8 *b, u32 len))
{
	if (len > ENTRY_MAX) len = ENTRY_MAX;
	e.radix = 16, e.n = 2 * len, e.doneHex = done;
	for (u32 i = 0; i < len; i++) {
		u8 v = init ? init[i] : 0;
		e.dig[2 * i] = v >> 4, e.dig[2 * i + 1] = v & 0xF;
	}
	begin(title, what);
}

void entryDec(const char *title, const char *what, s64 min, s64 max, s64 init, void (*done)(s64 v))
{
	e.radix = 10, e.min = min, e.max = max, e.doneDec = done;
	e.n = 1;
	for (s64 m = max; m >= 10; m /= 10) e.n++;
	if (init < 0) init = 0;
	for (int i = e.n - 1; i >= 0; i--, init /= 10) e.dig[i] = init % 10;
	begin(title, what);
	e.cur = e.n - 1;
}
