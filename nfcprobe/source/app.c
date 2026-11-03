// App shell: screen stack, dialogs, the card job worker, the root menu with the generic scan, the log,
// and the bottom screen. Everything works on the top screen with the buttons (a card on the reader
// covers the whole bottom screen); the bottom screen doubles them for touch. Card families bring
// their own screens (MIFARE Classic: mfui.c, editor.c).

#include <dirent.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <3ds.h>

#include "app.h"
#include "dumplist.h"
#include "probe.h"
#include "ui.h"

#define MS(x) ((s64)(x) * 1000000LL)

static const Screen *stack[16];
static int depth;
static u32 frame;

static void showTop(void)
{
	if (stack[depth - 1]->show) stack[depth - 1]->show();
}

void appScreen(const Screen *s)
{
	if (depth && stack[depth - 1] == s) return;
	if (depth == 16) memmove(stack + 1, stack + 2, 14 * sizeof(*stack)); // keep the root
	else depth++;
	stack[depth - 1] = s;
	showTop();
}

const Screen *appTop(void)
{
	return stack[depth - 1];
}

void appBack(void)
{
	if (depth > 1) depth--;
	showTop();
}

static char toastMsg[128];
static u32 toastUntil;

void toast(const char *fmt, ...)
{
	va_list va;
	va_start(va, fmt);
	vsnprintf(toastMsg, sizeof(toastMsg), fmt, va);
	va_end(va);
	toastUntil = frame + 180;
}

// Like pm3's hf 14a info: the SAK says Classic (bit 3) or ISO14443-4 (bit 5); the ATQA tells the rest apart.
const char *cardTypeName(const Card *c)
{
	u16 atqa = c->atqa[1] << 8 | c->atqa[0];
	switch (c->sak) {
	case 0x08: return "MIFARE Classic 1K";
	case 0x09: return "MIFARE Classic Mini";
	case 0x18: return "MIFARE Classic 4K";
	case 0x19: return "MIFARE Classic 2K";
	case 0x88: return "MIFARE Classic 1K (Infineon)";
	case 0x28: return "Classic 1K emulation (SmartMX)";
	case 0x38: return "Classic 4K emulation (SmartMX)";
	case 0x10: return "MIFARE Plus 2K (SL2)";
	case 0x11: return "MIFARE Plus 4K (SL2)";
	case 0x00: return (atqa & 0xFF0F) == 0x0004 ? "MIFARE Ultralight / NTAG" : "Ultralight / NTAG family";
	case 0x20:
		if (atqa == 0x0344) return "MIFARE DESFire";
		if (atqa == 0x0004 || atqa == 0x0044 || atqa == 0x0002 || atqa == 0x0042) return "MIFARE Plus (SL3) / ISO14443-4";
		return "ISO14443-4 smart card";
	}
	return c->sak & 0x20 ? "ISO14443-4 card" : "unknown ISO14443-A card";
}

void uidHex(const Card *c, char *out, const char *sep)
{
	*out = 0;
	for (int i = 0; i < c->uidLen; i++) sprintf(out + strlen(out), "%s%02X", i ? sep : "", c->uid[i]);
}

// --- dialogs ---

enum { DLG_NONE, DLG_MSG, DLG_CONFIRM, DLG_POPUP };
static struct {
	int kind;
	char title[48], msg[512];
	void (*yes)(void);
	MenuItem items[24];
	int n;
	UiList l;
} dlg;

#define POP_ROWS 12 // a longer popup scrolls

void msgBox(const char *title, const char *fmt, ...)
{
	va_list va;
	va_start(va, fmt);
	vsnprintf(dlg.msg, sizeof(dlg.msg), fmt, va);
	va_end(va);
	snprintf(dlg.title, sizeof(dlg.title), "%s", title);
	dlg.kind = DLG_MSG;
}

void confirm(const char *title, void (*yes)(void), const char *fmt, ...)
{
	va_list va;
	va_start(va, fmt);
	vsnprintf(dlg.msg, sizeof(dlg.msg), fmt, va);
	va_end(va);
	snprintf(dlg.title, sizeof(dlg.title), "%s", title);
	dlg.yes = yes;
	dlg.kind = DLG_CONFIRM;
}

void popup(const char *title, const MenuItem *items, int n)
{
	snprintf(dlg.title, sizeof(dlg.title), "%s", title);
	dlg.n = n < 24 ? n : 24;
	memcpy(dlg.items, items, dlg.n * sizeof(*items));
	dlg.l = (UiList){ 0 };
	dlg.kind = DLG_POPUP;
}

static void dialogInput(u32 kDown, u32 kRepeat)
{
	int kind = dlg.kind;
	if (kind == DLG_POPUP) {
		uiListNav(&dlg.l, dlg.n, POP_ROWS, kRepeat & (KEY_UP | KEY_DOWN));
		if (kDown & KEY_B) dlg.kind = DLG_NONE;
		if (kDown & KEY_A) {
			dlg.kind = DLG_NONE; // the item may open the next dialog
			dlg.items[dlg.l.sel].fn();
		}
		return;
	}
	if (kDown & (KEY_A | KEY_B)) {
		dlg.kind = DLG_NONE;
		if (kind == DLG_CONFIRM && (kDown & KEY_A)) dlg.yes();
	}
}

#define DLG_W 360

static void dialogDraw(void)
{
	if (dlg.kind == DLG_POPUP) {
		int rows = dlg.n < POP_ROWS ? dlg.n : POP_ROWS;
		float h = 22 + rows * LINE_H + 22, y = uiBox(240, h, dlg.title), x = (UI_W - 240) / 2;
		for (int i = dlg.l.top; i < dlg.l.top + rows; i++, y += LINE_H) {
			if (i == dlg.l.sel) uiSel(x + 2, y - 1, 236, LINE_H);
			uiText(x + 10, y, S_BODY, uiCol[COL_TEXT], "%s", dlg.items[i].label);
		}
		uiText(x + 10, y + 4, S_SMALL, uiCol[COL_DIM], BTN_A " select   " BTN_B " close");
		if (dlg.n > rows) uiTextRight(x + 230, y + 4, S_SMALL, uiCol[COL_DIM], "%d-%d of %d", dlg.l.top + 1,
			dlg.l.top + rows, dlg.n);
		uiHints(BTN_UD " item   " BTN_A " select   " BTN_B " close");
		return;
	}
	int lines = uiWrapLines(DLG_W - 20, S_SMALL, dlg.msg);
	float h = 22 + lines * SMALL_H + 26, y = uiBox(DLG_W, h, dlg.title), x = (UI_W - DLG_W) / 2;
	uiTextWrap(x + 10, y, DLG_W - 20, S_SMALL, uiCol[COL_TEXT], dlg.msg);
	const char *hint = dlg.kind == DLG_CONFIRM ? BTN_A " yes   " BTN_B " no" : BTN_A " ok";
	uiText(x + 10, y + lines * SMALL_H + 6, S_SMALL, uiCol[COL_DIM], "%s", hint);
	uiHints(hint);
}

// --- job worker ---

static Thread worker;
static volatile bool jobBusy, jobFinished;
static const char *jobTitle;
static const char *jobHint, *nextHint;
static void (*jobRun)(void), (*jobDone)(void);
static bool jobCancellable;
static float (*jobView)(float x, float y, float w);
static u32 jobs;

u32 jobCount(void)
{
	return jobs;
}

static void jobThread(void *arg)
{
	LightLock_Lock(&hwLock);
	jobRun();
	LightLock_Unlock(&hwLock);
	jobFinished = true;
}

void jobNextHint(const char *hint)
{
	nextHint = hint;
}

void jobStart(const char *title, void (*run)(void), void (*done)(void), bool cancellable)
{
	jobStartView(title, run, done, cancellable, NULL);
}

void jobStartView(const char *title, void (*run)(void), void (*done)(void), bool cancellable,
	float (*view)(float x, float y, float w))
{
	if (jobBusy) return;
	jobView = view;
	jobHint = nextHint ? nextHint : "Keep the card on the bottom screen.";
	nextHint = NULL;
	progJob();
	jobTitle = title;
	jobRun = run;
	jobDone = done;
	jobCancellable = cancellable;
	mfCancel = false;
	jobFinished = false;
	jobBusy = true;
	jobs++;
	logp("--- %s ---\n", title);
	worker = threadCreate(jobThread, NULL, 0x8000, 0x30, -2, false);
	if (!worker) {
		jobBusy = false;
		msgBox("Error", "Could not start the worker thread.");
	}
}

static void jobReap(void)
{
	if (!jobFinished) return;
	threadJoin(worker, U64_MAX);
	threadFree(worker);
	worker = NULL;
	jobFinished = jobBusy = false;
	if (jobDone) jobDone();
}

#define S_LOG 0.38f // 12 px lines

void fmtDuration(char *out, u32 ms)
{
	u32 s = (ms + 500) / 1000;
	sprintf(out, "%lu:%02lu", s / 60, s % 60);
}

// The job's op and its bar (when it has steps), elapsed time and ETA; returns the y below.
static float progressDraw(float x, float y, float w)
{
	char el[16], left[16];
	fmtDuration(el, osGetTime() - prog.start);
	uiTextRight(x + w, y, S_SMALL, uiCol[COL_DIM], "%s", el);
	if (!*prog.op) return y + SMALL_H + 2;
	uiText(x, y, S_SMALL, uiCol[COL_TEXT], "%s", prog.op);
	y += SMALL_H + 2;
	u32 done = prog.done, total = prog.total;
	if (!total) return y + 14; // its bar's row kept: the view below doesn't jump between ops
	float frac = done >= total ? 1 : (float)done / total;
	uiBar(x, y, w - 100, 9, frac, uiCol[COL_ACCENT]);
	u32 ms = progLeft();
	if (ms) fmtDuration(left, ms);
	if (ms) uiTextRight(x + w, y - 2, S_SMALL, uiCol[COL_TEXT], "%d%%   ETA %s", (int)(frac * 100), left);
	else uiTextRight(x + w, y - 2, S_SMALL, uiCol[COL_TEXT], "%d%%", (int)(frac * 100));
	return y + 14;
}

static void busyDraw(void)
{
	float w = jobView ? 392 : 372, h = jobView ? 226 : 176;
	float y = uiBox(w, h, jobTitle), x = (UI_W - w) / 2, bottom = y - 22 + h;
	static const char spin[] = "|/-\\";
	uiTextRight(x + w - 6, y - 21, S_BODY, uiCol[COL_ACCENT], "%c", spin[(frame / 8) % 4]);
	y = progressDraw(x + 10, y, w - 20);
	if (jobView) y += jobView(x + 10, y, w - 20) + 4;
	// The log's tail fills what is left above the hints line, wrapped, the last line at the bottom.
	int lines = (int)((bottom - 20 - y) / 12);
	if (lines > 9) lines = 9;
	if (lines > 0) uiRect(x + 6, y - 2, w - 12, lines * 12 + 4, uiCol[COL_BG]);
	int n = uiLogCount(), rows = 0;
	char line[100];
	for (int idx = n - 1; idx >= 0 && rows < lines; idx--) {
		uiLogLine(idx, line, sizeof(line));
		int k = uiWrapLines(w - 20, S_LOG, line);
		if (rows + k > lines) break; // not half a line at the top
		rows += k;
		uiTextWrap(x + 10, y + 12 * (lines - rows), w - 20, S_LOG, uiCol[idx == n - 1 ? COL_TEXT : COL_DIM], line);
	}
	float hy = bottom - 16;
	if (jobCancellable) {
		uiText(x + 10, hy, S_SMALL, uiCol[mfCancel ? COL_WARN : COL_DIM], mfCancel ? "Stopping..." : BTN_B " stop");
		uiTextRight(x + w - 10, hy, S_SMALL, uiCol[COL_DIM], "%s", jobHint);
	}
}

bool cardWait(void)
{
	if (!chipEnsure()) {
		logp("NFC takeover failed\n");
		return false;
	}
	logp("waiting for a card...\n");
	while (!mfCancel) {
		if (!iso14aStart()) continue;
		char uid[32];
		uidHex(&card, uid, "");
		logp("card: UID %s ATQA %02X%02X SAK %02X\n", uid, card.atqa[1], card.atqa[0], card.sak);
		return true;
	}
	return false;
}

// --- log ---

static int logTop = -1; // -1 = follow the end
#define LOG_ROWS 16

// The first line of the last screenful: log lines wrap, so some take two rows.
static int logMax(void)
{
	int n = uiLogCount(), rows = 0, top = n;
	char line[100];
	while (top > 0) {
		uiLogLine(top - 1, line, sizeof(line));
		int k = uiWrapLines(UI_W - 12, S_LOG, line);
		if (rows + k > LOG_ROWS) break;
		rows += k;
		top--;
	}
	return top;
}

static void logInput(u32 kDown, u32 kRepeat)
{
	int vis = LOG_ROWS, max = logMax();
	int top = logTop < 0 ? max : logTop;
	if (kRepeat & KEY_UP) top--;
	if (kRepeat & KEY_DOWN) top++;
	if (kRepeat & KEY_LEFT) top -= vis;
	if (kRepeat & KEY_RIGHT) top += vis;
	if (kRepeat & (KEY_L)) top = 0;
	if (kRepeat & (KEY_R)) top = max;
	top = top < 0 ? 0 : top > max ? max : top;
	logTop = top == max ? -1 : top;
	if (kDown & (KEY_B | KEY_SELECT)) appBack();
}

static void logDraw(void)
{
	int n = uiLogCount(), max = logMax();
	int top = logTop < 0 || logTop > max ? max : logTop;
	char hdr[48], line[100];
	snprintf(hdr, sizeof(hdr), "%s%d lines", logTop < 0 ? "following, " : "", n);
	uiHeader("Log", hdr);
	for (int i = top, rows = 0; i < n; i++) {
		uiLogLine(i, line, sizeof(line));
		int k = uiWrapLines(UI_W - 12, S_LOG, line);
		if (rows + k > LOG_ROWS) break;
		uiTextWrap(6, 23 + rows * 12, UI_W - 12, S_LOG, uiCol[COL_TEXT], line);
		rows += k;
	}
	uiFooter(BTN_UD " scroll   " BTN_LR " page   " BTN_L "/" BTN_R " start/end   " BTN_B " back   (also sdmc:/nfcprobe.log)");
}

static const Screen logScreen = { NULL, logInput, logDraw };

static void openLog(void)
{
	logTop = -1;
	appScreen(&logScreen);
}

// --- menus ---

void menuInput(Menu *m, u32 kDown, u32 kRepeat)
{
	uiListNav(&m->l, m->n, m->n, kRepeat & (KEY_UP | KEY_DOWN));
	if (kDown & KEY_A) m->entries[m->l.sel].fn();
	if ((kDown & KEY_B) && depth > 1) appBack();
}

void menuDraw(Menu *m)
{
	uiHeader(m->title, *netAddr ? netAddr : "no network");
	// 20 px rows; a longer list closes up to end above the footer, and the status lines go beside it
	float pitch = m->n > 1 && 30 + (m->n - 1) * 20 > 196 ? (float)(166 / (m->n - 1)) : 20;
	for (int i = 0; i < m->n; i++) {
		float y = 30 + i * pitch;
		if (i == m->l.sel) {
			uiSel(8, y - 3, 180, 19);
		}
		uiText(20, y, S_BODY, uiCol[i == m->l.sel ? COL_TEXT : COL_DIM], "%s", m->entries[i].label);
	}
	float h = 140;
	bool beside = 30 + m->n * pitch > 176;
	if (beside) { // the panel as tall as the longest help, the status lines under it
		int lines = 0;
		for (int i = 0; i < m->n; i++) {
			int k = uiWrapLines(UI_W - 224, S_SMALL, m->entries[i].help);
			if (k > lines) lines = k;
		}
		h = 12 + lines * SMALL_H;
	}
	uiRect(200, 27, UI_W - 208, h, uiCol[COL_PANEL]);
	uiTextWrap(208, 32, UI_W - 224, S_SMALL, uiCol[COL_TEXT], m->entries[m->l.sel].help);
	if (m->extra) {
		if (beside) m->extra(204, 27 + h + 6, UI_W - 212);
		else m->extra(12, 178, UI_W - 24);
	}
	uiFooter(depth > 1 ? BTN_A " select   " BTN_B " back   SELECT log   START exit"
	                   : BTN_A " select   SELECT log   START exit");
}

void menuLastCard(float x, float y, float w, const Card *c, const char *type)
{
	char uid[32], s[96];
	uidHex(c, uid, "");
	snprintf(s, sizeof(s), "Last card: %s, %s", uid, type);
	uiText(x, y, S_SMALL, uiCol[COL_DIM], "%s", uiFit(s, w, S_SMALL));
}

// --- a form: fields, A edits one, the last row runs it ---

static struct {
	const char *title, *go, *help;
	const Field *f;
	int (*count)(void); // fields shown (they may depend on each other)
	void (*run)(void);
	UiList l;
} form;

#define FORM_ROWS 11

static void formDraw(void)
{
	int n = form.count();
	uiHeader(form.title, NULL);
	float y = 26;
	for (int i = 0; i <= n; i++, y += LINE_H) {
		if (i == form.l.sel) uiSel(8, y - 1, UI_W - 16, LINE_H);
		if (i == n) {
			uiText(14, y, S_BODY, uiCol[COL_ACCENT], "%s", form.go);
			break;
		}
		char v[64];
		form.f[i].value(v);
		uiText(14, y, S_BODY, uiCol[COL_DIM], "%s", form.f[i].label);
		uiTextRight(UI_W - 14, y, S_BODY, uiCol[COL_TEXT], "%s", v);
	}
	if (form.help) uiTextWrap(12, y + LINE_H + 4, UI_W - 24, S_SMALL, uiCol[COL_DIM], form.help);
	uiFooter(BTN_UD " field   " BTN_A " change / go   " BTN_B " cancel");
}

static void formInput(u32 kDown, u32 kRepeat)
{
	int n = form.count();
	uiListNav(&form.l, n + 1, FORM_ROWS + 1, kRepeat & (KEY_UP | KEY_DOWN));
	if (kDown & KEY_A) {
		if (form.l.sel == n) {
			appBack();
			form.run();
		} else {
			form.f[form.l.sel].edit();
		}
	} else if (kDown & KEY_B) {
		appBack();
	}
}

// The fields as touch buttons (two columns for a long form): a tap edits that one.
static void formBottom(void)
{
	int n = form.count();
	if (n + 1 <= 7) {
		for (int i = 0; i <= n; i++) {
			char v[64], l[96];
			if (i < n) form.f[i].value(v), snprintf(l, sizeof(l), "%s: %s", form.f[i].label, v);
			else snprintf(l, sizeof(l), "%s", form.go);
			if (uiButton(4, 4 + i * 30, UI_BW - 8, 28, i == n ? uiCol[COL_SEL] : uiCol[COL_BAR], l)) {
				form.l.sel = i;
				appPress(KEY_A);
			}
		}
		if (uiButton(4, UI_H - 30, UI_BW - 8, 26, uiCol[COL_PANEL], "Cancel")) appPress(KEY_B);
		return;
	}
	// fields, then Create and Cancel, down the columns
	int rows = (n + 3) / 2;
	float w = (UI_BW - 12) / 2, h = 31;
	for (int i = 0; i < n + 2; i++) {
		float x = 4 + (i / rows) * (w + 4), y = 4 + (i % rows) * (h + 2);
		bool hit;
		if (i < n) {
			char v[64];
			form.f[i].value(v);
			hit = uiButton2(x, y, w, h, uiCol[COL_BAR], form.f[i].label, v);
		} else {
			hit = uiButton(x, y, w, h, i == n ? uiCol[COL_SEL] : uiCol[COL_PANEL], i == n ? form.go : "Cancel");
		}
		if (!hit) continue;
		if (i == n + 1) {
			appPress(KEY_B);
		} else {
			form.l.sel = i;
			appPress(KEY_A);
		}
	}
}

static const Screen formScreen = { NULL, formInput, formDraw, formBottom };

void formOpen(const char *title, const char *go, const char *help, const Field *f, int (*count)(void), void (*run)(void))
{
	form.title = title, form.go = go, form.help = help, form.f = f, form.count = count, form.run = run;
	form.l = (UiList){ 0 };
	appScreen(&formScreen);
}

// --- generic scan ("hf search"): identify, then hand the card to its family ---

static const CardFamily *families[] = { &mfcFamily, &mfuFamily, &dfFamily, &scFamily };
#define NFAMILIES (int)(sizeof(families) / sizeof(families[0]))

static Card tag; // the last card the generic scan found
static const CardFamily *tagFamily;
static int tagResult; // 1 = card, 0 = none / cancelled / lost, -1 = chip error

static void runIdentify(void)
{
	tagResult = 0;
	tagFamily = NULL;
	if (!cardWait()) return;
	tag = card;
	tagResult = 1;
	for (int i = 0; i < NFAMILIES; i++) {
		if (!families[i]->match(&tag)) continue;
		tagFamily = families[i];
		logp("identified: %s -> %s\n", cardTypeName(&tag), tagFamily->name);
		tagResult = tagFamily->probe ? tagFamily->probe() : 1;
		if (tagResult != FAMILY_PASS) break;
		tagFamily = NULL;
		tagResult = 1;
	}
	if (!tagFamily) logp("identified: %s (not supported)\n", cardTypeName(&tag));
	iso14aParity(true);
}

static const Screen tagScreen;

static void doneIdentify(void)
{
	if (tagResult < 0) msgBox("Scan", "The chip stopped answering.\nTry again.");
	else if (!tagResult && tag.uidLen && !mfCancel) msgBox("Scan", "Lost the card. Try again.");
	if (tagResult <= 0) return;
	if (tagFamily) tagFamily->show();
	else appScreen(&tagScreen);
}

static void startIdentify(void)
{
	tag.uidLen = 0;
	jobStart("Scanning", runIdentify, doneIdentify, true);
}

static void tagInput(u32 kDown, u32 kRepeat)
{
	if (kDown & KEY_A) {
		appBack(); // the scan's result screen replaces this one
		startIdentify();
	}
	if (kDown & KEY_B) appBack();
}

static void tagDraw(void)
{
	char hdr[48], uid[32];
	snprintf(hdr, sizeof(hdr), "ATQA %02X%02X  SAK %02X", tag.atqa[1], tag.atqa[0], tag.sak);
	uiHeader("Card", hdr);
	uidHex(&tag, uid, " ");
	uiText(12, 28, S_SMALL, uiCol[COL_DIM], "ISO14443-A, UID (%d bytes)", tag.uidLen);
	uiText(12, 40, 0.8f, uiCol[COL_ACCENT], "%s", uid);
	uiText(12, 68, S_BODY, uiCol[COL_TEXT], "%s", cardTypeName(&tag));
	uiRect(8, 92, UI_W - 16, 3 * SMALL_H + 8, uiCol[COL_PANEL]);
	uiText(14, 96, S_SMALL, uiCol[COL_WARN], "Not supported yet.");
	char fams[128] = "";
	for (int i = 0; i < NFAMILIES; i++) sprintf(fams + strlen(fams), "%s%s", i ? ", " : "", families[i]->name);
	uiText(14, 96 + SMALL_H, S_SMALL, uiCol[COL_TEXT], "Supported: %s", fams);
	uiFooter(BTN_A " scan again   " BTN_B " back");
}

static const Screen tagScreen = { NULL, tagInput, tagDraw };

// --- root menu ---

static bool quit;

static void doneProbe(void)
{
	openLog();
}

static void menuProbe(void)
{
	jobStart("Chip info", chipProbe, doneProbe, false);
}

static void menuExit(void)
{
	quit = true;
}

static MenuEntry rootEntries[7 + NFAMILIES + 1];
static void rootExtra(float x, float y, float w);
static Menu rootMenu = { "nfcprobe", rootEntries, 0, rootExtra };

static void rootExtra(float x, float y, float w)
{
	y = uiTextWrap(x, y, w, S_SMALL, uiCol[COL_DIM], "Cards go on the bottom screen. HOME is off while NFC is ours.");
	if (tag.uidLen) {
		char uid[32], s[96];
		uidHex(&tag, uid, "");
		snprintf(s, sizeof(s), "Last card: %s, %s", uid, cardTypeName(&tag));
		uiTextWrap(x, y + 4, w, S_SMALL, uiCol[COL_DIM], s);
	}
}

static void rootInput(u32 kDown, u32 kRepeat)
{
	menuInput(&rootMenu, kDown, kRepeat);
}

static void rootDraw(void)
{
	menuDraw(&rootMenu);
}

static const Screen rootScreen = { NULL, rootInput, rootDraw };

static void rootInit(void)
{
	int n = 0;
	rootEntries[n++] = (MenuEntry){ "Scan card", "Identify the card on the reader, then open it in its card type's "
		"tools (when supported).", startIdentify };
	for (int i = 0; i < NFAMILIES; i++)
		rootEntries[n++] = (MenuEntry){ families[i]->name, families[i]->help, families[i]->menu };
	rootEntries[n++] = (MenuEntry){ "iClass / PicoPass", "HID iClass (legacy and elite keys): key search, dump, the "
		"Wiegand credential. Not in the generic scan: iClass is ISO15693, polled on its own.", iclassOpenMenu };
	rootEntries[n++] = (MenuEntry){ "Emulate (card mode)", "The 3DS as a card for another reader: an NFC Forum Type 4 "
		"tag with a URL or text a phone can read (and write).", emuOpenMenu };
	rootEntries[n++] = (MenuEntry){ "Amiibo", "Read and copy Amiibo with this console's own keys, or make new ones "
		"from the figure list (AmiiboAPI, downloaded over Wi-Fi).", amiiboOpenMenu };
	rootEntries[n++] = (MenuEntry){ "Log", "Everything the card operations logged (also in sdmc:/nfcprobe.log).", openLog };
	rootEntries[n++] = (MenuEntry){ "Chip info", "Probe the NFC controller: reset, init, firmware patch version.", menuProbe };
	rootEntries[n++] = (MenuEntry){ "Exit", "Give NFC back to the system and quit.", menuExit };
	rootMenu.n = n;
	appScreen(&rootScreen);
}

// --- bottom screen ---

static u32 touchKeys; // pressed on the bottom screen, delivered next frame

void appPress(u32 keys)
{
	touchKeys |= keys;
}

// U+E000.. button glyphs in a hints string -> keys (0: the D-pad ones, which the D-pad covers)
static u32 glyphKey(const u8 *p)
{
	if (p[0] != 0xEE) return ~0u;
	u32 cp = (p[0] & 0x0F) << 12 | (p[1] & 0x3F) << 6 | (p[2] & 0x3F);
	switch (cp) {
	case 0xE000: return KEY_A;
	case 0xE001: return KEY_B;
	case 0xE002: return KEY_X;
	case 0xE003: return KEY_Y;
	case 0xE004: return KEY_L;
	case 0xE005: return KEY_R;
	case 0xE006: case 0xE07D: case 0xE07E: return 0;
	}
	return ~0u;
}

#define BOT_LOG 7 // log lines on the default bottom screen

// The default: the log's tail, a D-pad (lists, cursors) and one button per footer hint.
static void bottomDraw(void)
{
	u32 dim = uiCol[COL_DIM];
	int n = uiLogCount();
	uiRect(0, 0, UI_BW, BOT_LOG * 12 + 6, uiCol[COL_PANEL]);
	uiRect(0, BOT_LOG * 12 + 5, UI_BW, 1, uiCol[COL_ACCENT]);
	for (int i = 0; i < BOT_LOG; i++) {
		int k = n - BOT_LOG + i;
		if (k < 0) continue;
		char line[100];
		uiLogLine(k, line, sizeof(line));
		char *nl = strchr(line, '\n');
		if (nl) *nl = 0;
		uiText(4, 3 + i * 12, S_LOG, k == n - 1 ? uiCol[COL_TEXT] : dim, "%s", uiFit(line, UI_BW - 28, S_LOG));
	}
	float y0 = BOT_LOG * 12 + 14, c = 36; // D-pad cell
	u32 pad = uiCol[COL_BAR];
	if (uiButtonRep(c, y0, c, c, pad, "\uE079")) appPress(KEY_UP);
	if (uiButtonRep(0, y0 + c, c, c, pad, "\uE07B")) appPress(KEY_LEFT);
	if (uiButtonRep(2 * c, y0 + c, c, c, pad, "\uE07C")) appPress(KEY_RIGHT);
	if (uiButtonRep(c, y0 + 2 * c, c, c, pad, "\uE07A")) appPress(KEY_DOWN);
	// the hints: "<glyph> label   <glyph> label ...", two columns right of the D-pad
	const u8 *h = (const u8 *)uiHintsNow();
	float bx = 3 * c + 8, bw = (UI_BW - bx - 4) / 2 - 2, bh = 30;
	int i = 0;
	while (*h) {
		u32 key = glyphKey(h);
		if (key == ~0u) {
			h++;
			continue;
		}
		const u8 *e = h + 3;
		while (*e && glyphKey(e) == ~0u) e++;
		char label[48];
		int len = e - h < (int)sizeof(label) - 1 ? e - h : (int)sizeof(label) - 1;
		memcpy(label, h, len);
		label[len] = 0;
		char *gap = strstr(label + 3, "   "); // hints end at a wide gap ("... SELECT log" isn't a button)
		if (gap) *gap = 0;
		for (len = strlen(label); len > 3 && label[len - 1] == ' ';) label[--len] = 0;
		h = e;
		if (!key) continue;
		float x = bx + (i % 2) * (bw + 4), y = y0 + (i / 2) * (bh + 4);
		if (y + bh > UI_H - 2) break;
		if (uiButton(x, y, bw, bh, uiCol[COL_BAR], label)) appPress(key);
		i++;
	}
	if (uiButton(0, UI_H - 26, 3 * c, 24, uiCol[COL_PANEL], "Log")) appPress(KEY_SELECT);
}

// --- loop ---

// The saved dump lists, scanned once in the background: their first open doesn't wait for every file's date.
static Thread warmer;

static void warmMain(void *arg)
{
	mfFilesWarm();
	mfuFilesWarm();
}

void appRun(void)
{
	dumpInit();
	warmer = threadCreate(warmMain, NULL, 0x4000, 0x3F, -2, false);
	hidSetRepeatParameters(18, 4);
	rootInit();
	while (aptMainLoop() && !quit && !restartRequested) {
		frame++;
		hidScanInput();
		u32 net = __atomic_exchange_n(&netKeys, 0, __ATOMIC_SEQ_CST) | touchKeys;
		touchKeys = 0;
		u32 kDown = hidKeysDown() | net, kRepeat = hidKeysDownRepeat() | net;
		// touch: a new tap, then after a delay repeats while held (for D-pad and digit buttons)
		static u32 held;
		touchPosition tp = { 0 };
		if (hidKeysHeld() & KEY_TOUCH) hidTouchRead(&tp), held++;
		else held = 0;
		uiTouch(held == 1 || (held > 24 && held % 5 == 0), held > 1, tp.px, tp.py);
		if (aptCheckHomePressRejected()) toast("HOME is off while NFC is ours: START exits");
		jobReap();
		if (kDown & KEY_START) {
			mfCancel = true;
			break;
		}
		if (jobBusy) {
			if ((kDown & KEY_B) && jobCancellable) mfCancel = true;
		} else if (dlg.kind) {
			dialogInput(kDown, kRepeat);
		} else if ((kDown & KEY_SELECT) && stack[depth - 1] != &logScreen) {
			openLog();
		} else {
			stack[depth - 1]->input(kDown, kRepeat);
		}

		uiFrameBegin();
		stack[depth - 1]->draw();
		if (jobBusy) busyDraw();
		else if (dlg.kind) dialogDraw();
		if (jobBusy) uiHints(jobCancellable ? BTN_B " stop" : "");
		if (frame < toastUntil && !jobBusy && !dlg.kind) {
			char t[128];
			snprintf(t, sizeof(t), "%s", toastMsg);
			uiFit(t, UI_W - 32, S_SMALL);
			float w = 16 + uiTextWidth(S_SMALL, t);
			uiRect((UI_W - w) / 2, UI_H - 44, w, 20, uiCol[COL_BAR]);
			uiRect((UI_W - w) / 2, UI_H - 44, 2, 20, uiCol[COL_CURSOR]);
			uiTextCenter(UI_W / 2, UI_H - 41, S_SMALL, uiCol[COL_TEXT], "%s", t);
		}
		uiBottom();
		if (!jobBusy && !dlg.kind && stack[depth - 1]->bottom) stack[depth - 1]->bottom();
		else bottomDraw();
		uiFrameEnd();
	}
	uiFrameBegin();
	uiTextCenter(UI_W / 2, 110, S_BODY, uiCol[COL_TEXT], "Giving NFC back to the system...");
	uiFrameEnd();
}

void appShutdown(void)
{
	mfCancel = true;
	// A worker stuck in IPC can't be joined; only clean up a finished one.
	for (int i = 0; i < 100 && jobBusy && !jobFinished; i++) svcSleepThread(MS(100));
	if (worker && jobFinished) threadJoin(worker, U64_MAX), threadFree(worker);
	if (warmer) threadJoin(warmer, U64_MAX), threadFree(warmer);
	logp("--- exit: job %s ---\n", jobBusy && !jobFinished ? "STILL RUNNING" : "done");
}
