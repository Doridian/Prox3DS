// App shell: screen stack, dialogs, the card job worker, the root menu with the generic scan, the log.
// Top screen and buttons only: a card on the reader covers the whole bottom screen. Card families
// bring their own screens (MIFARE Classic: mfui.c, editor.c).

#include <dirent.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <3ds.h>

#include "app.h"
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
	MenuItem items[12];
	int n;
	UiList l;
} dlg;

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
	dlg.n = n < 12 ? n : 12;
	memcpy(dlg.items, items, dlg.n * sizeof(*items));
	dlg.l = (UiList){ 0 };
	dlg.kind = DLG_POPUP;
}

static void dialogInput(u32 kDown, u32 kRepeat)
{
	int kind = dlg.kind;
	if (kind == DLG_POPUP) {
		uiListNav(&dlg.l, dlg.n, dlg.n, kRepeat & (KEY_UP | KEY_DOWN));
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
		float h = 22 + dlg.n * LINE_H + 22, y = uiBox(240, h, dlg.title), x = (UI_W - 240) / 2;
		for (int i = 0; i < dlg.n; i++, y += LINE_H) {
			if (i == dlg.l.sel) uiRect(x + 2, y - 1, 236, LINE_H, uiCol[COL_SEL]);
			uiText(x + 10, y, S_BODY, uiCol[COL_TEXT], "%s", dlg.items[i].label);
		}
		uiText(x + 10, y + 4, S_SMALL, uiCol[COL_DIM], BTN_A " select   " BTN_B " close");
		return;
	}
	int lines = uiWrapLines(DLG_W - 20, S_SMALL, dlg.msg);
	float h = 22 + lines * SMALL_H + 26, y = uiBox(DLG_W, h, dlg.title), x = (UI_W - DLG_W) / 2;
	uiTextWrap(x + 10, y, DLG_W - 20, S_SMALL, uiCol[COL_TEXT], dlg.msg);
	uiText(x + 10, y + lines * SMALL_H + 6, S_SMALL, uiCol[COL_DIM], "%s",
		dlg.kind == DLG_CONFIRM ? BTN_A " yes   " BTN_B " no" : BTN_A " ok");
}

// --- job worker ---

static Thread worker;
static volatile bool jobBusy, jobFinished;
static const char *jobTitle;
static void (*jobRun)(void), (*jobDone)(void);
static bool jobCancellable;
static float (*jobView)(float x, float y, float w);

static void jobThread(void *arg)
{
	LightLock_Lock(&hwLock);
	jobRun();
	LightLock_Unlock(&hwLock);
	jobFinished = true;
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
	progJob();
	jobTitle = title;
	jobRun = run;
	jobDone = done;
	jobCancellable = cancellable;
	mfCancel = false;
	jobFinished = false;
	jobBusy = true;
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
		uiTextRight(x + w - 10, hy, S_SMALL, uiCol[COL_DIM], "Keep the card on the bottom screen.");
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
	for (int i = 0; i < m->n; i++) {
		float y = 30 + i * 20;
		if (i == m->l.sel) {
			uiRect(8, y - 3, 180, 19, uiCol[COL_SEL]);
			uiRect(8, y - 3, 3, 19, uiCol[COL_ACCENT]);
		}
		uiText(20, y, S_BODY, uiCol[i == m->l.sel ? COL_TEXT : COL_DIM], "%s", m->entries[i].label);
	}
	uiRect(200, 27, UI_W - 208, 140, uiCol[COL_PANEL]);
	uiTextWrap(208, 32, UI_W - 224, S_SMALL, uiCol[COL_TEXT], m->entries[m->l.sel].help);
	if (m->extra) m->extra(178);
	uiFooter(depth > 1 ? BTN_A " select   " BTN_B " back   SELECT log   START exit"
	                   : BTN_A " select   SELECT log   START exit");
}

void menuLastCard(float y, const Card *c, const char *type)
{
	char uid[32], s[96];
	uidHex(c, uid, "");
	snprintf(s, sizeof(s), "Last card: %s, %s", uid, type);
	uiText(12, y, S_SMALL, uiCol[COL_DIM], "%s", uiFit(s, UI_W - 24, S_SMALL));
}

// --- generic scan ("hf search"): identify, then hand the card to its family ---

static const CardFamily *families[] = { &mfcFamily, &mfuFamily, &dfFamily };
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
	for (int i = 0; i < NFAMILIES && !tagFamily; i++)
		if (families[i]->match(&tag)) tagFamily = families[i];
	logp("identified: %s%s%s\n", cardTypeName(&tag), tagFamily ? " -> " : " (not supported)",
		tagFamily ? tagFamily->name : "");
	tagResult = tagFamily && tagFamily->probe ? tagFamily->probe() : 1;
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

static MenuEntry rootEntries[4 + NFAMILIES + 1];
static void rootExtra(float y);
static Menu rootMenu = { "nfcprobe", rootEntries, 0, rootExtra };

static void rootExtra(float y)
{
	if (tag.uidLen) menuLastCard(y, &tag, cardTypeName(&tag));
	uiText(12, y + SMALL_H, S_SMALL, uiCol[COL_DIM], "Cards go on the bottom screen. HOME is off while NFC is ours.");
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
	rootEntries[n++] = (MenuEntry){ "Log", "Everything the card operations logged (also in sdmc:/nfcprobe.log).", openLog };
	rootEntries[n++] = (MenuEntry){ "Chip info", "Probe the NFC controller: reset, init, firmware patch version.", menuProbe };
	rootEntries[n++] = (MenuEntry){ "Exit", "Give NFC back to the system and quit.", menuExit };
	rootMenu.n = n;
	appScreen(&rootScreen);
}

// --- loop ---

void appRun(void)
{
	hidSetRepeatParameters(18, 4);
	rootInit();
	while (aptMainLoop() && !quit && !restartRequested) {
		frame++;
		hidScanInput();
		u32 net = __atomic_exchange_n(&netKeys, 0, __ATOMIC_SEQ_CST);
		u32 kDown = hidKeysDown() | net, kRepeat = hidKeysDownRepeat() | net;
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
		if (frame < toastUntil && !jobBusy && !dlg.kind) {
			char t[128];
			snprintf(t, sizeof(t), "%s", toastMsg);
			uiFit(t, UI_W - 32, S_SMALL);
			float w = 16 + uiTextWidth(S_SMALL, t);
			uiRect((UI_W - w) / 2, UI_H - 44, w, 20, uiCol[COL_BAR]);
			uiTextCenter(UI_W / 2, UI_H - 41, S_SMALL, uiCol[COL_TEXT], "%s", t);
		}
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
	logp("--- exit: job %s ---\n", jobBusy && !jobFinished ? "STILL RUNNING" : "done");
}
