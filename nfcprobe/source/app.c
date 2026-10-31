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
	int lines = 1;
	for (const char *p = dlg.msg; *p; p++) lines += *p == '\n';
	float h = 22 + lines * SMALL_H + 26, y = uiBox(340, h, dlg.title), x = (UI_W - 340) / 2;
	uiText(x + 10, y, S_SMALL, uiCol[COL_TEXT], "%s", dlg.msg);
	uiText(x + 10, y + lines * SMALL_H + 6, S_SMALL, uiCol[COL_DIM], "%s",
		dlg.kind == DLG_CONFIRM ? BTN_A " yes   " BTN_B " no" : BTN_A " ok");
}

// --- job worker ---

static Thread worker;
static volatile bool jobBusy, jobFinished;
static const char *jobTitle;
static void (*jobRun)(void), (*jobDone)(void);
static bool jobCancellable;

static void jobThread(void *arg)
{
	LightLock_Lock(&hwLock);
	jobRun();
	LightLock_Unlock(&hwLock);
	jobFinished = true;
}

void jobStart(const char *title, void (*run)(void), void (*done)(void), bool cancellable)
{
	if (jobBusy) return;
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

static void busyDraw(void)
{
	float y = uiBox(372, 176, jobTitle), x = (UI_W - 372) / 2;
	static const char spin[] = "|/-\\";
	if (jobCancellable) uiText(x + 10, y, S_SMALL, uiCol[COL_ACCENT], "Keep the card on the bottom screen.");
	uiTextRight(x + 362, y, S_BODY, uiCol[COL_ACCENT], "%c", spin[(frame / 8) % 4]);
	y += SMALL_H + 4;
	uiRect(x + 6, y - 2, 360, 9 * 12 + 4, uiCol[COL_BG]);
	int n = uiLogCount();
	char line[100];
	for (int i = 0; i < 9; i++) {
		int idx = n - 9 + i;
		if (idx < 0) continue;
		uiLogLine(idx, line, sizeof(line));
		uiText(x + 10, y + 12 * i, 0.38f, uiCol[i == 8 ? COL_TEXT : COL_DIM], "%s", line);
	}
	if (jobCancellable)
		uiText(x + 10, y + 9 * 12 + 6, S_SMALL, uiCol[mfCancel ? COL_WARN : COL_DIM],
			mfCancel ? "Stopping..." : BTN_B " stop");
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

static void logInput(u32 kDown, u32 kRepeat)
{
	int n = uiLogCount(), vis = 16, max = n > vis ? n - vis : 0;
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
	int n = uiLogCount(), vis = 16, max = n > vis ? n - vis : 0;
	int top = logTop < 0 || logTop > max ? max : logTop;
	char hdr[48], line[100];
	snprintf(hdr, sizeof(hdr), "%s%d lines", logTop < 0 ? "following, " : "", n);
	uiHeader("Log", hdr);
	for (int i = 0; i < vis && top + i < n; i++) {
		uiLogLine(top + i, line, sizeof(line));
		uiText(6, 23 + i * 12, 0.38f, uiCol[COL_TEXT], "%s", line);
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
		float y = 30 + i * 22;
		if (i == m->l.sel) {
			uiRect(8, y - 3, 180, 21, uiCol[COL_SEL]);
			uiRect(8, y - 3, 3, 21, uiCol[COL_ACCENT]);
		}
		uiText(20, y, S_BODY, uiCol[i == m->l.sel ? COL_TEXT : COL_DIM], "%s", m->entries[i].label);
	}
	uiRect(200, 27, UI_W - 208, 128, uiCol[COL_PANEL]);
	uiTextWrap(208, 32, UI_W - 224, S_SMALL, uiCol[COL_TEXT], m->entries[m->l.sel].help);
	if (m->extra) m->extra(168);
	uiFooter(depth > 1 ? BTN_A " select   " BTN_B " back   SELECT log   START exit"
	                   : BTN_A " select   SELECT log   START exit");
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
	uiText(14, 96 + SMALL_H, S_SMALL, uiCol[COL_TEXT], "Supported:");
	char fams[128] = "";
	for (int i = 0; i < NFAMILIES; i++) sprintf(fams + strlen(fams), "%s%s", i ? ", " : "", families[i]->name);
	uiText(76, 96 + SMALL_H, S_SMALL, uiCol[COL_TEXT], "%s", fams);
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
	if (tag.uidLen) {
		char uid[32];
		uidHex(&tag, uid, "");
		uiText(12, y, S_SMALL, uiCol[COL_DIM], "Last card: %s, %s", uid, cardTypeName(&tag));
	}
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
		if (frame < toastUntil) {
			float w = 16 + strlen(toastMsg) * 5.2f;
			uiRect((UI_W - w) / 2, UI_H - 44, w, 20, uiCol[COL_BAR]);
			uiTextCenter(UI_W / 2, UI_H - 41, S_SMALL, uiCol[COL_TEXT], "%s", toastMsg);
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
