// Screens, dialogs and the card job worker. Top screen and buttons only: a card on the reader covers
// the whole bottom screen. The dump editor is in editor.c.

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

static int screen = SCR_MENU, from[SCR_LOG + 1];
static u32 frame;

void appScreen(int scr)
{
	if (scr == screen) return;
	from[scr] = screen;
	screen = scr;
}

void appBack(void)
{
	screen = from[screen];
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

const char *cardTypeName(u8 sak)
{
	switch (sak) {
	case 0x08: return "MIFARE Classic 1K";
	case 0x09: return "MIFARE Classic Mini";
	case 0x18: return "MIFARE Classic 4K";
	case 0x19: return "MIFARE Classic 2K";
	case 0x88: return "MIFARE Classic 1K (Infineon)";
	case 0x28: return "Classic 1K emulation (SmartMX)";
	case 0x38: return "Classic 4K emulation (SmartMX)";
	case 0x00: return "Ultralight / NTAG (not Classic)";
	case 0x20: return "ISO14443-4 (not Classic)";
	}
	return "unknown (treated as Classic)";
}

static const char *sizeName(int sectors)
{
	return sectors == 5 ? "Mini" : sectors == 16 ? "1K" : sectors == 32 ? "2K" : sectors == 40 ? "4K" : "?";
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
		char uid[21] = "";
		for (int i = 0; i < card.uidLen; i++) sprintf(uid + 2 * i, "%02X", card.uid[i]);
		logp("card: UID %s ATQA %02X%02X SAK %02X\n", uid, card.atqa[1], card.atqa[0], card.sak);
		return true;
	}
	return false;
}

// --- scan / card screen ---

static Card sc; // the card the card screen shows
static MfMagic sm;
static int scanResult; // 1 = card, 0 = none / cancelled, -1 = monitor error

static void runScan(void)
{
	scanResult = 0;
	if (!cardWait()) return;
	sc = card;
	scanResult = mfMagicDetect(mfGen4DefaultPwd, false, &sm) < 0 ? -1 : 1;
	iso14aParity(true);
}

static void doneScan(void)
{
	if (scanResult > 0) appScreen(SCR_CARD);
	else if (scanResult < 0) msgBox("Scan", "The chip stopped answering.\nTry again.");
}

static void startScan(void)
{
	jobStart("Scanning", runScan, doneScan, true);
}

static MfDump rd;
static char rdPath[128];
static int rdGot;

static void runRead(void)
{
	static u8 keys[MF_MAX_KEYS][6];
	rdGot = -2;
	rdPath[0] = 0;
	if (!cardWait()) return;
	sc = card;
	int sectors = mfSectorsFromSak(card.sak);
	int nkeys = mfKeyList(keys, MF_MAX_KEYS, NULL, 0);
	logp("%d sectors, %d dictionary keys\n", sectors, nkeys);
	rdGot = mfDumpCard(&rd, sectors, (const u8 (*)[6])keys, nkeys);
	iso14aParity(true);
	if (rdGot > 0 && mfSaveDump(&rd, rdPath, sizeof(rdPath))) logp("saved %s\n", rdPath);
}

static void doneRead(void)
{
	if (rdGot == -2) return; // no card (cancelled)
	if (rdGot < 0) {
		msgBox("Read card", "Lost the card (or the chip stopped answering).");
		return;
	}
	if (!rdGot) {
		msgBox("Read card", "No block could be read: no key found.");
		return;
	}
	int keys = 0;
	for (int s = 0; s < rd.sectors; s++) keys += rd.keyFound[s][0] + rd.keyFound[s][1];
	editorOpen(&rd, rdPath);
	msgBox(mfCancel ? "Read card (stopped)" : "Read card", "%d/%d blocks read, %d/%d keys found.\n%s",
		rdGot, mfFirstBlock(rd.sectors), keys, 2 * rd.sectors,
		rdPath[0] ? rdPath : "Could not save the dump to the SD card!");
}

static void startRead(void)
{
	jobStart("Reading card", runRead, doneRead, true);
}

static void cardDraw(void)
{
	char hdr[48];
	snprintf(hdr, sizeof(hdr), "ATQA %02X%02X  SAK %02X", sc.atqa[1], sc.atqa[0], sc.sak);
	uiHeader("Card", hdr);
	float y = 28;
	char uid[40] = "";
	for (int i = 0; i < sc.uidLen; i++) sprintf(uid + 3 * i, "%02X ", sc.uid[i]);
	uiText(12, y, S_SMALL, uiCol[COL_DIM], "UID (%d bytes)", sc.uidLen);
	uiText(12, y + 12, 0.8f, uiCol[COL_ACCENT], "%s", uid);
	y += 40;
	uiText(12, y, S_BODY, uiCol[COL_TEXT], "%s", cardTypeName(sc.sak));
	uiText(12, y + LINE_H, S_SMALL, uiCol[COL_DIM], "%d sectors, %d blocks", mfSectorsFromSak(sc.sak),
		mfFirstBlock(mfSectorsFromSak(sc.sak)));
	y += LINE_H + SMALL_H + 8;

	char magic[64] = "";
	if (sm.flags & MF_MAGIC_GEN4) strcat(magic, "Gen4 GTU, ");
	if (sm.flags & MF_MAGIC_USCUID) strcat(magic, "USCUID (Gen4 GDM), ");
	else if (sm.flags & MF_MAGIC_GEN1A) strcat(magic, "Gen1a, ");
	if (*magic) magic[strlen(magic) - 2] = 0;
	uiText(12, y, S_BODY, uiCol[COL_TEXT], "Magic:");
	uiText(62, y, S_BODY, uiCol[*magic ? COL_OK : COL_DIM], "%s", *magic ? magic : "none found");
	y += LINE_H;
	if (!*magic) uiText(62, y, S_SMALL, uiCol[COL_DIM], "(a Gen2 / CUID card only shows when written to)");

	if (sm.flags & MF_MAGIC_GEN4) {
		const u8 *c = sm.cfg;
		static const char *shadow[] = { "pre-write", "restore", "off", "off (fast)" };
		uiRect(8, y + 2, UI_W - 16, 3 * SMALL_H + 8, uiCol[COL_PANEL]);
		y += 6;
		uiText(14, y, S_SMALL, uiCol[COL_ACCENT], "Gen4 GTU config (password 00000000)");
		y += SMALL_H;
		uiText(14, y, S_SMALL, uiCol[COL_TEXT], "Mode %s   UID %d bytes   Shadow mode %s",
			c[0] ? "Ultralight" : "Classic", c[1] == 2 ? 10 : c[1] == 1 ? 7 : 4, c[6] < 4 ? shadow[c[6]] : "?");
		y += SMALL_H;
		uiText(14, y, S_SMALL, uiCol[COL_TEXT], "ATQA %02X%02X   SAK %02X   Max sectors %02X   ATS %s",
			c[25], c[24], c[26], c[28], c[7] ? "on" : "off");
	} else if (sm.flags & MF_MAGIC_USCUID) {
		uiRect(8, y + 2, UI_W - 16, 2 * SMALL_H + 8, uiCol[COL_PANEL]);
		y += 6;
		char hex[40];
		for (int i = 0; i < MF_USC_CFG; i++) sprintf(hex + 2 * i, "%02X", sm.usc[i]);
		uiText(14, y, S_SMALL, uiCol[COL_ACCENT], "USCUID config");
		uiText(14, y + SMALL_H, S_SMALL, uiCol[COL_TEXT], "%s", hex);
	}
	uiFooter(BTN_A " scan again   " BTN_X " read card   " BTN_Y " Gen4 config   " BTN_B " back");
}

// --- Gen4 GTU config ---

static u8 g4cfg[MF_GEN4_CFG], g4new[MF_GEN4_CFG];
static int g4sel, g4uid, g4size, g4shadow, g4result;
static char g4why[64];
static const u8 sizeSak[] = { 0x09, 0x08, 0x19, 0x18 };
static const char *sizeNames[] = { "Mini (5 sectors)", "1K (16 sectors)", "2K (32 sectors)", "4K (40 sectors)" };
static const char *shadowNames[] = { "pre-write", "restore", "off", "off, high speed" };

static void gen4Open(void)
{
	memcpy(g4cfg, sm.cfg, MF_GEN4_CFG);
	g4uid = g4cfg[1] <= 2 ? g4cfg[1] : 0;
	g4shadow = g4cfg[6] <= 3 ? g4cfg[6] : 2;
	g4size = 1;
	for (int i = 0; i < 4; i++)
		if (g4cfg[26] == sizeSak[i]) g4size = i;
	g4sel = 0;
	appScreen(SCR_GEN4);
}

static void gen4Build(void)
{
	memcpy(g4new, g4cfg, MF_GEN4_CFG);
	g4new[1] = g4uid;
	g4new[6] = g4shadow;
	g4new[24] = (g4size == 3 ? 0x02 : 0x04) | (g4uid == 1 ? 0x40 : g4uid == 2 ? 0x80 : 0); // ATQA, swapped
	g4new[25] = 0x00;
	g4new[26] = sizeSak[g4size];
}

static void runGen4(void)
{
	g4result = 0;
	if (!cardWait()) return;
	g4result = mfGen4SetConfig(mfGen4DefaultPwd, g4new);
	snprintf(g4why, sizeof(g4why), "%s", mfWhy());
	// Reactivate: the UID length, ATQA and SAK may all have changed.
	if (g4result == 1 && iso14aStart()) {
		sc = card;
		if (mfMagicDetect(mfGen4DefaultPwd, false, &sm) >= 0) memcpy(g4cfg, sm.cfg, MF_GEN4_CFG);
		iso14aParity(true);
	}
}

static void doneGen4(void)
{
	if (g4result == 1) {
		appBack();
		toast("Gen4 config written and verified");
	} else if (!mfCancel) {
		msgBox("Gen4 config", "Not written: %s", g4result < 0 ? "the chip stopped answering" : g4why);
	}
}

static void gen4Apply(void)
{
	jobStart("Writing Gen4 config", runGen4, doneGen4, true);
}

static void gen4Input(u32 kDown, u32 kRepeat)
{
	if (kRepeat & KEY_UP) g4sel = (g4sel + 2) % 3;
	if (kRepeat & KEY_DOWN) g4sel = (g4sel + 1) % 3;
	int d = (kRepeat & KEY_RIGHT) ? 1 : (kRepeat & KEY_LEFT) ? -1 : 0;
	if (g4sel == 0) g4uid = (g4uid + 3 + d) % 3;
	if (g4sel == 1) g4size = (g4size + 4 + d) % 4;
	if (g4sel == 2) g4shadow = (g4shadow + 4 + d) % 4;
	if (kDown & KEY_B) appBack();
	if (kDown & KEY_A) {
		gen4Build();
		if (!memcmp(g4new, g4cfg, MF_GEN4_CFG)) {
			toast("Nothing changed");
			return;
		}
		confirm("Gen4 config", gen4Apply, "Write the new config to the GTU on the reader?\n"
			"The UID is then read from block 0's first %d bytes.", g4uid == 2 ? 10 : g4uid == 1 ? 7 : 4);
	}
}

static void gen4Draw(void)
{
	uiHeader("Gen4 GTU config", "password 00000000");
	if (g4cfg[0]) {
		uiText(12, 40, S_BODY, uiCol[COL_WARN], "This GTU is in Ultralight mode: not supported here.");
		uiFooter(BTN_B " back");
		return;
	}
	gen4Build();
	static const char *labels[] = { "UID length", "Card type", "Shadow mode" };
	char vals[3][32];
	snprintf(vals[0], 32, "%d bytes", g4uid == 2 ? 10 : g4uid == 1 ? 7 : 4);
	snprintf(vals[1], 32, "%s", sizeNames[g4size]);
	snprintf(vals[2], 32, "%s", shadowNames[g4shadow]);
	float y = 32;
	for (int i = 0; i < 3; i++, y += 22) {
		if (i == g4sel) uiRect(8, y - 3, UI_W - 16, 21, uiCol[COL_SEL]);
		uiText(16, y, S_BODY, uiCol[COL_TEXT], "%s", labels[i]);
		uiText(140, y, S_BODY, uiCol[COL_ACCENT], "< %s >", vals[i]);
	}
	y += 8;
	uiText(16, y, S_SMALL, uiCol[COL_DIM], "Announces ATQA %02X%02X, SAK %02X (now %02X%02X, %02X).",
		g4new[25], g4new[24], g4new[26], g4cfg[25], g4cfg[24], g4cfg[26]);
	y += SMALL_H + 6;
	static const char *help[] = {
		"4, 7 or 10 bytes, taken from the start of block 0.",
		"Sets ATQA and SAK. The GTU holds 4K of data whatever it announces.",
		"pre-write: writes go to a shadow copy and vanish when the card leaves the field.",
	};
	uiText(16, y, S_SMALL, uiCol[COL_TEXT], "%s", help[g4sel]);
	uiFooter(BTN_UD " select   " BTN_LR " change   " BTN_A " write to card   " BTN_B " back");
}

// --- clone ---

static MfDump cl;
static bool clForce;
static int clResult;
static char clWhy[64];

static void runClone(void)
{
	clResult = -2;
	if (!cardWait()) return;
	clResult = mfCloneToMagic((const u8 (*)[16])cl.data, cl.valid, mfFirstBlock(cl.sectors), clForce);
	snprintf(clWhy, sizeof(clWhy), "%s", mfWhy());
	iso14aParity(true);
	logp("clone: %s\n", clResult == 1 ? "done" : clWhy);
}

static void cloneForce(void)
{
	cloneStart(&cl, true);
}

static void doneClone(void)
{
	if (clResult == -2) return;
	if (clResult == 1) msgBox("Write to magic card", "Done: every block written and read back.");
	else if (clResult < 0) msgBox("Write to magic card", "The chip stopped answering.\nThe card may be half written.");
	else if (strstr(clWhy, "(force)"))
		confirm("Write to magic card", cloneForce, "Refused: %s.\nA Gen2 card can't change that sector again "
			"afterwards.\nWrite anyway?", clWhy);
	else msgBox("Write to magic card", "Refused: %s", clWhy);
}

void cloneStart(const MfDump *d, bool force)
{
	if (d != &cl) cl = *d;
	clForce = force;
	jobStart("Writing to magic card", runClone, doneClone, true);
}

// --- saved dumps ---

typedef struct {
	char name[64];
	int blocks;
	u64 mtime;
} FileEnt;
static FileEnt files[200];
static int nfiles;
static UiList fl;

static int fileCmp(const void *a, const void *b)
{
	const FileEnt *x = a, *y = b;
	return x->mtime < y->mtime ? 1 : x->mtime > y->mtime ? -1 : strcmp(x->name, y->name);
}

static void filesScan(void)
{
	nfiles = 0;
	DIR *dir = opendir(MF_DUMPS);
	struct dirent *e;
	while (dir && (e = readdir(dir)) && nfiles < 200) {
		int len = strlen(e->d_name);
		if (len < 5 || len >= 64 || strcasecmp(e->d_name + len - 4, ".bin")) continue;
		FileEnt *f = &files[nfiles];
		char path[128];
		snprintf(path, sizeof(path), MF_DUMPS "/%s", e->d_name);
		struct stat st;
		if (stat(path, &st)) continue;
		snprintf(f->name, sizeof(f->name), "%s", e->d_name);
		f->blocks = st.st_size / 16;
		f->mtime = 0;
		archive_getmtime(path, &f->mtime);
		nfiles++;
	}
	if (dir) closedir(dir);
	qsort(files, nfiles, sizeof(*files), fileCmp);
	if (fl.sel >= nfiles) fl.sel = nfiles ? nfiles - 1 : 0;
}

static void filePath(char *out, u32 max)
{
	snprintf(out, max, MF_DUMPS "/%s", files[fl.sel].name);
}

static void fileDelete(void)
{
	char path[128], kpath[140];
	filePath(path, sizeof(path));
	snprintf(kpath, sizeof(kpath), "%.*s.keys.txt", (int)strlen(path) - 4, path);
	remove(path);
	remove(kpath);
	toast("Deleted %s", files[fl.sel].name);
	filesScan();
}

static void fileClone(void)
{
	cloneStart(&cl, false);
}

static void filesInput(u32 kDown, u32 kRepeat)
{
	uiListNav(&fl, nfiles, 12, kRepeat);
	if (kDown & KEY_B) appBack();
	if (!nfiles) return;
	char path[128];
	filePath(path, sizeof(path));
	if (kDown & (KEY_A | KEY_X)) {
		static MfDump d;
		if (!mfLoadDump(&d, path)) {
			msgBox("Saved dumps", "%s is not a Mifare Classic dump\n(%d bytes).", files[fl.sel].name,
				files[fl.sel].blocks * 16);
			return;
		}
		if (kDown & KEY_A) {
			editorOpen(&d, path);
			return;
		}
		cl = d;
		confirm("Write to magic card", fileClone, "Write %s onto the magic card on the reader?\n"
			"Everything on that card is overwritten (Gen1a, Gen2, Gen4 GTU, USCUID).", files[fl.sel].name);
	}
	if (kDown & KEY_Y) confirm("Delete", fileDelete, "Delete %s and its key file?", files[fl.sel].name);
}

static void filesDraw(void)
{
	char hdr[32];
	snprintf(hdr, sizeof(hdr), "%d dump%s", nfiles, nfiles == 1 ? "" : "s");
	uiHeader("Saved dumps", hdr);
	if (!nfiles) {
		uiTextCenter(UI_W / 2, 100, S_BODY, uiCol[COL_DIM], "No dumps yet.");
		uiTextCenter(UI_W / 2, 118, S_SMALL, uiCol[COL_DIM], "Read a card, or copy .bin dumps to " MF_DUMPS);
		uiFooter(BTN_B " back");
		return;
	}
	for (int i = 0; i < 12 && fl.top + i < nfiles; i++) {
		const FileEnt *f = &files[fl.top + i];
		float y = 24 + i * LINE_H;
		if (fl.top + i == fl.sel) uiRect(4, y - 1, UI_W - 8, LINE_H, uiCol[COL_SEL]);
		uiText(10, y, S_BODY, uiCol[COL_TEXT], "%s", f->name);
		int sectors = 0;
		while (sectors < 40 && mfFirstBlock(sectors) < f->blocks) sectors++;
		uiTextRight(268, y + 1, S_SMALL, uiCol[mfFirstBlock(sectors) == f->blocks ? COL_ACCENT : COL_ERR], "%s",
			mfFirstBlock(sectors) == f->blocks ? sizeName(sectors) : "not MFC");
		if (f->mtime) {
			time_t t = f->mtime;
			struct tm *tm = gmtime(&t);
			uiTextRight(UI_W - 10, y + 1, S_SMALL, uiCol[COL_DIM], "%04d-%02d-%02d %02d:%02d", tm->tm_year + 1900,
				tm->tm_mon + 1, tm->tm_mday, tm->tm_hour, tm->tm_min);
		}
	}
	if (nfiles > 12) uiTextRight(UI_W - 6, UI_H - 34, S_SMALL, uiCol[COL_DIM], "%d-%d of %d", fl.top + 1,
		fl.top + 12 < nfiles ? fl.top + 12 : nfiles, nfiles);
	uiFooter(BTN_A " open   " BTN_X " write to magic card   " BTN_Y " delete   " BTN_B " back");
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

// --- main menu ---

static bool quit;
static int dictKeys;
static UiList ml;

static void doneProbe(void)
{
	logTop = -1;
	appScreen(SCR_LOG);
}

static void menuFiles(void)
{
	appScreen(SCR_FILES);
}

static void menuLog(void)
{
	logTop = -1;
	appScreen(SCR_LOG);
}

static void menuProbe(void)
{
	jobStart("Chip info", chipProbe, doneProbe, false);
}

static void menuExit(void)
{
	quit = true;
}

static const struct {
	const char *label, *help;
	void (*fn)(void);
} menu[] = {
	{ "Scan card", "Identify the card on the reader: type, UID, magic generation (Gen1a, Gen4 GTU, USCUID).", startScan },
	{ "Read card", "Dump every sector. Keys from the dictionary, then the nested and static-nonce attacks and the "
	               "magic backdoors. Saved to the SD card and opened in the editor.", startRead },
	{ "Saved dumps", "View and edit dumps, write them onto magic cards.", menuFiles },
	{ "Log", "Everything the card operations logged (also in sdmc:/nfcprobe.log).", menuLog },
	{ "Chip info", "Probe the NFC controller: reset, init, firmware patch version.", menuProbe },
	{ "Exit", "Give NFC back to the system and quit.", menuExit },
};
#define MENU_N (int)(sizeof(menu) / sizeof(menu[0]))

static void menuEnter(void)
{
	static u8 keys[MF_MAX_KEYS][6];
	dictKeys = mfKeyList(keys, MF_MAX_KEYS, NULL, 0);
}

static void menuInput(u32 kDown, u32 kRepeat)
{
	uiListNav(&ml, MENU_N, MENU_N, kRepeat & (KEY_UP | KEY_DOWN));
	if (kDown & KEY_A) menu[ml.sel].fn();
}

static void menuDraw(void)
{
	uiHeader("nfcprobe — MIFARE Classic", *netAddr ? netAddr : "no network");
	for (int i = 0; i < MENU_N; i++) {
		float y = 30 + i * 22;
		if (i == ml.sel) {
			uiRect(8, y - 3, 180, 21, uiCol[COL_SEL]);
			uiRect(8, y - 3, 3, 21, uiCol[COL_ACCENT]);
		}
		uiText(20, y, S_BODY, uiCol[i == ml.sel ? COL_TEXT : COL_DIM], "%s", menu[i].label);
	}
	// help panel: word-wrapped by hand
	uiRect(200, 27, UI_W - 208, 128, uiCol[COL_PANEL]);
	char buf[256], *w = buf, line[64] = "";
	snprintf(buf, sizeof(buf), "%s", menu[ml.sel].help);
	float y = 32;
	for (char *tok = strtok_r(buf, " ", &w); tok; tok = strtok_r(NULL, " ", &w)) {
		if (strlen(line) + strlen(tok) + 1 > 34) {
			uiText(208, y, S_SMALL, uiCol[COL_TEXT], "%s", line);
			y += SMALL_H;
			line[0] = 0;
		}
		if (*line) strcat(line, " ");
		strcat(line, tok);
	}
	uiText(208, y, S_SMALL, uiCol[COL_TEXT], "%s", line);

	float by = 168;
	uiText(12, by, S_SMALL, uiCol[COL_DIM], "Dictionary: %d keys (defaults + " MF_KEYS ")", dictKeys);
	if (sc.uidLen) {
		char uid[21] = "";
		for (int i = 0; i < sc.uidLen; i++) sprintf(uid + 2 * i, "%02X", sc.uid[i]);
		uiText(12, by + SMALL_H, S_SMALL, uiCol[COL_DIM], "Last card: %s, %s", uid, cardTypeName(sc.sak));
	}
	uiText(12, by + 2 * SMALL_H, S_SMALL, uiCol[COL_DIM], "Cards go on the bottom screen. HOME is off while NFC is ours.");
	uiFooter(BTN_A " select   SELECT log   START exit");
}

// --- loop ---

static void screenInput(u32 kDown, u32 kRepeat)
{
	if ((kDown & KEY_SELECT) && screen != SCR_LOG) {
		menuLog();
		return;
	}
	switch (screen) {
	case SCR_MENU: menuInput(kDown, kRepeat); break;
	case SCR_CARD:
		if (kDown & KEY_A) startScan();
		if (kDown & KEY_X) startRead();
		if ((kDown & KEY_Y) && (sm.flags & MF_MAGIC_GEN4)) gen4Open();
		else if (kDown & KEY_Y) toast("Not a Gen4 GTU");
		if (kDown & KEY_B) appBack();
		break;
	case SCR_GEN4: gen4Input(kDown, kRepeat); break;
	case SCR_FILES: filesInput(kDown, kRepeat); break;
	case SCR_EDIT: editorInput(kDown, kRepeat); break;
	case SCR_LOG: logInput(kDown, kRepeat); break;
	}
}

static void screenDraw(void)
{
	switch (screen) {
	case SCR_MENU: menuDraw(); break;
	case SCR_CARD: cardDraw(); break;
	case SCR_GEN4: gen4Draw(); break;
	case SCR_FILES: filesDraw(); break;
	case SCR_EDIT: editorDraw(); break;
	case SCR_LOG: logDraw(); break;
	}
}

void appRun(void)
{
	hidSetRepeatParameters(18, 4);
	menuEnter();
	int lastScreen = SCR_MENU;
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
		} else {
			screenInput(kDown, kRepeat);
		}
		if (screen != lastScreen && screen == SCR_MENU) menuEnter();
		if (screen != lastScreen && screen == SCR_FILES) filesScan(); // the editor may have saved one
		lastScreen = screen;

		uiFrameBegin();
		screenDraw();
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
