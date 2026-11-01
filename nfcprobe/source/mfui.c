// MIFARE Classic family: its menu (scan, read, saved dumps), card screen, Gen4 GTU config, clone onto
// magic cards and the dump list. The dump editor is in editor.c.

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <3ds.h>

#include "app.h"
#include "probe.h"
#include "ui.h"

static const char *sizeName(int sectors)
{
	return sectors == 5 ? "Mini" : sectors == 16 ? "1K" : sectors == 32 ? "2K" : sectors == 40 ? "4K" : "?";
}

// --- card screen ---

static Card sc; // the card the card screen shows
static MfMagic sm;
static int scanResult; // 1 = card, 0 = none / cancelled, -1 = monitor error

static const Screen cardScreen;

// Family probe (card active): magic detection for the card screen.
static int mfcProbe(void)
{
	sc = card;
	int r = mfMagicDetect(mfGen4DefaultPwd, true, &sm) < 0 ? -1 : 1;
	iso14aParity(true);
	return r;
}

static void runScan(void)
{
	scanResult = 0;
	if (cardWait()) scanResult = mfcProbe();
}

static void mfcShow(void)
{
	appScreen(&cardScreen);
}

static void doneScan(void)
{
	if (scanResult > 0) mfcShow();
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
	uiHeader("MIFARE Classic: card", hdr);
	float y = 28;
	char uid[32];
	uidHex(&sc, uid, " ");
	uiText(12, y, S_SMALL, uiCol[COL_DIM], "UID (%d bytes)", sc.uidLen);
	uiText(12, y + 12, 0.8f, uiCol[COL_ACCENT], "%s", uid);
	y += 40;
	uiText(12, y, S_BODY, uiCol[COL_TEXT], "%s", cardTypeName(&sc));
	if (mfcFamily.match(&sc))
		uiText(12, y + LINE_H, S_SMALL, uiCol[COL_DIM], "%d sectors, %d blocks", mfSectorsFromSak(sc.sak),
			mfFirstBlock(mfSectorsFromSak(sc.sak)));
	else
		uiText(12, y + LINE_H, S_SMALL, uiCol[COL_WARN], "Not a MIFARE Classic card: reading it as one will fail.");
	y += LINE_H + SMALL_H + 8;

	char magic[64] = "";
	if (sm.flags & MF_MAGIC_GEN4) strcat(magic, "Gen4 GTU, ");
	if (sm.flags & MF_MAGIC_USCUID) strcat(magic, "USCUID (Gen4 GDM), ");
	else if (sm.flags & MF_MAGIC_GEN1A) strcat(magic, "Gen1a, ");
	if (sm.flags & MF_MAGIC_GEN2) strcat(magic, "Gen2 / CUID, ");
	if (*magic) magic[strlen(magic) - 2] = 0;
	uiText(12, y, S_BODY, uiCol[COL_TEXT], "Magic:");
	uiText(62, y, S_BODY, uiCol[*magic ? COL_OK : COL_DIM], "%s", *magic ? magic : "none found");
	y += LINE_H;
	if (!*magic) uiText(62, y, S_SMALL, uiCol[COL_DIM], "(Gen2 / CUID needs a default key for sector 0 or a known ATS)");

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

static void gen4Open(void);

static void cardInput(u32 kDown, u32 kRepeat)
{
	if (kDown & KEY_A) startScan();
	if (kDown & KEY_X) startRead();
	if ((kDown & KEY_Y) && (sm.flags & MF_MAGIC_GEN4)) gen4Open();
	else if (kDown & KEY_Y) toast("Not a Gen4 GTU");
	if (kDown & KEY_B) appBack();
}

static const Screen cardScreen = { NULL, cardInput, cardDraw };

// --- Gen4 GTU config ---

static u8 g4cfg[MF_GEN4_CFG], g4new[MF_GEN4_CFG];
static int g4sel, g4uid, g4size, g4shadow, g4result;
static char g4why[64];
static const u8 sizeSak[] = { 0x09, 0x08, 0x19, 0x18 };
static const char *sizeNames[] = { "Mini (5 sectors)", "1K (16 sectors)", "2K (32 sectors)", "4K (40 sectors)" };
static const char *shadowNames[] = { "pre-write", "restore", "off", "off, high speed" };

static void gen4Input(u32 kDown, u32 kRepeat);
static void gen4Draw(void);

static void gen4Open(void)
{
	memcpy(g4cfg, sm.cfg, MF_GEN4_CFG);
	g4uid = g4cfg[1] <= 2 ? g4cfg[1] : 0;
	g4shadow = g4cfg[6] <= 3 ? g4cfg[6] : 2;
	g4size = 1;
	for (int i = 0; i < 4; i++)
		if (g4cfg[26] == sizeSak[i]) g4size = i;
	g4sel = 0;
	static const Screen gen4Screen = { NULL, gen4Input, gen4Draw };
	appScreen(&gen4Screen);
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

static const Screen filesScreen = { filesScan, filesInput, filesDraw }; // rescanned: the editor may have saved one

// --- menu and family ---

static int dictKeys;

static void openFiles(void)
{
	appScreen(&filesScreen);
}

static const MenuEntry mfcEntries[] = {
	{ "Scan card", "Read the card's UID, ATQA/SAK and magic generation (Gen1a, Gen4 GTU, USCUID) and the GTU / "
	               "USCUID config.", startScan },
	{ "Read card", "Dump every sector. Keys from the dictionary, then the nested and static-nonce attacks and the "
	               "magic backdoors. Saved to the SD card and opened in the editor.", startRead },
	{ "Saved dumps", "View and edit dumps, write them onto magic cards.", openFiles },
};

static void mfcExtra(float y)
{
	uiText(12, y, S_SMALL, uiCol[COL_DIM], "Dictionary: %d keys (defaults + " MF_KEYS ")", dictKeys);
	if (sc.uidLen) {
		char uid[32];
		uidHex(&sc, uid, "");
		uiText(12, y + SMALL_H, S_SMALL, uiCol[COL_DIM], "Last card: %s, %s", uid, cardTypeName(&sc));
	}
}

static Menu mfcMenu = { "MIFARE Classic", mfcEntries, sizeof(mfcEntries) / sizeof(mfcEntries[0]), mfcExtra };

static void mfcMenuShow(void)
{
	static u8 keys[MF_MAX_KEYS][6];
	dictKeys = mfKeyList(keys, MF_MAX_KEYS, NULL, 0);
}

static void mfcMenuInput(u32 kDown, u32 kRepeat)
{
	menuInput(&mfcMenu, kDown, kRepeat);
}

static void mfcMenuDraw(void)
{
	menuDraw(&mfcMenu);
}

static void mfcOpenMenu(void)
{
	static const Screen s = { mfcMenuShow, mfcMenuInput, mfcMenuDraw };
	appScreen(&s);
}

// Classic and what talks Classic: SAK bit 3 (Mini/1K/2K/4K, Infineon, SmartMX emulation).
static bool mfcMatch(const Card *c)
{
	switch (c->sak) {
	case 0x08: case 0x09: case 0x18: case 0x19: case 0x88: case 0x28: case 0x38: return true;
	}
	return false;
}

const CardFamily mfcFamily = {
	"MIFARE Classic",
	"Mini / 1K / 2K / 4K: read with key recovery, dump editor, magic cards (Gen1a, Gen2, Gen4 GTU, USCUID).",
	mfcMatch, mfcProbe, mfcShow, mfcOpenMenu,
};
