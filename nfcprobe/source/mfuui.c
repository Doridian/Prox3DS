// MIFARE Ultralight / NTAG family: its menu (scan, read, saved dumps), card screen, writing a dump's
// user pages back onto a card and the dump list. The page editor is in mfuedit.c.

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <3ds.h>

#include "app.h"
#include "mfu.h"
#include "probe.h"
#include "ui.h"

// --- card screen ---

static Card sc;
static MfuDump sm; // identify + pages 0-3 + the config pages, for the card screen
static bool smGtu;  // a Gen4 GTU (in Ultralight mode, or it would not be here)
static int scanResult;

static const Screen cardScreen;

static int mfuProbe(void)
{
	sc = card;
	u8 buf[16];
	int r = mfuIdentify(&sm.info);
	memset(sm.valid, 0, sizeof(sm.valid));
	if (r <= 0) return r;
	const MfuType *t = sm.info.type;
	sm.pages = t->pages;
	int want[2] = { 0, t->cfg ? t->cfg : t == &mfuTypeULC ? 0x28 : -1 };
	for (int i = 0; i < 2; i++) {
		if (want[i] < 0) continue;
		if ((r = mfuRead(want[i], buf)) < 0) return -1;
		for (int k = 0; r && k < 4 && want[i] + k < t->pages; k++) {
			memcpy(sm.data[want[i] + k], buf + 4 * k, 4);
			sm.valid[want[i] + k] = true;
		}
	}
	u8 cfg[32];
	if ((r = mfGen4Config(mfGen4DefaultPwd, cfg, sizeof(cfg))) < 0) return -1;
	smGtu = r > 0;
	return 1;
}

static void runScan(void)
{
	scanResult = 0;
	if (cardWait()) scanResult = mfuProbe();
	iso14aParity(true);
}

static void mfuShow(void)
{
	appScreen(&cardScreen);
}

static void doneScan(void)
{
	if (scanResult > 0) mfuShow();
	else if (scanResult < 0) msgBox("Scan", "The chip stopped answering.\nTry again.");
	else if (!mfCancel) msgBox("Scan", "No Ultralight / NTAG answer:\n%s", mfuWhy());
}

static void startScan(void)
{
	jobStart("Scanning", runScan, doneScan, true);
}

static MfuDump rd;
static char rdPath[128];
static int rdResult;

static void runRead(void)
{
	rdResult = -2;
	rdPath[0] = 0;
	if (!cardWait()) return;
	sc = card;
	rdResult = mfuDumpCard(&rd, NULL);
	iso14aParity(true);
	if (rdResult > 0 && mfuSaveDump(&rd, rdPath, sizeof(rdPath))) logp("saved %s\n", rdPath);
}

static void doneRead(void)
{
	if (rdResult == -2) return;
	if (rdResult < 0) {
		msgBox("Read card", "Lost the card (or the chip stopped answering).");
		return;
	}
	if (!rdResult) {
		msgBox("Read card", "No Ultralight / NTAG answer:\n%s", mfuWhy());
		return;
	}
	int got = 0;
	for (int p = 0; p < rd.pages; p++) got += rd.valid[p];
	mfuEditorOpen(&rd, rdPath);
	msgBox(mfCancel ? "Read card (stopped)" : "Read card", "%s: %d/%d pages read.%s\n%s", rd.info.type->name,
		got, rd.pages, got < rd.pages ? "\nThe rest is password-protected." : "",
		rdPath[0] ? rdPath : "Could not save the dump to the SD card!");
}

static void startRead(void)
{
	jobStart("Reading card", runRead, doneRead, true);
}

// Static lock bits (page 2 bytes 2-3): which of pages 3-15 are read-only.
static void lockedPages(const u8 *p2, char *out, u32 max)
{
	int n = 0;
	*out = 0;
	for (int pg = 3; pg < 16; pg++) {
		int bit = pg == 3 ? 0 : pg < 8 ? pg : pg - 8; // page 3 = L-OTP (byte 2 bit 3)
		bool locked = pg == 3 ? p2[2] & 0x08 : pg < 8 ? p2[2] >> bit & 1 : p2[3] >> bit & 1;
		if (locked) n += snprintf(out + n, max - n, "%s%d", n ? " " : "", pg);
		if ((u32)n >= max) break;
	}
	if (!n) snprintf(out, max, "none");
}

static void cardDraw(void)
{
	const MfuInfo *in = &sm.info;
	const MfuType *t = in->type;
	char hdr[48], s[80];
	snprintf(hdr, sizeof(hdr), "ATQA %02X%02X  SAK %02X", sc.atqa[1], sc.atqa[0], sc.sak);
	uiHeader("Ultralight / NTAG: card", hdr);
	float y = 28;
	uidHex(&sc, s, " ");
	uiText(12, y, S_SMALL, uiCol[COL_DIM], "UID (%d bytes)", sc.uidLen);
	uiText(12, y + 12, 0.8f, uiCol[COL_ACCENT], "%s", s);
	y += 40;
	uiText(12, y, S_BODY, uiCol[COL_TEXT], "%s", t->name);
	if (t->userEnd > 4)
		uiText(12, y + LINE_H, S_SMALL, uiCol[COL_DIM], "%d pages, user memory %d-%d (%d bytes)", t->pages, 4,
			t->userEnd - 1, 4 * (t->userEnd - 4));
	else
		uiText(12, y + LINE_H, S_SMALL, uiCol[COL_DIM], "Unknown layout: up to %d pages", t->pages);
	y += LINE_H + SMALL_H + 4;
	u32 txt = uiCol[COL_TEXT], dim = uiCol[COL_DIM];
	uiRect(8, y, UI_W - 16, 8 * SMALL_H + 6, uiCol[COL_PANEL]);
	y += 3;
	if (in->hasVersion)
		uiText(14, y, S_SMALL, txt, "Version %02X%02X%02X%02X%02X%02X%02X%02X", in->version[0], in->version[1],
			in->version[2], in->version[3], in->version[4], in->version[5], in->version[6], in->version[7]);
	else
		uiText(14, y, S_SMALL, dim, "No GET_VERSION (Ultralight, Ultralight C or NTAG203)");
	if (smGtu) uiTextRight(UI_W - 14, y, S_SMALL, uiCol[COL_OK], "Magic: Gen4 GTU");
	y += SMALL_H;
	if (in->hasSig) {
		uiText(14, y, S_SMALL, txt, "Signature");
		for (int h = 0; h < 2; h++, y += SMALL_H) {
			for (int i = 0; i < 16; i++) sprintf(s + 2 * i, "%02X", in->sig[16 * h + i]);
			uiMonoS(80, y + 1, 0.36f, 6.0f, txt, s);
		}
	} else {
		uiText(14, y, S_SMALL, dim, "Signature: %s", t->pwd ? "no answer" : "none on this type");
		y += 2 * SMALL_H;
	}
	if (t->counters || t->tearing) {
		float x = uiText(14, y, S_SMALL, txt, "Counters");
		for (int i = 0; i < 3; i++) {
			if (!(t->counters & 1 << i)) continue;
			const u8 *c = in->cnt[i];
			if (in->cntOk & 1 << i) x += uiText(14 + x, y, S_SMALL, txt, "   %d: %lu", i, (u32)(c[0] | c[1] << 8 | c[2] << 16));
			else x += uiText(14 + x, y, S_SMALL, dim, "   %d: off", i);
			if ((in->tearOk & 1 << i) && c[3] != 0xBD) // BD = intact
				x += uiText(14 + x, y, S_SMALL, uiCol[COL_WARN], " torn (%02X)", c[3]);
		}
	} else {
		uiText(14, y, S_SMALL, dim, "No READ_CNT counters on this type");
	}
	y += SMALL_H;
	if (sm.valid[2]) {
		const u8 *p0 = sm.data[0], *p1 = sm.data[1], *p2 = sm.data[2], *p3 = sm.data[3];
		bool bcc0 = (0x88 ^ p0[0] ^ p0[1] ^ p0[2]) == p0[3], bcc1 = (p1[0] ^ p1[1] ^ p1[2] ^ p1[3]) == p2[0];
		uiText(14, y, S_SMALL, bcc0 && bcc1 ? txt : uiCol[COL_WARN], "BCC0 %02X %s   BCC1 %02X %s", p0[3], bcc0 ? "ok" : "BAD", p2[0],
			bcc1 ? "ok" : "BAD");
		y += SMALL_H;
		char locked[64];
		lockedPages(p2, locked, sizeof(locked));
		uiText(14, y, S_SMALL, txt, "Lock bytes %02X%02X: read-only pages %s", p2[2], p2[3], locked);
		y += SMALL_H;
		if (p3[0] == 0xE1)
			uiText(14, y, S_SMALL, txt, "CC %02X%02X%02X%02X: NDEF %d.%d, %d bytes, %s", p3[0], p3[1], p3[2], p3[3],
				p3[1] >> 4, p3[1] & 0xF, p3[2] * 8, p3[3] == 0 ? "read/write" : p3[3] == 0x0F ? "read-only" : "access ?");
		else
			uiText(14, y, S_SMALL, txt, "OTP %02X%02X%02X%02X", p3[0], p3[1], p3[2], p3[3]);
	} else {
		uiText(14, y, S_SMALL, uiCol[COL_WARN], "Pages 0-3 did not read");
		y += 2 * SMALL_H;
	}
	y += SMALL_H;
	if (t->cfg && sm.valid[t->cfg]) {
		const u8 *c0 = sm.data[t->cfg], *c1 = sm.data[t->cfg + 1];
		int lim = c1[0] & 7;
		char prot[40];
		if (c0[3] >= t->pages) snprintf(prot, sizeof(prot), "no password");
		else snprintf(prot, sizeof(prot), "%s from page %d", c1[0] & 0x80 ? "r/w protected" : "write protected", c0[3]);
		uiText(14, y, S_SMALL, txt, "AUTH0 %02X: %s   config %s   AUTHLIM %d%s", c0[3], prot,
			c1[0] & 0x40 ? "locked" : "open", lim, lim ? "" : " (off)");
	} else if (t->cfg) {
		uiText(14, y, S_SMALL, uiCol[COL_WARN], "Config pages %d-%d read-protected (AUTH0 <= %d, PROT)", t->cfg,
			t->cfg + 3, t->cfg);
	} else if (t == &mfuTypeULC && sm.valid[0x2A]) {
		const u8 *a0 = sm.data[0x2A], *a1 = sm.data[0x2B];
		uiText(14, y, S_SMALL, txt, "AUTH0 %02X: %s", a0[0], a0[0] >= 0x30 ? "no 3DES auth needed" :
			a1[0] & 1 ? "writes need 3DES auth" : "reads + writes need 3DES auth");
	} else {
		uiText(14, y, S_SMALL, dim, "No config pages on this type");
	}
	uiFooter(BTN_A " scan again   " BTN_X " read card   " BTN_B " back");
}

static void cardInput(u32 kDown, u32 kRepeat)
{
	if (kDown & KEY_A) startScan();
	if (kDown & KEY_X) startRead();
	if (kDown & KEY_B) appBack();
}

static const Screen cardScreen = { NULL, cardInput, cardDraw };

// --- write a dump's user pages onto a card ---

static MfuDump wr;
static int wrResult, wrPages;
static char wrWhy[64];

static void runRestore(void)
{
	wrResult = -2;
	if (!cardWait()) return;
	wrResult = mfuRestore(&wr, &wrPages);
	snprintf(wrWhy, sizeof(wrWhy), "%s", mfuWhy());
	iso14aParity(true);
	logp("restore: %d pages written, %s\n", wrPages, wrResult == 1 ? "done" : wrWhy);
}

static void doneRestore(void)
{
	if (wrResult == -2) return;
	if (wrResult == 1)
		msgBox("Write to card", wrPages ? "Done: %d page%s written and read back,\nthe rest already matched."
		                                : "Nothing to write: every user page already matches.", wrPages, wrPages == 1 ? "" : "s");
	else if (wrResult < 0) msgBox("Write to card", "The chip stopped answering after %d page%s.", wrPages, wrPages == 1 ? "" : "s");
	else msgBox("Write to card", "Stopped after %d page%s: %s", wrPages, wrPages == 1 ? "" : "s", wrWhy);
}

void mfuRestoreStart(const MfuDump *d)
{
	if (d != &wr) wr = *d;
	jobStart("Writing to card", runRestore, doneRestore, true);
}

// --- clone onto a magic card ---

static MfuDump cl;
static int clResult;
static char clWhy[64];

static void runClone(void)
{
	clResult = -2;
	if (!cardWait()) return;
	clResult = mfuCloneToGtu(&cl);
	snprintf(clWhy, sizeof(clWhy), "%s", mfuWhy());
	iso14aParity(true);
	logp("clone: %s\n", clResult == 1 ? "done" : clWhy);
}

static void doneClone(void)
{
	if (clResult == -2) return;
	if (clResult == 1) msgBox("Write to magic card", "Done: the GTU now reads back as this %s.", cl.info.type->name);
	else if (clResult < 0) msgBox("Write to magic card", "The chip stopped answering.\nThe card may be half written.");
	else msgBox("Write to magic card", "Not done: %s", clWhy);
}

static void mfuCloneGo(void)
{
	mfuCloneStart(&cl);
}

void mfuCloneStart(const MfuDump *d)
{
	if (d != &cl) cl = *d;
	jobStart("Writing to magic card", runClone, doneClone, true);
}

void mfuCloneAsk(const MfuDump *d, const char *name)
{
	cl = *d;
	if (!cl.info.type) {
		msgBox("Write to magic card", "%s: unknown card type (no version, odd size).", name);
		return;
	}
	confirm("Write to magic card", mfuCloneGo, "Clone %s onto the Gen4 GTU on the reader?\n"
		"It becomes a %s: UID, version, signature,\nevery page. Everything on it is overwritten.", name, cl.info.type->name);
}

// --- saved dumps ---

typedef struct {
	char name[64];
	int size, pages; // pages 0: not a dump
	u64 mtime;
} FileEnt;
static FileEnt files[200];
static int nfiles;
static UiList fl;
static MfuDump ld;

static int fileCmp(const void *a, const void *b)
{
	const FileEnt *x = a, *y = b;
	return x->mtime < y->mtime ? 1 : x->mtime > y->mtime ? -1 : strcmp(x->name, y->name);
}

static void filesScan(void)
{
	nfiles = 0;
	DIR *dir = opendir(MFU_DIR);
	struct dirent *e;
	while (dir && (e = readdir(dir)) && nfiles < 200) {
		int len = strlen(e->d_name);
		if (len < 5 || len >= 64 || strcasecmp(e->d_name + len - 4, ".bin")) continue;
		FileEnt *f = &files[nfiles];
		char path[128];
		snprintf(path, sizeof(path), MFU_DIR "/%s", e->d_name);
		struct stat st;
		if (stat(path, &st)) continue;
		snprintf(f->name, sizeof(f->name), "%s", e->d_name);
		f->size = st.st_size;
		f->pages = 0;
		u8 hdr[12];
		FILE *fp = fopen(path, "rb");
		if (fp && fread(hdr, 1, 12, fp) == 12 && f->size - MFU_HDR == 4 * (hdr[11] + 1)) f->pages = hdr[11] + 1;
		else if (f->size % 4 == 0 && f->size >= 64 && f->size <= 4 * MFU_MAX_PAGES) f->pages = f->size / 4;
		if (fp) fclose(fp);
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
	snprintf(out, max, MFU_DIR "/%s", files[fl.sel].name);
}

static void fileDelete(void)
{
	char path[128], tpath[140];
	filePath(path, sizeof(path));
	snprintf(tpath, sizeof(tpath), "%.*s.txt", (int)strlen(path) - 4, path);
	remove(path);
	remove(tpath);
	toast("Deleted %s", files[fl.sel].name);
	filesScan();
}

static void fileRestore(void)
{
	mfuRestoreStart(&ld);
}

static void fileRestoreAsk(void)
{
	confirm("Write to card", fileRestore, "Write the user pages of %s\nonto the card on the reader? Its user memory is overwritten.\n"
		"Lock bits, OTP and config are left alone.", files[fl.sel].name);
}

static void fileCloneAsk(void)
{
	mfuCloneAsk(&ld, files[fl.sel].name);
}

static void filesInput(u32 kDown, u32 kRepeat)
{
	uiListNav(&fl, nfiles, 12, kRepeat);
	if (kDown & KEY_B) appBack();
	if (!nfiles) return;
	char path[128];
	filePath(path, sizeof(path));
	if (kDown & (KEY_A | KEY_X)) {
		if (!mfuLoadDump(&ld, path)) {
			msgBox("Saved dumps", "%s is not an Ultralight / NTAG dump\n(%d bytes).", files[fl.sel].name, files[fl.sel].size);
			return;
		}
		if (kDown & KEY_A) {
			mfuEditorOpen(&ld, path);
			return;
		}
		static const MenuItem items[] = { { "Write user pages to card", fileRestoreAsk },
			{ "Clone onto magic card (GTU)", fileCloneAsk } };
		popup(files[fl.sel].name, items, 2);
	}
	if (kDown & KEY_Y) confirm("Delete", fileDelete, "Delete %s?", files[fl.sel].name);
}

static void filesDraw(void)
{
	char hdr[32];
	snprintf(hdr, sizeof(hdr), "%d dump%s", nfiles, nfiles == 1 ? "" : "s");
	uiHeader("Saved Ultralight / NTAG dumps", hdr);
	if (!nfiles) {
		uiTextCenter(UI_W / 2, 100, S_BODY, uiCol[COL_DIM], "No dumps yet.");
		uiTextCenter(UI_W / 2, 118, S_SMALL, uiCol[COL_DIM], "Read a card, or copy pm3 .bin dumps to " MFU_DIR);
		uiFooter(BTN_B " back");
		return;
	}
	for (int i = 0; i < 12 && fl.top + i < nfiles; i++) {
		const FileEnt *f = &files[fl.top + i];
		float y = 24 + i * LINE_H;
		if (fl.top + i == fl.sel) uiRect(4, y - 1, UI_W - 8, LINE_H, uiCol[COL_SEL]);
		char name[64];
		snprintf(name, sizeof(name), "%s", f->name);
		uiText(10, y, S_BODY, uiCol[COL_TEXT], "%s", uiFit(name, 190, S_BODY)); // up to the size column
		uiTextRight(268, y + 1, S_SMALL, uiCol[f->pages ? COL_ACCENT : COL_ERR], f->pages ? "%d pages" : "not MFU", f->pages);
		if (f->mtime) {
			time_t t = f->mtime;
			struct tm *tm = gmtime(&t);
			uiTextRight(UI_W - 10, y + 1, S_SMALL, uiCol[COL_DIM], "%04d-%02d-%02d %02d:%02d", tm->tm_year + 1900,
				tm->tm_mon + 1, tm->tm_mday, tm->tm_hour, tm->tm_min);
		}
	}
	if (nfiles > 12) uiTextRight(UI_W - 6, UI_H - 34, S_SMALL, uiCol[COL_DIM], "%d-%d of %d", fl.top + 1,
		fl.top + 12 < nfiles ? fl.top + 12 : nfiles, nfiles);
	uiFooter(BTN_A " open   " BTN_X " write to card   " BTN_Y " delete   " BTN_B " back");
}

static const Screen filesScreen = { filesScan, filesInput, filesDraw };

// --- menu and family ---

static void openFiles(void)
{
	appScreen(&filesScreen);
}

static const MenuEntry mfuEntries[] = {
	{ "Scan card", "Type (GET_VERSION), originality signature, counters and tearing flags, lock bits, OTP / "
	               "capability container and the password config.", startScan },
	{ "Read card", "Dump every readable page (a password-protected area stays unread). Saved to the SD card "
	               "in pm3's format and opened in the editor.", startRead },
	{ "Saved dumps", "View and edit dumps, write their user memory back onto a card, or clone them onto a Gen4 GTU.", openFiles },
};

static void mfuExtra(float y)
{
	uiText(12, y, S_SMALL, uiCol[COL_DIM], "Dumps: " MFU_DIR " (pm3 hf mfu .bin)");
	if (sc.uidLen) menuLastCard(y + SMALL_H, &sc, sm.info.type ? sm.info.type->name : cardTypeName(&sc));
}

static Menu mfuMenu = { "Ultralight / NTAG", mfuEntries, sizeof(mfuEntries) / sizeof(mfuEntries[0]), mfuExtra };

static void mfuMenuInput(u32 kDown, u32 kRepeat)
{
	menuInput(&mfuMenu, kDown, kRepeat);
}

static void mfuMenuDraw(void)
{
	menuDraw(&mfuMenu);
}

static void mfuOpenMenu(void)
{
	static const Screen s = { NULL, mfuMenuInput, mfuMenuDraw };
	appScreen(&s);
}

// Type 2 tags: SAK 00 (no Classic, no ISO14443-4).
static bool mfuMatch(const Card *c)
{
	return c->sak == 0x00;
}

const CardFamily mfuFamily = {
	"Ultralight / NTAG",
	"MIFARE Ultralight (EV1, C), NTAG21x and other type 2 tags: info, read, page editor, write user memory back, clone onto a Gen4 GTU.",
	mfuMatch, mfuProbe, mfuShow, mfuOpenMenu,
};
