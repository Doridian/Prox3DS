// Ultralight / NTAG dump viewer / editor: one page per row (hex, ASCII and what the page is for), the
// page under the cursor decoded below (UID and BCCs, lock bits, OTP / capability container, config,
// password). Bytes are edited a nibble at a time with the D-pad; only user memory goes to a card.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <3ds.h>

#include "app.h"
#include "dumplist.h"
#include "mfu.h"
#include "probe.h"
#include "ui.h"

#define VIS_ROWS 11
#define ROW_H    13
#define GRID_Y   26
#define HEX_X    64
#define BYTE_W   20
#define ASCII_X  152
#define ROLE_X   196

static MfuDump d, orig;
static char path[160];
static int page, col, top;
static bool editing;
static int nib;
static u8 clip[4];
static bool clipOk;

static const MfuType *type(void) { return d.info.type; }
static int userEnd(void) { return type() ? type()->userEnd : d.pages; }
static bool isUser(int p) { return p >= 4 && p < userEnd(); }

static bool changed(int p)
{
	return d.valid[p] != orig.valid[p] || (d.valid[p] && memcmp(d.data[p], orig.data[p], 4));
}

static bool dirty(void)
{
	for (int p = 0; p < d.pages; p++)
		if (changed(p)) return true;
	return false;
}

static const char *baseName(void)
{
	const char *s = strrchr(path, '/');
	return s ? s + 1 : path;
}

// Static lock bits in page 2: pages 3 (L-OTP) to 15.
static bool locked(int p)
{
	if (!d.valid[2] || p < 3 || p > 15) return false;
	const u8 *l = d.data[2] + 2;
	return p == 3 ? l[0] & 0x08 : p < 8 ? l[0] >> p & 1 : l[1] >> (p - 8) & 1;
}

static const char *role(int p)
{
	const MfuType *t = type();
	if (p == 0) return "UID 0-2, BCC0";
	if (p == 1) return "UID 3-6";
	if (p == 2) return "BCC1, internal, lock";
	if (p == 3) return d.valid[3] && d.data[3][0] == 0xE1 ? "capability container" : "OTP";
	if (isUser(p)) return "user memory";
	if (!t) return "";
	if (t->dynLock && p == t->dynLock) return "dynamic lock";
	if (t->cfg && p >= t->cfg && p < t->cfg + 4) {
		static const char *cfg[] = { "CFG0 (AUTH0)", "CFG1 (ACCESS)", "PWD", "PACK" };
		return cfg[p - t->cfg];
	}
	if (t->userEnd == 0x28 && p == 0x28) return "lock bytes 2-3";
	if (t->userEnd == 0x28 && p == 0x29) return "counter";
	if (t == &mfuTypeULC && p == 0x2A) return "AUTH0";
	if (t == &mfuTypeULC && p == 0x2B) return "AUTH1";
	if (t == &mfuTypeULC && p >= 0x2C) return "3DES key";
	return "";
}

static void editorInput(u32 kDown, u32 kRepeat);
static void editorDraw(void);

void mfuEditorOpen(const MfuDump *src, const char *p)
{
	d = *src;
	orig = d;
	snprintf(path, sizeof(path), "%s", p);
	page = col = top = 0;
	editing = false;
	static const Screen s = { NULL, editorInput, editorDraw };
	appScreen(&s);
}

// --- actions ---

static void save(void)
{
	if (!mfuWriteDump(&d, path)) {
		msgBox("Save", "Could not write %s", path);
		return;
	}
	orig = d;
	dumpForget(path);
	toast("Saved %s", baseName());
}

static void saveCopy(void)
{
	char base[128], np[160];
	snprintf(base, sizeof(base), "%.*s", (int)strlen(path) - 4, path);
	char *dash = strrchr(base, '-'), *slash = strrchr(base, '/');
	if (dash && dash > slash) { // drop an old -N
		char *e;
		strtol(dash + 1, &e, 10);
		if (e != dash + 1 && !*e) *dash = 0;
	}
	struct stat st;
	int i = 2;
	do snprintf(np, sizeof(np), "%s-%d.bin", base, i++);
	while (!stat(np, &st) && i < 1000);
	mkdir(APP_DIR, 0777);
	mkdir(MFU_DIR, 0777);
	snprintf(path, sizeof(path), "%s", np);
	save();
}

static u8 wpData[4];
static int wpPage, wpResult;
static char wpWhy[64];

static void runWritePage(void)
{
	wpResult = -2;
	if (!cardWait()) return;
	MfuInfo info;
	wpResult = mfuIdentify(&info);
	if (wpResult > 0 && mfuWriteAuth(info.type, &d) < 0) wpResult = -1;
	if (wpResult > 0) wpResult = mfuWritePage(info.type, wpPage, wpData);
	snprintf(wpWhy, sizeof(wpWhy), "%s", mfuWhy());
	iso14aParity(true);
	logp("write page %d: %s\n", wpPage, wpResult == 1 ? "ok" : wpWhy);
}

static void doneWritePage(void)
{
	if (wpResult == -2) return;
	if (wpResult == 1) msgBox("Write page", "Page %d written and read back.", wpPage);
	else if (wpResult < 0) msgBox("Write page", "The chip stopped answering.");
	else msgBox("Write page", "Page %d not written: %s", wpPage, wpWhy);
}

static void writePageGo(void)
{
	jobStart("Writing page", runWritePage, doneWritePage, true);
}

static void writePage(void)
{
	if (!d.valid[page]) {
		msgBox("Write page", "Page %d was never read: nothing to write.", page);
		return;
	}
	memcpy(wpData, d.data[page], 4);
	wpPage = page;
	confirm("Write page", writePageGo, "Write page %d (%02X%02X%02X%02X) to the card on the reader?", page,
		wpData[0], wpData[1], wpData[2], wpData[3]);
}

static void copyPage(void)
{
	memcpy(clip, d.data[page], 4);
	clipOk = true;
	toast("Page %d copied", page);
}

static void pastePage(void)
{
	memcpy(d.data[page], clip, 4);
	d.valid[page] = true;
}

static void revertPage(void)
{
	memcpy(d.data[page], orig.data[page], 4);
	d.valid[page] = orig.valid[page];
}

static void revertAll(void)
{
	d = orig;
}

static void back(void)
{
	appBack();
}

static void actions(void)
{
	static char wlabel[32];
	snprintf(wlabel, sizeof(wlabel), "Write page %d to card", page);
	MenuItem items[16];
	int n = 0;
	items[n++] = (MenuItem){ "Save", save };
	items[n++] = (MenuItem){ "Save as a copy", saveCopy };
	if (isUser(page)) items[n++] = (MenuItem){ wlabel, writePage };
	items[n++] = (MenuItem){ "Copy page", copyPage };
	if (clipOk) items[n++] = (MenuItem){ "Paste page", pastePage };
	items[n++] = (MenuItem){ "Revert page", revertPage };
	items[n++] = (MenuItem){ "Revert all changes", revertAll };
	n += mfuDumpActions(items + n, &d, baseName());
	popup("Dump", items, n);
}

// --- input ---

static void setNibble(int dv)
{
	u8 *p = &d.data[page][col];
	if (!d.valid[page]) {
		memset(d.data[page], 0, 4);
		d.valid[page] = true;
	}
	int sh = nib ? 0 : 4, v = ((*p >> sh) + dv) & 0xF;
	*p = (*p & ~(0xF << sh)) | v << sh;
}

static void movePage(int dp)
{
	page = (page + dp + d.pages) % d.pages;
}

static void editorInput(u32 kDown, u32 kRepeat)
{
	if (editing) {
		if (kRepeat & KEY_UP) setNibble(1);
		if (kRepeat & KEY_DOWN) setNibble(-1);
		if (kRepeat & KEY_LEFT) {
			if (nib) nib = 0;
			else if (col > 0) col--, nib = 1;
		}
		if (kRepeat & KEY_RIGHT) {
			if (!nib) nib = 1;
			else if (col < 3) col++, nib = 0;
		}
		if (kDown & (KEY_A | KEY_B)) editing = false;
		return;
	}
	if (kRepeat & KEY_UP) movePage(-1);
	if (kRepeat & KEY_DOWN) movePage(1);
	if (kRepeat & KEY_LEFT) {
		if (--col < 0) col = 3, movePage(-1);
	}
	if (kRepeat & KEY_RIGHT) {
		if (++col > 3) col = 0, movePage(1);
	}
	if (kRepeat & KEY_L) page = page >= VIS_ROWS ? page - VIS_ROWS : 0;
	if (kRepeat & KEY_R) page = page + VIS_ROWS < d.pages ? page + VIS_ROWS : d.pages - 1;
	if (page < top) top = page;
	if (page >= top + VIS_ROWS) top = page - VIS_ROWS + 1;
	if (kDown & KEY_A) {
		editing = true;
		nib = 0;
	}
	if (kDown & KEY_X) actions();
	if (kDown & KEY_Y) copyPage();
	if (kDown & KEY_B) {
		if (dirty()) confirm("Close dump", back, "Drop the unsaved changes?");
		else back();
	}
}

// --- drawing ---

static void drawInfo(float y)
{
	const MfuType *t = type();
	const u8 *p = d.data[page];
	float x = 10;
	u32 txt = uiCol[COL_TEXT], dim = uiCol[COL_DIM], acc = uiCol[COL_ACCENT];
	uiRect(4, y, UI_W - 8, UI_H - 20 - y - 2, uiCol[COL_PANEL]);
	y += 3;
	if (changed(page)) uiTextRight(UI_W - 10, y, S_SMALL, uiCol[COL_CHANGED], "modified");
	if (!d.valid[page]) {
		uiText(x, y, S_SMALL, dim, "Page %d was not read (password-protected, or not readable at all).", page);
		uiText(x, y + SMALL_H, S_SMALL, dim, "Editing it adds it to the dump.");
		return;
	}
	if (page <= 2 && d.valid[0] && d.valid[1]) {
		const u8 *a = d.data[0], *b = d.data[1];
		u8 bcc0 = 0x88 ^ a[0] ^ a[1] ^ a[2], bcc1 = b[0] ^ b[1] ^ b[2] ^ b[3];
		uiText(x, y, S_SMALL, acc, "UID %02X%02X%02X%02X%02X%02X%02X%s", a[0], a[1], a[2], b[0], b[1], b[2], b[3],
			a[0] == 0x04 ? " (NXP)" : "");
		y += SMALL_H;
		if (bcc0 == a[3]) uiText(x, y, S_SMALL, txt, "BCC0 %02X ok", a[3]);
		else uiText(x, y, S_SMALL, uiCol[COL_WARN], "BCC0 %02X BAD (should be %02X)", a[3], bcc0);
		if (d.valid[2]) {
			const u8 *c = d.data[2];
			if (bcc1 == c[0]) uiText(x + 170, y, S_SMALL, txt, "BCC1 %02X ok", c[0]);
			else uiText(x + 170, y, S_SMALL, uiCol[COL_WARN], "BCC1 %02X BAD (should be %02X)", c[0], bcc1);
			y += SMALL_H;
			if (page == 2) {
				int n = 0;
				char lk[64] = "";
				for (int q = 3; q < 16; q++)
					if (locked(q)) n += snprintf(lk + n, sizeof(lk) - n, "%s%d", n ? " " : "", q);
				uiText(x, y, S_SMALL, txt, "Lock %02X%02X: read-only pages %s%s", c[2], c[3], n ? lk : "none",
					c[2] & 7 ? "   (block-lock bits set)" : "");
			} else {
				uiText(x, y, S_SMALL, dim, "Only magic cards take a new UID; page 2 has the lock bits.");
			}
		}
		return;
	}
	if (page == 3) {
		if (p[0] == 0xE1) {
			uiText(x, y, S_SMALL, acc, "Capability container (NDEF)");
			uiText(x, y + SMALL_H, S_SMALL, txt, "Version %d.%d, data area %d bytes, %s", p[1] >> 4, p[1] & 0xF, p[2] * 8,
				p[3] == 0 ? "read/write" : p[3] == 0x0F ? "read-only" : "unknown access");
		} else {
			uiText(x, y, S_SMALL, acc, "OTP (one-time programmable)");
			uiText(x, y + SMALL_H, S_SMALL, txt, "Bits only turn on: a written 1 can never be cleared.");
		}
		uiText(x, y + 2 * SMALL_H, S_SMALL, dim, "%s", locked(3) ? "Locked (L-OTP)." : "Not written to cards from here.");
		return;
	}
	if (isUser(page)) {
		uiText(x, y, S_SMALL, acc, "User memory, page %d of %d-%d", page, 4, userEnd() - 1);
		if (locked(page)) uiText(x, y + SMALL_H, S_SMALL, uiCol[COL_WARN], "Locked by the static lock bits: the card refuses writes.");
		else uiText(x, y + SMALL_H, S_SMALL, dim, BTN_X " writes it, or every user page, to the card on the reader.");
		return;
	}
	if (t && t->cfg && page == t->cfg) {
		uiText(x, y, S_SMALL, acc, "CFG0: byte 0 %02X (mirror / mode), mirror page %02X", p[0], p[2]);
		uiText(x, y + SMALL_H, S_SMALL, txt, p[3] >= t->pages ? "AUTH0 %02X: no password protection" :
			"AUTH0 %02X: the password guards page %d on", p[3], p[3]);
		uiText(x, y + 2 * SMALL_H, S_SMALL, dim, "Config: never written to cards from here.");
		return;
	}
	if (t && t->cfg && page == t->cfg + 1) {
		int lim = p[0] & 7;
		uiText(x, y, S_SMALL, acc, "CFG1: ACCESS %02X", p[0]);
		uiText(x, y + SMALL_H, S_SMALL, txt, "PROT %d (password for %s)   CFGLCK %d   AUTHLIM %d%s", p[0] >> 7,
			p[0] & 0x80 ? "reads + writes" : "writes", p[0] >> 6 & 1, lim, lim ? "" : " (off)");
		uiText(x, y + 2 * SMALL_H, S_SMALL, dim, "NFC_CNT_EN %d   NFC_CNT_PWD_PROT %d (NTAG)", p[0] >> 4 & 1, p[0] >> 3 & 1);
		return;
	}
	if (t && t->cfg && page >= t->cfg + 2 && page < t->cfg + 4) {
		uiText(x, y, S_SMALL, acc, page == t->cfg + 2 ? "Password %02X%02X%02X%02X" : "PACK %02X%02X (password ack)", p[0],
			p[1], p[2], p[3]);
		uiText(x, y + SMALL_H, S_SMALL, dim, "Write-only: a card reads it as 00. Filled in when read with the password.");
		return;
	}
	if (t == &mfuTypeULC && page >= 0x2A) {
		if (page == 0x2A) uiText(x, y, S_SMALL, acc, "AUTH0 %02X: 3DES auth needed from page %d%s", p[0], p[0],
			p[0] >= 0x30 ? " (off)" : "");
		else if (page == 0x2B) uiText(x, y, S_SMALL, acc, "AUTH1 %02X: %s", p[0], p[0] & 1 ? "writes need auth" : "reads + writes need auth");
		else uiText(x, y, S_SMALL, acc, "3DES key, part %d (write-only)", page - 0x2C + 1);
		return;
	}
	if (t && t->userEnd == 0x28 && page == 0x29) {
		uiText(x, y, S_SMALL, acc, "16-bit one-way counter: %d", p[0] | p[1] << 8);
		return;
	}
	uiText(x, y, S_SMALL, acc, "%s", *role(page) ? role(page) : "Page");
	uiText(x, y + SMALL_H, S_SMALL, dim, "Not written to cards from here.");
}

static void editorDraw(void)
{
	char title[176], right[64];
	snprintf(title, sizeof(title), "%s%s", baseName(), dirty() ? " *" : "");
	snprintf(right, sizeof(right), "%s", type() ? type()->name : "unknown type");
	uiHeader(title, right);
	int vis = d.pages < VIS_ROWS ? d.pages : VIS_ROWS;
	for (int r = 0; r < vis; r++) {
		int p = top + r;
		float y = GRID_Y + r * ROW_H;
		bool cur = p == page;
		char s[12];
		if (cur) uiRect(2, y - 1, UI_W - 8, ROW_H, uiCol[COL_SEL]);
		snprintf(s, sizeof(s), "%3d %02X", p, p);
		uiMonoS(4, y, S_MONO, 7, uiCol[cur ? COL_ACCENT : changed(p) ? COL_CHANGED : COL_DIM], s);
		for (int i = 0; i < 4; i++) {
			float x = HEX_X + i * BYTE_W;
			if (cur && i == col) {
				uiRect(x - 1, y - 1, 2 * MONO_W + 2, ROW_H - 1, uiCol[editing ? COL_BAR : COL_PANEL]);
				if (editing) uiRect(x - 1 + nib * MONO_W, y - 1, MONO_W + 2, ROW_H - 1, uiCol[COL_CURSOR]);
			}
			if (!d.valid[p]) {
				uiMono(x, y, uiCol[COL_DIM], "--");
				continue;
			}
			u32 c = uiCol[isUser(p) ? COL_TEXT : p < 4 ? COL_KEYA : COL_KEYB];
			if (orig.valid[p] && d.data[p][i] != orig.data[p][i]) c = uiCol[COL_CHANGED];
			snprintf(s, sizeof(s), "%02X", d.data[p][i]);
			if (cur && i == col && editing) {
				char hi[2] = { s[0], 0 }, lo[2] = { s[1], 0 };
				uiMono(x, y, nib ? c : uiCol[COL_BG], hi);
				uiMono(x + MONO_W, y, nib ? uiCol[COL_BG] : c, lo);
			} else {
				uiMono(x, y, c, s);
			}
		}
		char a[5];
		for (int i = 0; i < 4; i++) {
			u8 ch = d.data[p][i];
			a[i] = !d.valid[p] ? ' ' : (ch >= 32 && ch < 127) ? ch : '.';
		}
		a[4] = 0;
		uiMono(ASCII_X, y, uiCol[COL_DIM], a);
		uiText(ROLE_X, y, S_SMALL, uiCol[locked(p) ? COL_WARN : COL_DIM], "%s%s", role(p), locked(p) ? " (locked)" : "");
	}
	if (d.pages > VIS_ROWS) {
		float h = vis * ROW_H, bar = h * VIS_ROWS / d.pages;
		uiRect(UI_W - 4, GRID_Y, 2, h, uiCol[COL_PANEL]);
		uiRect(UI_W - 4, GRID_Y + h * top / d.pages, 2, bar, uiCol[COL_DIM]);
	}
	drawInfo(GRID_Y + 2 + vis * ROW_H);
	if (editing)
		uiFooter(BTN_UD " change nibble   " BTN_LR " move   " BTN_A "/" BTN_B " done");
	else
		uiFooter(BTN_DPAD " move   " BTN_L BTN_R " page   " BTN_A " edit   " BTN_X " actions   " BTN_Y " copy   " BTN_B " close");
}
