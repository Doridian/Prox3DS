// Dump viewer / editor: one sector at a time as a hex + ASCII grid, with the block under the cursor
// decoded below (manufacturer block, trailer keys and access conditions, value blocks). Bytes are
// edited a nibble at a time with the D-pad; access bits through their own editor, which keeps the
// inverted copy consistent.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <3ds.h>

#include "app.h"
#include "dumplist.h"
#include "entry.h"
#include "probe.h"
#include "ui.h"

#define VIS_ROWS 7   // rows shown at once (4K's 16-block sectors scroll)
#define ROW_H    13
#define GRID_Y   39
#define HEX_X    26
#define BYTE_W   16.5f // two MONO_W cells and a gap
#define ASCII_X  300
#define ASCII_W  5.8f
#define S_ASCII  0.34f

static MfDump d, orig;
static char path[160];
static int sec, row, col, top; // cursor: sector, block within it, byte; first visible row
static bool editing;
static int nib;                 // 0 = high nibble
static u8 clip[16];
static bool clipOk;
static struct {
	bool on;
	int sel, c[4];
} acl;

static int nblocks(void) { return mfSectorBlocks(sec); }
static int blk(void) { return mfFirstBlock(sec) + row; }
static int trailerOf(int s) { return mfFirstBlock(s) + mfSectorBlocks(s) - 1; }
static int groupOf(int r) { return mfSectorBlocks(sec) == 4 ? r : r == 15 ? 3 : r / 5; }
static float byteX(int i) { return HEX_X + i * BYTE_W + (i >= 8 ? 3 : 0); }

static bool changed(int b)
{
	return d.valid[b] != orig.valid[b] || (d.valid[b] && memcmp(d.data[b], orig.data[b], 16));
}

static bool dirty(void)
{
	for (int b = 0; b < mfFirstBlock(d.sectors); b++)
		if (changed(b)) return true;
	return false;
}

static const char *baseName(void)
{
	const char *s = strrchr(path, '/');
	return s ? s + 1 : path;
}

static void editorInput(u32 kDown, u32 kRepeat);
static void editorDraw(void);

void editorOpen(const MfDump *src, const char *p)
{
	d = *src;
	orig = d;
	snprintf(path, sizeof(path), "%s", p);
	sec = row = col = top = 0;
	editing = acl.on = false;
	static const Screen editorScreen = { NULL, editorInput, editorDraw };
	appScreen(&editorScreen);
}

// --- access conditions (NXP MF1S50 tables), C1 C2 C3 as bits 2..0 ---

static const char *dataAcl[8] = {
	"read AB  write AB  incr AB  decr AB", // 000
	"read AB  decr AB (value)",            // 001
	"read AB",                             // 010
	"read B  write B",                     // 011
	"read AB  write B",                    // 100
	"read B",                              // 101
	"read AB  write B  incr B  decr AB",   // 110
	"no access",                           // 111
};
static const char *trailerAcl[8] = {
	"key A: w A   ACL: r A   key B: r A w A", // 000 (key B readable: it's data)
	"key A: w A   ACL: r A w A   key B: r A w A", // 001 transport
	"key A: -   ACL: r A   key B: r A", // 010
	"key A: w B   ACL: r AB w B   key B: w B", // 011
	"key A: w B   ACL: r AB   key B: w B", // 100
	"key A: -   ACL: r AB w B   key B: -", // 101
	"key A: -   ACL: r AB   key B: -", // 110
	"key A: -   ACL: r AB   key B: -", // 111
};

// Key B is plain readable data under trailer conditions 000, 001, 010.
static bool keyBReadable(const u8 *t)
{
	return mfAclGet(t, 3) <= 2;
}

static void groupLabel(char *out, u32 max, int g)
{
	if (g == 3) snprintf(out, max, "Trailer");
	else if (nblocks() == 4) snprintf(out, max, "Block %d", mfFirstBlock(sec) + g);
	else snprintf(out, max, "Blocks %d-%d", mfFirstBlock(sec) + 5 * g, mfFirstBlock(sec) + 5 * g + 4);
}

// --- actions ---

static void keysFromTrailers(void)
{
	// A trailer edited here holds the keys this dump means; untouched ones keep what the read found.
	for (int s = 0; s < d.sectors; s++) {
		int t = trailerOf(s);
		if (!d.valid[t] || (orig.valid[t] && !memcmp(d.data[t], orig.data[t], 16))) continue;
		memcpy(d.keys[s][0], d.data[t], 6);
		memcpy(d.keys[s][1], d.data[t] + 10, 6);
		d.keyFound[s][0] = d.keyFound[s][1] = true;
	}
}

static void save(void)
{
	keysFromTrailers();
	if (!mfWriteDump(&d, path)) {
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
	mkdir(MF_DIR, 0777);
	mkdir(MF_DUMPS, 0777);
	snprintf(path, sizeof(path), "%s", np);
	save();
}

static u8 wbData[16], wbKeys[4][6];
static int wbBlock, wbNkeys, wbResult;
static bool wbKeyB[4];
static char wbWhy[64], wbHow[32];

// Keys to try on a normal card: the ones the read found, then what the trailer held when loaded.
static void gatherKeys(void)
{
	int t = trailerOf(sec);
	wbNkeys = 0;
	for (int k = 0; k < 2; k++)
		if (orig.keyFound[sec][k]) {
			memcpy(wbKeys[wbNkeys], orig.keys[sec][k], 6);
			wbKeyB[wbNkeys++] = k;
		}
	if (orig.valid[t])
		for (int k = 0; k < 2; k++) {
			memcpy(wbKeys[wbNkeys], orig.data[t] + 10 * k, 6);
			wbKeyB[wbNkeys++] = k;
		}
}

static void runWriteBlock(void)
{
	wbResult = -2;
	if (!cardWait()) return;
	MfMagic m;
	wbResult = -1;
	if (mfMagicDetect(mfGen4Pwd, false, &m) < 0) return;
	if (m.flags & MF_MAGIC_GEN4) {
		snprintf(wbHow, sizeof(wbHow), "Gen4 GTU backdoor");
		wbResult = mfGen4Write(mfGen4Pwd, wbBlock, wbData);
	} else if (m.flags & MF_MAGIC_GEN1A) {
		snprintf(wbHow, sizeof(wbHow), "Gen1a backdoor");
		wbResult = mfGen1aWrite(wbBlock, wbData);
	} else {
		wbResult = 0;
		snprintf(wbHow, sizeof(wbHow), "no key known for sector %d", sec);
		for (int k = 0; k < wbNkeys && wbResult == 0; k++) {
			snprintf(wbHow, sizeof(wbHow), "key %c %02X%02X%02X%02X%02X%02X", wbKeyB[k] ? 'B' : 'A',
				wbKeys[k][0], wbKeys[k][1], wbKeys[k][2], wbKeys[k][3], wbKeys[k][4], wbKeys[k][5]);
			wbResult = mfWrite(wbBlock, wbKeys[k], wbKeyB[k], wbData);
		}
	}
	snprintf(wbWhy, sizeof(wbWhy), "%s", wbNkeys || wbResult ? mfWhy() : wbHow);
	iso14aParity(true);
	logp("write block %d: %s (%s)\n", wbBlock, wbResult == 1 ? "ok" : wbWhy, wbHow);
}

static void doneWriteBlock(void)
{
	if (wbResult == -2) return;
	if (wbResult == 1) msgBox("Write block", "Block %d written and read back\n(%s).", wbBlock, wbHow);
	else if (wbResult < 0) msgBox("Write block", "The chip stopped answering.");
	else msgBox("Write block", "Block %d not written: %s", wbBlock, wbWhy);
}

static void writeBlockGo(void)
{
	jobStart("Writing block", runWriteBlock, doneWriteBlock, true);
}

static void writeBlock(void)
{
	int b = blk(), t = trailerOf(sec);
	if (!d.valid[b]) {
		msgBox("Write block", "Block %d was never read: nothing to write.", b);
		return;
	}
	memcpy(wbData, d.data[b], 16);
	wbBlock = b;
	gatherKeys();
	if (b == t) {
		if (!mfAclValid(wbData)) {
			msgBox("Write block", "These access bits are inconsistent: a real card would lock this\n"
				"sector for good. Fix them with " BTN_A " on bytes 6-8.");
			return;
		}
		confirm("Write trailer", writeBlockGo, "Write trailer %d (keys and access bits) to the card?\n%s", b,
			mfTrailerRewritable(wbData) ? "Make sure you know the new keys."
			: "WARNING: after this, the keys or access bits can't be changed again.");
		return;
	}
	confirm("Write block", writeBlockGo, "Write block %d to the card on the reader?\n"
		"Magic cards through their backdoor, others with this dump's keys.", b);
}

// --- value blocks: INCREMENT / DECREMENT / RESTORE + TRANSFER on the card, with this dump's keys ---

static u8 vlOp, vlOut[16];
static s32 vlDelta;
static int vlDest, vlResult;

static void runValue(void)
{
	vlResult = -2;
	if (!cardWait()) return;
	vlResult = 0;
	snprintf(wbHow, sizeof(wbHow), "no key known for sector %d", sec);
	for (int k = 0; k < wbNkeys && vlResult == 0; k++) {
		snprintf(wbHow, sizeof(wbHow), "key %c %02X%02X%02X%02X%02X%02X", wbKeyB[k] ? 'B' : 'A',
			wbKeys[k][0], wbKeys[k][1], wbKeys[k][2], wbKeys[k][3], wbKeys[k][4], wbKeys[k][5]);
		vlResult = mfValue(vlOp, wbBlock, vlDelta, vlDest, wbKeys[k], wbKeyB[k], vlOut);
	}
	snprintf(wbWhy, sizeof(wbWhy), "%s", wbNkeys ? mfWhy() : wbHow);
	iso14aParity(true);
	logp("value %02X block %d -> %d: %s (%s)\n", vlOp, wbBlock, vlDest, vlResult == 1 ? "ok" : wbWhy, wbHow);
}

static void doneValue(void)
{
	if (vlResult == -2) return;
	if (vlResult < 0) {
		msgBox("Value block", "The chip stopped answering.");
		return;
	}
	if (vlResult == 0) {
		msgBox("Value block", "Refused: %s\n(%s)", wbWhy, wbHow);
		return;
	}
	// the card holds this now: the dump and its "as read" copy both take it
	memcpy(d.data[vlDest], vlOut, 16);
	memcpy(orig.data[vlDest], vlOut, 16);
	d.valid[vlDest] = orig.valid[vlDest] = true;
	s32 v;
	if (mfValueParse(vlOut, &v, NULL)) msgBox("Value block", "Block %d now holds %ld (read back, %s).", vlDest, (long)v, wbHow);
	else msgBox("Value block", "Done, but block %d doesn't read back as a value block.", vlDest);
}

static void valueGo(void)
{
	jobStart("Value block", runValue, doneValue, false);
}

static void valueAddDone(s64 v)
{
	if (!v) return;
	vlOp = v > 0 ? MF_VAL_INC : MF_VAL_DEC;
	vlDelta = v > 0 ? v : -v;
	wbBlock = vlDest = blk();
	gatherKeys();
	confirm("Value block", valueGo, "%s block %d's value by %ld on the card?", v > 0 ? "Increase" : "Decrease",
		wbBlock, (long)vlDelta);
}

static void valueAdd(void)
{
	entryDec("Value block", "Add to the value (negative: subtract)", -0x7FFFFFFF, 0x7FFFFFFF, 0, valueAddDone);
}

static void valueCopyDone(s64 dest)
{
	vlOp = MF_VAL_RESTORE;
	vlDelta = 0;
	wbBlock = blk();
	vlDest = dest;
	gatherKeys();
	confirm("Value block", valueGo, "Copy block %d's value to block %d on the card\n(RESTORE + TRANSFER)?", wbBlock, vlDest);
}

static void valueCopy(void)
{
	int b0 = mfFirstBlock(sec);
	entryDec("Value block", "Copy the value to block", b0 == 0 ? 1 : b0, trailerOf(sec) - 1, blk(), valueCopyDone);
}

static void valueFormatDone(s64 v)
{
	mfValueBlock(v, blk(), d.data[blk()]);
	d.valid[blk()] = true;
	toast("Block %d is now a value block in the dump: write it to the card", blk());
}

static void valueFormat(void)
{
	entryDec("Value block", "Make this block a value block holding", -0x7FFFFFFF, 0x7FFFFFFF, 0, valueFormatDone);
}

static void copyBlock(void)
{
	memcpy(clip, d.data[blk()], 16);
	clipOk = true;
	toast("Block %d copied", blk());
}

static void pasteBlock(void)
{
	memcpy(d.data[blk()], clip, 16);
	d.valid[blk()] = true;
}

static void revertBlock(void)
{
	memcpy(d.data[blk()], orig.data[blk()], 16);
	d.valid[blk()] = orig.valid[blk()];
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
	snprintf(wlabel, sizeof(wlabel), "Write block %d to card", blk());
	MenuItem items[20];
	int n = 0;
	int b = blk();
	bool data = b && b != trailerOf(sec);
	items[n++] = (MenuItem){ "Save", save };
	items[n++] = (MenuItem){ "Save as a copy", saveCopy };
	items[n++] = (MenuItem){ wlabel, writeBlock };
	if (data && orig.valid[b] && mfValueParse(orig.data[b], NULL, NULL)) {
		items[n++] = (MenuItem){ "Value: add / subtract on card", valueAdd };
		items[n++] = (MenuItem){ "Value: copy to another block", valueCopy };
	} else if (data) {
		items[n++] = (MenuItem){ "Make a value block", valueFormat };
	}
	items[n++] = (MenuItem){ "Copy block", copyBlock };
	if (clipOk) items[n++] = (MenuItem){ "Paste block", pasteBlock };
	items[n++] = (MenuItem){ "Revert block", revertBlock };
	items[n++] = (MenuItem){ "Revert all changes", revertAll };
	keysFromTrailers(); // the dump as edited, for the card actions (clone, emulate, keys)
	n += mfDumpActions(items + n, &d, baseName());
	popup("Dump", items, n);
}

// --- input ---

static void moveRow(int dr)
{
	row += dr;
	if (row < 0) {
		sec = (sec + d.sectors - 1) % d.sectors;
		row = nblocks() - 1;
	} else if (row >= nblocks()) {
		sec = (sec + 1) % d.sectors;
		row = 0;
	}
}

static void setNibble(int dv)
{
	u8 *p = &d.data[blk()][col];
	if (!d.valid[blk()]) {
		memset(d.data[blk()], 0, 16);
		d.valid[blk()] = true;
	}
	int sh = nib ? 0 : 4, v = ((*p >> sh) + dv) & 0xF;
	*p = (*p & ~(0xF << sh)) | v << sh;
}

static void editorInput(u32 kDown, u32 kRepeat)
{
	if (acl.on) {
		if (kRepeat & KEY_UP) acl.sel = (acl.sel + 3) % 4;
		if (kRepeat & KEY_DOWN) acl.sel = (acl.sel + 1) % 4;
		if (kRepeat & KEY_LEFT) acl.c[acl.sel] = (acl.c[acl.sel] + 7) % 8;
		if (kRepeat & KEY_RIGHT) acl.c[acl.sel] = (acl.c[acl.sel] + 1) % 8;
		if (kDown & KEY_B) acl.on = false;
		if (kDown & KEY_A) {
			u8 *t = d.data[blk()];
			for (int g = 0; g < 4; g++) mfAclSet(t, g, acl.c[g]);
			d.valid[blk()] = true;
			acl.on = false;
		}
		return;
	}
	if (editing) {
		if (kRepeat & KEY_UP) setNibble(1);
		if (kRepeat & KEY_DOWN) setNibble(-1);
		if (kRepeat & KEY_LEFT) {
			if (nib) nib = 0;
			else if (col > 0) col--, nib = 1;
		}
		if (kRepeat & KEY_RIGHT) {
			if (!nib) nib = 1;
			else if (col < 15) col++, nib = 0;
		}
		if (kDown & (KEY_A | KEY_B)) editing = false;
		return;
	}
	if (kRepeat & KEY_UP) moveRow(-1);
	if (kRepeat & KEY_DOWN) moveRow(1);
	if (kRepeat & KEY_LEFT) {
		if (--col < 0) col = 15, moveRow(-1);
	}
	if (kRepeat & KEY_RIGHT) {
		if (++col > 15) col = 0, moveRow(1);
	}
	if (kRepeat & KEY_L) sec = (sec + d.sectors - 1) % d.sectors, row = row < nblocks() ? row : nblocks() - 1;
	if (kRepeat & KEY_R) sec = (sec + 1) % d.sectors, row = row < nblocks() ? row : nblocks() - 1;
	if (row < top) top = row;
	if (row >= top + VIS_ROWS) top = row - VIS_ROWS + 1;
	if (nblocks() <= VIS_ROWS) top = 0;
	if (kDown & KEY_A) {
		if (row == nblocks() - 1 && col >= 6 && col <= 8) {
			const u8 *t = d.data[blk()];
			for (int g = 0; g < 4; g++) acl.c[g] = mfAclGet(t, g);
			if (!d.valid[blk()] || !mfAclValid(t)) // start from the transport config
				for (int g = 0; g < 4; g++) acl.c[g] = g == 3 ? 1 : 0;
			acl.sel = groupOf(row);
			acl.on = true;
		} else {
			editing = true;
			nib = 0;
		}
	}
	if (kDown & KEY_X) actions();
	if (kDown & KEY_Y) copyBlock();
	if (kDown & KEY_B) {
		if (dirty()) confirm("Close dump", back, "Drop the unsaved changes?");
		else back();
	}
}

// --- drawing ---

static void drawInfo(float y)
{
	int b = blk(), t = trailerOf(sec);
	const u8 *p = d.data[b];
	float x = 10;
	u32 txt = uiCol[COL_TEXT], dim = uiCol[COL_DIM];
	uiRect(4, y, UI_W - 8, UI_H - 20 - y - 2, uiCol[COL_PANEL]);
	y += 3;
	if (changed(b)) uiTextRight(UI_W - 10, y, S_SMALL, uiCol[COL_CHANGED], "modified");
	if (!d.valid[b]) {
		uiText(x, y, S_SMALL, dim, "Block %d was not read (no key for it).", b);
		uiText(x, y + SMALL_H, S_SMALL, dim, "Editing it adds it to the dump.");
		return;
	}
	if (b == 0) {
		uiText(x, y, S_SMALL, uiCol[COL_ACCENT], "Manufacturer block");
		y += SMALL_H;
		u8 bcc = p[0] ^ p[1] ^ p[2] ^ p[3];
		uiText(x, y, S_SMALL, txt, "4-byte UID %02X%02X%02X%02X   SAK %02X   ATQA %02X%02X", p[0], p[1], p[2], p[3],
			p[5], p[7], p[6]);
		y += SMALL_H;
		if (bcc == p[4]) {
			uiText(x, y, S_SMALL, uiCol[COL_OK], "BCC %02X ok", p[4]);
		} else {
			char why[96];
			snprintf(why, sizeof(why), "BCC %02X, should be %02X: Gen1a/Gen2 cards refuse it (the GTU makes its own)", p[4], bcc);
			y = uiTextWrap(x, y, UI_W - 2 * x, S_SMALL, uiCol[COL_WARN], why);
			uiText(x, y, S_SMALL, dim, "As a 7-byte UID: %02X%02X%02X%02X%02X%02X%02X   SAK %02X   ATQA %02X%02X",
				p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[9], p[8]);
		}
		return;
	}
	if (b == t) {
		float w = uiText(x, y, S_SMALL, dim, "Key A ");
		w += uiText(x + w, y, S_SMALL, uiCol[COL_KEYA], "%02X%02X%02X%02X%02X%02X", p[0], p[1], p[2], p[3], p[4], p[5]);
		w += uiText(x + w, y, S_SMALL, dim, "    Key B ");
		w += uiText(x + w, y, S_SMALL, uiCol[COL_KEYB], "%02X%02X%02X%02X%02X%02X", p[10], p[11], p[12], p[13], p[14], p[15]);
		uiText(x + w, y, S_SMALL, dim, "%s    GPB %02X", keyBReadable(p) ? " (data)" : "", p[9]);
		y += SMALL_H;
		if (!mfAclValid(p)) {
			uiText(x, y, S_SMALL, uiCol[COL_ERR], "Access bits %02X%02X%02X are inconsistent: a real card would lock", p[6], p[7], p[8]);
			uiText(x, y + SMALL_H, S_SMALL, uiCol[COL_ERR], "this sector for good. " BTN_A " on bytes 6-8 to fix them.");
			return;
		}
		for (int g = 0; g < 4; g++, y += SMALL_H) {
			char lbl[24];
			groupLabel(lbl, sizeof(lbl), g);
			int c = mfAclGet(p, g);
			uiText(x, y, S_SMALL, g == groupOf(row) ? txt : dim, "%s", lbl);
			uiText(x + 88, y, S_SMALL, uiCol[COL_ACL], "%d%d%d", c >> 2, c >> 1 & 1, c & 1);
			uiText(x + 112, y, S_SMALL, txt, "%s", g == 3 ? trailerAcl[c] : dataAcl[c]);
		}
		uiText(x, y, S_SMALL, dim, BTN_A " on bytes 6-8: edit access conditions");
		return;
	}
	u32 v = p[0] | p[1] << 8 | p[2] << 16 | p[3] << 24, vi = p[4] | p[5] << 8 | p[6] << 16 | p[7] << 24;
	u32 v2 = p[8] | p[9] << 8 | p[10] << 16 | p[11] << 24;
	bool value = v == ~vi && v == v2 && p[12] == (u8)~p[13] && p[12] == p[14] && p[13] == p[15];
	if (value) uiText(x, y, S_SMALL, uiCol[COL_ACCENT], "Value block: %ld (0x%08lX), address %02X", (s32)v, v, p[12]);
	else uiText(x, y, S_SMALL, uiCol[COL_ACCENT], "Data block %d", b);
	y += SMALL_H;
	if (d.valid[t] && mfAclValid(d.data[t])) {
		int c = mfAclGet(d.data[t], groupOf(row));
		uiText(x, y, S_SMALL, txt, "Access %d%d%d: %s", c >> 2, c >> 1 & 1, c & 1, dataAcl[c]);
	} else {
		uiText(x, y, S_SMALL, dim, "Access conditions unknown (trailer not read)");
	}
	y += SMALL_H;
	for (int k = 0; k < 2; k++)
		uiText(x + 190 * k, y, S_SMALL, dim, "Key %c: %s", "AB"[k], d.keyFound[sec][k] ? "known" : "not found");
}

static void drawAclEditor(void)
{
	float y = uiBox(372, 22 + 4 * 30 + 36, "Access conditions"), x = (UI_W - 372) / 2;
	for (int g = 0; g < 4; g++, y += 30) {
		char lbl[24];
		groupLabel(lbl, sizeof(lbl), g);
		int c = acl.c[g];
		if (g == acl.sel) uiRect(x + 2, y - 2, 368, 29, uiCol[COL_SEL]);
		uiText(x + 8, y, S_SMALL, uiCol[COL_TEXT], "%s", lbl);
		uiText(x + 100, y, S_SMALL, uiCol[COL_ACL], "< %d%d%d >", c >> 2, c >> 1 & 1, c & 1);
		uiText(x + 8, y + 13, S_SMALL, uiCol[COL_DIM], "%s", g == 3 ? trailerAcl[c] : dataAcl[c]);
	}
	u8 t[16];
	memcpy(t, d.data[blk()], 16);
	for (int g = 0; g < 4; g++) mfAclSet(t, g, acl.c[g]);
	uiText(x + 8, y + 2, S_SMALL, uiCol[mfTrailerRewritable(t) ? COL_DIM : COL_WARN], "Bytes 6-8 become %02X%02X%02X%s",
		t[6], t[7], t[8], mfTrailerRewritable(t) ? "" : ": the trailer can't be fully changed later");
	uiText(x + 8, y + 16, S_SMALL, uiCol[COL_DIM], BTN_UD " select   " BTN_LR " change   " BTN_A " apply   " BTN_B " cancel");
}

static void editorDraw(void)
{
	char title[176], right[48];
	snprintf(title, sizeof(title), "%s%s", baseName(), dirty() ? " *" : "");
	snprintf(right, sizeof(right), "sector %d of %d   %s", sec, d.sectors - 1,
		d.sectors == 5 ? "Mini" : d.sectors == 16 ? "1K" : d.sectors == 32 ? "2K" : "4K");
	uiHeader(title, right);

	// sector strip: one tick per sector, coloured by keys found
	float sw = (float)(UI_W - 12) / d.sectors;
	for (int s = 0; s < d.sectors; s++) {
		int k = d.keyFound[s][0] + d.keyFound[s][1];
		u32 c = uiCol[k == 2 ? COL_OK : k ? COL_WARN : COL_ERR];
		uiRect(6 + s * sw + 0.5f, 22, sw - 1, s == sec ? 5 : 3, s == sec ? uiCol[COL_TEXT] : c);
	}

	for (int i = 0; i < 16; i++) {
		char h[2] = { "0123456789ABCDEF"[i], 0 };
		uiMono(byteX(i) + MONO_W / 2, GRID_Y - 9, uiCol[i == col ? COL_ACCENT : COL_DIM], h);
	}
	int nb = nblocks(), vis = nb < VIS_ROWS ? nb : VIS_ROWS;
	for (int r = top; r < top + vis; r++) {
		int b = mfFirstBlock(sec) + r;
		float y = GRID_Y + 2 + (r - top) * ROW_H;
		bool trailer = r == nb - 1, cur = r == row;
		char s[8];
		snprintf(s, sizeof(s), "%3d", b);
		uiMonoS(0, y, S_MONO, 7,  uiCol[cur ? COL_ACCENT : changed(b) ? COL_CHANGED : COL_DIM], s);
		for (int i = 0; i < 16; i++) {
			float x = byteX(i);
			if (cur && i == col) {
				uiRect(x - 1, y - 1, 2 * MONO_W + 2, ROW_H - 1, uiCol[editing ? COL_BAR : COL_SEL]);
				if (editing) uiRect(x - 1 + nib * MONO_W, y - 1, MONO_W + 2, ROW_H - 1, uiCol[COL_CURSOR]);
			}
			u32 c = uiCol[COL_TEXT];
			if (trailer) c = uiCol[i < 6 ? COL_KEYA : i < 9 ? COL_ACL : i == 9 ? COL_DIM : COL_KEYB];
			if (d.valid[b] && orig.valid[b] && d.data[b][i] != orig.data[b][i]) c = uiCol[COL_CHANGED];
			if (!d.valid[b]) {
				uiMono(x, y, uiCol[COL_DIM], "--");
				continue;
			}
			snprintf(s, sizeof(s), "%02X", d.data[b][i]);
			if (cur && i == col && editing) {
				char hi[2] = { s[0], 0 }, lo[2] = { s[1], 0 };
				uiMono(x, y, nib ? c : uiCol[COL_BG], hi);
				uiMono(x + MONO_W, y, nib ? uiCol[COL_BG] : c, lo);
			} else {
				uiMono(x, y, c, s);
			}
		}
		char a[17];
		for (int i = 0; i < 16; i++) {
			u8 ch = d.data[b][i];
			a[i] = !d.valid[b] ? ' ' : (ch >= 32 && ch < 127) ? ch : '.';
		}
		a[16] = 0;
		if (cur) uiRect(ASCII_X + col * ASCII_W, y - 1, ASCII_W, ROW_H - 1, uiCol[COL_SEL]);
		uiMonoS(ASCII_X, y + 1, S_ASCII, ASCII_W, uiCol[COL_DIM], a);
	}
	if (nb > VIS_ROWS) {
		float h = vis * ROW_H, bar = h * VIS_ROWS / nb;
		uiRect(UI_W - 4, GRID_Y + 1, 2, h, uiCol[COL_PANEL]);
		uiRect(UI_W - 4, GRID_Y + 1 + h * top / nb, 2, bar, uiCol[COL_DIM]);
	}
	drawInfo(GRID_Y + 4 + vis * ROW_H);
	if (editing)
		uiFooter(BTN_UD " change nibble   " BTN_LR " move   " BTN_A "/" BTN_B " done");
	else
		uiFooter(BTN_DPAD " move   " BTN_L BTN_R " sector   " BTN_A " edit   " BTN_X " actions   " BTN_Y " copy   " BTN_B " close");
	if (acl.on) drawAclEditor();
}
