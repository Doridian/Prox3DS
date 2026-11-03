// MIFARE Classic family: its menu (scan, read, saved dumps), card screen, Gen4 GTU config, clone onto
// magic cards and the dump list. The dump editor is in editor.c.

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <3ds.h>

#include "app.h"
#include "dumplist.h"
#include "mfcinfo.h"
#include "pm3dict.h"
#include "entry.h"
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
	int r = mfMagicDetect(mfGen4Pwd, true, &sm) < 0 ? -1 : 1;
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
	char kdf[256] = "";
	int n = rd.kdf ? snprintf(kdf, sizeof(kdf), "Keys from the UID: %s.\n", rd.kdf) : 0;
	mfcInfoSummary(&rd, kdf + n, sizeof(kdf) - n);
	msgBox(mfCancel ? "Read card (stopped)" : "Read card", "%d/%d blocks read, %d/%d keys found.\n%s%s",
		rdGot, mfFirstBlock(rd.sectors), keys, 2 * rd.sectors, kdf,
		rdPath[0] ? rdPath : "Could not save the dump to the SD card!");
}

// The read job's key table: a column per sector (20 a row). The key square is split on its diagonal,
// key A top left and key B bottom right: grey open, blue (blinking) being tried, green found, red
// every attack failed. Under it, the sector's blocks read: grey none, yellow some, green all.
static u32 keyColor(int st)
{
	if (st == MF_KEY_TRYING) return uiCol[(osGetTime() / 300) % 2 ? COL_ACCENT : COL_SEL];
	return uiCol[st == MF_KEY_FOUND ? COL_OK : st == MF_KEY_FAILED ? COL_ERR : COL_BAR];
}

static float readView(float x, float y, float w)
{
	int n = mfProg.sectors;
	if (!n) return 0;
	int perRow = n > 20 ? 20 : n, keys = 0, blocks = 0, open = 0;
	float lw = 28, cw = (w - lw) / perRow, y0 = y;
	if (cw > 22) cw = 22;
	float bx = cw > 19 ? 16 : cw - 3;
	for (int r = 0; r * perRow < n; r++, y += 2 * bx + 18) {
		uiText(x, y + 10 + bx / 2 - 6, S_SMALL, uiCol[COL_DIM], "keys");
		uiText(x, y + 13 + 3 * bx / 2 - 6, S_SMALL, uiCol[COL_DIM], "data");
		for (int i = 0; i < perRow && r * perRow + i < n; i++) {
			int sec = r * perRow + i, nb = mfSectorBlocks(sec), got = mfProg.blocks[sec];
			float cx = x + lw + i * cw + (cw - bx) / 2, cy = y + 10, dy = cy + bx + 3;
			uiTextCenter(cx + bx / 2, y, 0.34f, uiCol[COL_DIM], "%d", sec);
			uiTri(cx, cy, cx + bx, cy, cx, cy + bx, keyColor(mfProg.key[sec][0]));
			uiTri(cx + bx, cy, cx + bx, cy + bx, cx, cy + bx, keyColor(mfProg.key[sec][1]));
			uiLine(cx + bx, cy, cx, cy + bx, 1.5f, uiCol[COL_PANEL]);
			for (int kb = 0; kb < 2; kb++) {
				int st = mfProg.key[sec][kb];
				keys += st == MF_KEY_FOUND;
				open += st == MF_KEY_OPEN || st == MF_KEY_TRYING;
			}
			uiRect(cx, dy, bx, bx, uiCol[COL_BAR]);
			float fh = bx * got / nb; // fills from the bottom
			uiRect(cx, dy + bx - fh, bx, fh, uiCol[got == nb ? COL_OK : COL_WARN]);
			blocks += got;
		}
	}
	uiText(x, y, S_SMALL, uiCol[COL_TEXT], "Keys %d/%d   Blocks %d/%d", keys, 2 * n, blocks, mfFirstBlock(n));
	if (open && mfProg.pivot) {
		// Worst case: every open key needs the nested attack (a dictionary hit is far quicker).
		u32 avg = mfProg.nestedRuns ? mfProg.nestedMs / mfProg.nestedRuns : MF_NESTED_MS;
		bool nested = !strncmp(prog.op, "Nested", 6);
		u32 ms = (open - nested) * avg + (nested ? progLeft() : 0);
		char t[16];
		fmtDuration(t, ms);
		uiTextRight(x + w, y, S_SMALL, uiCol[COL_DIM], "up to ~%s more (nested ~%lus a key)", t, (avg + 500) / 1000);
	} else if (open) {
		uiTextRight(x + w, y, S_SMALL, uiCol[COL_DIM], "nested needs one known key");
	}
	return y + SMALL_H - y0;
}

static void startRead(void)
{
	memset(&mfProg, 0, sizeof(mfProg)); // no old table before the card is found
	jobStartView("Reading card", runRead, doneRead, true, readView);
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
	if (!*magic && sm.mute)
		uiText(62, y, S_SMALL, uiCol[COL_WARN], "(went mute: a GTU with another password? Lift it, rescan)");
	else if (!*magic)
		uiText(62, y, S_SMALL, uiCol[COL_DIM], "(Gen2 / CUID needs a default sector 0 key or a known ATS)");

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
	g4result = mfGen4SetConfig(mfGen4Pwd, g4new);
	snprintf(g4why, sizeof(g4why), "%s", mfWhy());
	// Reactivate: the UID length, ATQA and SAK may all have changed.
	if (g4result == 1 && iso14aStart()) {
		sc = card;
		if (mfMagicDetect(mfGen4Pwd, false, &sm) >= 0) memcpy(g4cfg, sm.cfg, MF_GEN4_CFG);
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
	uiTextWrap(16, y, UI_W - 32, S_SMALL, uiCol[COL_TEXT], help[g4sel]);
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

// --- a dump's card actions: the saved dumps list and the editor share them (X) ---

static const MfDump *act; // the list's cl or the editor's dump: valid while their popup is up
static char actName[64];

static void actInfo(void)
{
	mfcInfoOpen(act);
}

static void actClone(void)
{
	cloneStart(act, false);
}

static void actCloneAsk(void)
{
	confirm("Write to magic card", actClone, "Write %s onto the magic card on the reader?\n"
		"Everything on that card is overwritten (Gen1a, Gen2, Gen4 GTU, USCUID).", actName);
}

static void actEmu(void)
{
	emuStartMfc(act, actName);
}

// The UID, SAK and ATQA from block 0: 4-byte UID + BCC, SAK, ATQA; else a 7-byte UID, SAK, ATQA.
static void actEmuUid(void)
{
	const u8 *b = act->data[0];
	Card c;
	c.uidLen = (b[0] ^ b[1] ^ b[2] ^ b[3]) == b[4] ? 4 : 7;
	memcpy(c.uid, b, c.uidLen);
	c.sak = b[c.uidLen == 4 ? 5 : 7];
	memcpy(c.atqa, b + (c.uidLen == 4 ? 6 : 8), 2);
	emuStartUid(&c);
}

static void actAddKeys(void)
{
	static u8 have[MF_MAX_KEYS][6];
	int n = mfKeyList(have, MF_MAX_KEYS, NULL, 0), added = 0;
	mkdir(MF_DIR, 0777);
	FILE *f = fopen(MF_KEYS, "a");
	if (!f) {
		msgBox("Dictionary", "Could not open " MF_KEYS);
		return;
	}
	for (int s = 0; s < act->sectors; s++)
		for (int k = 0; k < 2; k++) {
			if (!act->keyFound[s][k]) continue;
			bool dup = false;
			for (int i = 0; i < n && !dup; i++) dup = !memcmp(have[i], act->keys[s][k], 6);
			if (dup || n >= MF_MAX_KEYS) continue;
			const u8 *key = act->keys[s][k];
			fprintf(f, "%02X%02X%02X%02X%02X%02X # %s sector %d %c\n", key[0], key[1], key[2], key[3], key[4],
				key[5], actName, s, "AB"[k]);
			memcpy(have[n++], key, 6);
			added++;
		}
	fclose(f);
	msgBox("Dictionary", added ? "%d new key%s added to " MF_KEYS "." : "All of this dump's keys are already known.",
		added, added == 1 ? "" : "s");
}

int mfDumpActions(MenuItem *items, const MfDump *d, const char *name)
{
	act = d;
	snprintf(actName, sizeof(actName), "%s", name);
	int n = 0;
	items[n++] = (MenuItem){ "Card info (MAD, Saflok, signature)", actInfo };
	items[n++] = (MenuItem){ "Write to magic card", actCloneAsk };
	items[n++] = (MenuItem){ "Emulate this card", actEmu };
	if (d->valid[0]) items[n++] = (MenuItem){ "Emulate its UID", actEmuUid };
	items[n++] = (MenuItem){ "Add keys to dictionary", actAddKeys };
	return n;
}

// --- saved dumps ---

static DumpDir dumps = { .dir = MF_DUMPS };
static UiList fl;

static void filesScan(void)
{
	dumpScan(&dumps);
	if (fl.sel >= dumps.n) fl.sel = dumps.n ? dumps.n - 1 : 0;
}

static void filePath(char *out, u32 max)
{
	snprintf(out, max, MF_DUMPS "/%s", dumps.ent[fl.sel].name);
}

static void fileDelete(void)
{
	char path[128], kpath[140];
	filePath(path, sizeof(path));
	snprintf(kpath, sizeof(kpath), "%.*s.keys.txt", (int)strlen(path) - 4, path);
	remove(path);
	remove(kpath);
	toast("Deleted %s", dumps.ent[fl.sel].name);
	filesScan();
}

static void filesInput(u32 kDown, u32 kRepeat)
{
	uiListNav(&fl, dumps.n, 12, kRepeat);
	if (kDown & KEY_B) appBack();
	if (!dumps.n) return;
	char path[128];
	filePath(path, sizeof(path));
	if (kDown & (KEY_A | KEY_X)) {
		static MfDump d;
		if (!mfLoadDump(&d, path)) {
			msgBox("Saved dumps", "%s is not a Mifare Classic dump\n(%lu bytes).", dumps.ent[fl.sel].name,
				(unsigned long)dumps.ent[fl.sel].size);
			return;
		}
		if (kDown & KEY_A) {
			editorOpen(&d, path);
			return;
		}
		cl = d;
		MenuItem items[8];
		popup(dumps.ent[fl.sel].name, items, mfDumpActions(items, &cl, dumps.ent[fl.sel].name));
	}
	if (kDown & KEY_Y) confirm("Delete", fileDelete, "Delete %s and its key file?", dumps.ent[fl.sel].name);
}

static void filesDraw(void)
{
	char hdr[32];
	snprintf(hdr, sizeof(hdr), "%d dump%s", dumps.n, dumps.n == 1 ? "" : "s");
	uiHeader("Saved dumps", hdr);
	if (!dumps.n) {
		uiTextCenter(UI_W / 2, 100, S_BODY, uiCol[COL_DIM], "No dumps yet.");
		uiTextCenter(UI_W / 2, 118, S_SMALL, uiCol[COL_DIM], "Read a card, or copy .bin dumps to " MF_DUMPS);
		uiFooter(BTN_B " back");
		return;
	}
	for (int i = 0; i < 12 && fl.top + i < dumps.n; i++) {
		const DumpEnt *f = &dumps.ent[fl.top + i];
		int blocks = f->size / 16;
		float y = 24 + i * LINE_H;
		if (fl.top + i == fl.sel) uiRect(4, y - 1, UI_W - 8, LINE_H, uiCol[COL_SEL]);
		char name[64];
		snprintf(name, sizeof(name), "%s", f->name);
		uiText(10, y, S_BODY, uiCol[COL_TEXT], "%s", uiFit(name, 200, S_BODY)); // up to the size column
		int sectors = 0;
		while (sectors < 40 && mfFirstBlock(sectors) < blocks) sectors++;
		uiTextRight(268, y + 1, S_SMALL, uiCol[mfFirstBlock(sectors) == blocks ? COL_ACCENT : COL_ERR], "%s",
			mfFirstBlock(sectors) == blocks ? sizeName(sectors) : "not MFC");
		if (f->mtime > 1) {
			time_t t = f->mtime;
			struct tm *tm = gmtime(&t);
			uiTextRight(UI_W - 10, y + 1, S_SMALL, uiCol[COL_DIM], "%04d-%02d-%02d %02d:%02d", tm->tm_year + 1900,
				tm->tm_mon + 1, tm->tm_mday, tm->tm_hour, tm->tm_min);
		}
	}
	if (dumps.n > 12) uiTextRight(UI_W - 6, UI_H - 34, S_SMALL, uiCol[COL_DIM], "%d-%d of %d", fl.top + 1,
		fl.top + 12 < dumps.n ? fl.top + 12 : dumps.n, dumps.n);
	uiFooter(BTN_A " open   " BTN_X " actions   " BTN_Y " delete   " BTN_B " back");
}

static const Screen filesScreen = { filesScan, filesInput, filesDraw }; // rescanned: the editor may have saved one

void mfFilesChanged(void)
{
	filesScan();
}

void mfFilesWarm(void)
{
	if (!dumps.scanned) dumpScan(&dumps);
}

// --- menu and family ---

static int dictKeys, pm3Keys;

static void openFiles(void)
{
	appScreen(&filesScreen);
}

// --- keys the user enters ---

static u8 newKey[6];

static void readNow(void)
{
	startRead();
}

static void keyEntered(const u8 *b, u32 len)
{
	static u8 have[MF_MAX_KEYS][6];
	int n = mfKeyList(have, MF_MAX_KEYS, NULL, 0);
	memcpy(newKey, b, 6);
	for (int i = 0; i < n; i++)
		if (!memcmp(have[i], b, 6)) {
			confirm("Enter a key", readNow, "%02X%02X%02X%02X%02X%02X is in the dictionary already.\nRead the card now?",
				b[0], b[1], b[2], b[3], b[4], b[5]);
			return;
		}
	mkdir(MF_DIR, 0777);
	FILE *f = fopen(MF_KEYS, "a");
	if (!f) {
		msgBox("Enter a key", "Could not open " MF_KEYS);
		return;
	}
	fprintf(f, "%02X%02X%02X%02X%02X%02X # entered\n", b[0], b[1], b[2], b[3], b[4], b[5]);
	fclose(f);
	dictKeys = mfKeyList(have, MF_MAX_KEYS, NULL, 0);
	confirm("Enter a key", readNow, "%02X%02X%02X%02X%02X%02X added to the dictionary (" MF_KEYS ").\nRead the card now?",
		b[0], b[1], b[2], b[3], b[4], b[5]);
}

static void enterKey(void)
{
	entryHex("Classic key", "A sector key (6 bytes, A or B). It goes into the dictionary, which Read card tries "
		"on every sector before the attacks.", 6, newKey, keyEntered);
}

static void gtuPwdSet(const u8 *b, u32 len)
{
	memcpy(mfGen4Pwd, b, 4);
	toast("GTU password %02X%02X%02X%02X", b[0], b[1], b[2], b[3]);
}

static void gtuPwd(void)
{
	entryHex("Gen4 GTU password", "The password for the GTU's CF commands (scan, backdoor read, config, clone; "
		"default 00000000). Until the app restarts.", 4, mfGen4Pwd, gtuPwdSet);
}

static void mfcMenuShow(void);

static void startDownload(void)
{
	pm3DictDownload("Downloading pm3's MIFARE Classic keys", "mfc_default_keys.dic", MF_PM3_KEYS, 1ull << 12,
		mfcMenuShow);
}

static const MenuEntry mfcEntries[] = {
	{ "Scan card", "Read the card's UID, ATQA/SAK and magic generation (Gen1a, Gen2 / CUID, Gen4 GTU, USCUID) and the GTU / "
	               "USCUID config.", startScan },
	{ "Read card", "Dump every sector. Keys from the dictionary, then the nested and static-nonce attacks and the "
	               "magic backdoors. Saved to the SD card and opened in the editor.", startRead },
	{ "Saved dumps", "View and edit dumps, write them onto magic cards, or emulate them (1K, Mini): the 3DS as the card.", openFiles },
	{ "Enter a key", "Type a sector key into the dictionary (" MF_KEYS "), then read the card with it.", enterKey },
	{ "GTU password", "Set the Gen4 GTU password the magic card operations use (default 00000000).", gtuPwd },
	{ "Download keys", "Fetch pm3's mfc_default_keys.dic (~2500 keys, over Wi-Fi). Read card checks them "
	                   "against static nonces, and tries them (~17 s a key slot) only where the attacks fail.",
	                   startDownload },
};

static void mfcExtra(float x, float y, float w)
{
	uiText(x, y, S_SMALL, uiCol[COL_DIM], "Dictionary: %d keys (defaults + " MF_KEYS ")", dictKeys);
	if (pm3Keys > 0) uiText(x, y += SMALL_H, S_SMALL, uiCol[COL_DIM], "pm3's dictionary: %d keys", pm3Keys);
	if (sc.uidLen) menuLastCard(x, y += SMALL_H, w, &sc, cardTypeName(&sc));
	if (memcmp(mfGen4Pwd, mfGen4DefaultPwd, 4)) uiText(x, y + SMALL_H, S_SMALL, uiCol[COL_WARN], "GTU password %02X%02X%02X%02X",
		mfGen4Pwd[0], mfGen4Pwd[1], mfGen4Pwd[2], mfGen4Pwd[3]);
}

static Menu mfcMenu = { "MIFARE Classic", mfcEntries, sizeof(mfcEntries) / sizeof(mfcEntries[0]), mfcExtra };

static void mfcMenuShow(void)
{
	static u8 keys[MF_MAX_KEYS][6];
	dictKeys = mfKeyList(keys, MF_MAX_KEYS, NULL, 0);
	pm3Keys = pm3DictCount(MF_PM3_KEYS, 1ull << 12);
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
