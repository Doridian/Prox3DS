// HID iClass / PicoPass: menu (read with the key search, read with a key), card screen (header,
// configuration, keys, the credential in blocks 7-9, every block). The reader is iclassrw.c.

#include <stdio.h>
#include <string.h>
#include <3ds.h>

#include "app.h"
#include "entry.h"
#include "iclass.h"
#include "mfc.h"
#include "probe.h"
#include "ui.h"

static IcCard sc;      // the card screen's copy (the job fills icCard)
static int rdResult;
static char rdPath[96];
static u8 rdKey[8];
static int rdKind = -1; // -1 = key search
static UiList bl;       // block list

static const Screen cardScreen;

static void runRead(void)
{
	rdResult = -2;
	rdPath[0] = 0;
	if (!chipEnsure()) {
		logp("NFC takeover failed\n");
		return;
	}
	logp("waiting for an iClass card...\n");
	if (!icWait(icCard.csn, 0)) return;
	logp("iclass: CSN %02X%02X%02X%02X%02X%02X%02X%02X\n", icCard.csn[0], icCard.csn[1], icCard.csn[2], icCard.csn[3],
		icCard.csn[4], icCard.csn[5], icCard.csn[6], icCard.csn[7]);
	rdResult = icReadCard(&icCard, rdKind < 0 ? NULL : rdKey, rdKind < 0 ? 0 : rdKind);
	if (rdResult > 0 && icSaveDump(&icCard, rdPath, sizeof(rdPath))) logp("saved %s\n", rdPath);
	icStop();
}

static void doneRead(void)
{
	if (rdResult == -2) return; // cancelled while waiting
	if (rdResult <= 0) {
		msgBox("iClass", rdResult < 0 ? "The chip stopped answering. Try again." : "Lost the card. Try again.");
		return;
	}
	sc = icCard;
	bl = (UiList){ 0 };
	appScreen(&cardScreen);
	int got = 0;
	for (int b = 0; b < sc.nblocks; b++) got += sc.have[b];
	const char *keys = sc.cfg.nonSecure ? "Non-secured card: no keys needed."
		: sc.kdKnown && sc.kcKnown ? "Both keys found." : sc.kdKnown ? "Debit key (Kd) found, no credit key (Kc)."
		: sc.kcKnown ? "Credit key (Kc) found, no debit key (Kd)." : rdKind >= 0 ? "The key did not open the card."
		: "No key in the dictionaries opened the card.";
	msgBox(mfCancel ? "iClass (stopped)" : "iClass", "%d/%d blocks read. %s\n%s", got, sc.nblocks, keys,
		rdPath[0] ? rdPath : "Could not save the dump to the SD card!");
}

static void startRead(void)
{
	rdKind = -1;
	jobStart("Reading iClass card", runRead, doneRead, true);
}

static void kindStd(void) { rdKind = IC_KEY_STD; jobStart("Reading iClass card with key", runRead, doneRead, true); }
static void kindElite(void) { rdKind = IC_KEY_ELITE; jobStart("Reading iClass card with key", runRead, doneRead, true); }
static void kindDiv(void) { rdKind = IC_KEY_DIV; jobStart("Reading iClass card with key", runRead, doneRead, true); }

static void keyEntered(const u8 *b, u32 len)
{
	memcpy(rdKey, b, 8);
	static const MenuItem kinds[] = {
		{ "Standard master key", kindStd },
		{ "Elite master key", kindElite },
		{ "Diversified card key", kindDiv },
	};
	popup("Key type", kinds, 3);
}

static void startKeyRead(void)
{
	entryHex("iClass key", "A master key (diversified with the CSN, standard or elite) or the card's own "
		"diversified key, as pm3 shows it. It is tried as Kd and Kc.", 8, rdKey, keyEntered);
}

// --- card screen ---

static void hex8(const u8 *b, char *out, const char *sep)
{
	out[0] = 0;
	for (int i = 0; i < 8; i++) sprintf(out + strlen(out), "%s%02X", i ? sep : "", b[i]);
}

static const char *kindName(int k)
{
	return k == IC_KEY_DIV ? "diversified" : k == IC_KEY_ELITE ? "elite" : "standard";
}

#define ROWS 6

static void cardDraw(void)
{
	char s[64];
	const IcConfig *c = &sc.cfg;
	u32 txt = uiCol[COL_TEXT], dim = uiCol[COL_DIM];
	uiHeader("iClass: card", c->personalization ? "personalization mode" : "application mode");
	float y = 26;
	hex8(sc.csn, s, " ");
	uiText(12, y, S_SMALL, dim, "CSN");
	uiText(40, y - 4, 0.7f, uiCol[COL_ACCENT], "%s", s);
	y += 20;
	if (c->nonSecure) uiText(12, y, S_SMALL, txt, "%d KBits, non-secured page (no keys)", c->kbits);
	else uiText(12, y, S_SMALL, txt, "%d KBits, %d app areas, AA1 6-%d, %s%s", c->kbits, c->areas, c->appLimit,
		c->keysLocked ? "keys locked" : "secured", c->pagemap == 0 ? " (auth disabled)" : "");
	y += SMALL_H;
	uiText(12, y, S_SMALL, dim, "Coding %s, %s", c->coding, c->keyAccessSplit ? "AA1 Kd / AA2 Kc" : "read with Kd or Kc");
	y += SMALL_H + 3;
	uiRect(8, y, UI_W - 16, 3 * SMALL_H + 6, uiCol[COL_PANEL]);
	y += 3;
	for (int k = 0; k < 2; k++, y += SMALL_H) {
		bool known = k ? sc.kcKnown : sc.kdKnown;
		uiText(14, y, S_SMALL, txt, k ? "Kc (credit)" : "Kd (debit)");
		if (c->nonSecure) {
			uiText(90, y, S_SMALL, dim, "not needed");
			continue;
		}
		if (!known) {
			uiText(90, y, S_SMALL, uiCol[COL_WARN], "not found (%lu keys tried)", (unsigned long)sc.keysTried);
			continue;
		}
		hex8(k ? sc.kc : sc.kd, s, "");
		uiMonoS(90, y + 1, 0.36f, 6.0f, txt, s);
		char lab[64];
		snprintf(lab, sizeof(lab), "%s, %s", kindName(k ? sc.kcKind : sc.kdKind), k ? sc.kcLabel : sc.kdLabel);
		uiTextRight(UI_W - 14, y, S_SMALL, dim, "%s", uiFit(lab, UI_W - 14 - 196, S_SMALL));
	}
	const IcCredential *cr = &sc.cred;
	if (!cr->present) uiText(14, y, S_SMALL, dim, "No legacy credential in block 7");
	else if (cr->encrypted) uiText(14, y, S_SMALL, uiCol[COL_WARN], "Credential encrypted: needs %s", "iclass/iclass_decryptionkey.bin");
	else if (cr->format[0])
		uiText(14, y, S_SMALL, uiCol[cr->parityOk ? COL_OK : COL_WARN], "%s  FC %lu  CN %lu%s", cr->name,
			(unsigned long)cr->fc, (unsigned long)cr->cn, cr->parityOk ? "" : "  (parity BAD)");
	else uiText(14, y, S_SMALL, txt, "Credential: %d bits, no known format", cr->bits);
	y += SMALL_H + 6;
	// blocks
	int n = sc.nblocks;
	for (int r = 0; r < ROWS && bl.top + r < n; r++, y += SMALL_H) {
		int b = bl.top + r;
		u32 col = b == bl.sel ? uiCol[COL_ACCENT] : sc.have[b] ? txt : dim;
		if (sc.have[b]) hex8(sc.blocks[b], s, " ");
		else snprintf(s, sizeof(s), "-- -- -- -- -- -- -- --");
		char row[80];
		snprintf(row, sizeof(row), "%3d %s", b, s);
		uiMono(14, y + 1, col, row);
		const char *what = b == 0 ? "CSN" : b == 1 ? "config" : b == 2 ? "e-purse" : b == 3 ? "Kd" : b == 4 ? "Kc"
			: b == 5 ? "AIA" : b <= c->appLimit ? "AA1" : "AA2";
		uiText(14 + 28 * MONO_W, y, S_SMALL, dim, "%s", what);
	}
	uiFooter(BTN_UD " blocks   " BTN_A " read again   " BTN_Y " with key   " BTN_B " back");
}

static void cardInput(u32 kDown, u32 kRepeat)
{
	uiListNav(&bl, sc.nblocks, ROWS, kRepeat);
	if (kDown & KEY_A) startRead();
	if (kDown & KEY_Y) startKeyRead();
	if (kDown & KEY_B) appBack();
}

static const Screen cardScreen = { NULL, cardInput, cardDraw };

// --- menu ---

static void openCard(void)
{
	if (sc.nblocks) appScreen(&cardScreen);
	else toast("No iClass card read yet");
}

static const MenuEntry icEntries[] = {
	{ "Read card", "Find the keys and dump every block: keys remembered for the card, " ICLASS_KEYS " (\"<key> "
	               "[s|e|d] label\": standard, elite or diversified), then pm3's default (standard and elite) and "
	               "elite dictionaries. Saved to the SD card in pm3's format.", startRead },
	{ "Read with key", "The same with one key you type: a master key (standard or elite) or the card's "
	                   "diversified key.", startKeyRead },
	{ "Last card", "The card screen of the last card read.", openCard },
};

static void icExtra(float y)
{
	uiText(12, y, S_SMALL, uiCol[COL_DIM], "Dumps: " ICLASS_DIR " (pm3 hf iclass .bin)");
	uiText(12, y + SMALL_H, S_SMALL, uiCol[COL_DIM], "Credential decryption: pm3's iclass_decryptionkey.bin there");
}

static Menu icMenu = { "iClass / PicoPass", icEntries, sizeof(icEntries) / sizeof(icEntries[0]), icExtra };

static void icMenuInput(u32 kDown, u32 kRepeat)
{
	menuInput(&icMenu, kDown, kRepeat);
}

static void icMenuDraw(void)
{
	menuDraw(&icMenu);
}

void iclassOpenMenu(void)
{
	static const Screen s = { NULL, icMenuInput, icMenuDraw };
	appScreen(&s);
}
