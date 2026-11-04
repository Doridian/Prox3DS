// ID documents (eid.h): what the chip offers, the eID PIN's state, a CAN check (PACE + one command under
// secure messaging).

#include <stdio.h>
#include <string.h>
#include <3ds.h>

#include "app.h"
#include "eid.h"
#include "entry.h"
#include "iso7816.h"
#include "probe.h"
#include "ui.h"

static EidCard ed;
static int readResult;
static char readWhy[96];
static UiList il;

// the last CAN check: 0 none, 1 right, 2 wrong, 3 failed (canWhy)
static int canState, canResult;
static char canWhy[96];
static s64 canValue = -1;
static char canText[8];
static u16 canSmSw;

static const Screen eidScreen;

static void runRead(void)
{
	readResult = 0;
	*readWhy = 0;
	if (!cardWait()) return;
	readResult = eidRead(&ed);
	snprintf(readWhy, sizeof(readWhy), "%s", eidWhy());
	iso14aParity(true);
}

static void doneRead(void)
{
	if (readResult < 0) {
		msgBox("ID document", "The chip stopped answering.\nTry again.");
		return;
	}
	if (!readResult) {
		if (!mfCancel && *readWhy) msgBox("ID document", "%s", readWhy);
		return;
	}
	il = (UiList){ 0 };
	canState = 0;
	appScreen(&eidScreen);
}

void eidOpenTool(void)
{
	jobStart("Reading the ID document", runRead, doneRead, true);
}

// --- CAN check ---

static void runCan(void)
{
	static u8 buf[64];
	static EidSm sm;
	canResult = 0;
	*canWhy = 0;
	canSmSw = 0;
	if (!cardWait()) return;
	canResult = eidPace(&ed, EID_CAN, canText, &sm);
	snprintf(canWhy, sizeof(canWhy), "%s", eidWhy());
	if (canResult == 1) {
		// one command under secure messaging: SELECT the ePass application (P2 0C, no answer data)
		static const u8 epass[] = { 0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01 };
		int n = eidSmCmd(&sm, 0xA4, 0x04, 0x0C, epass, sizeof(epass), false, buf, sizeof(buf), &canSmSw);
		if (n < 0) {
			snprintf(canWhy, sizeof(canWhy), "secure messaging: %s", eidWhy());
			canSmSw = 0;
		}
	}
	iso14aParity(true);
}

static void doneCan(void)
{
	if (mfCancel) return;
	if (canResult < 0) {
		msgBox("CAN", "The chip stopped answering.\nTry again.");
		return;
	}
	canState = canResult == 1 ? 1 : canResult == 2 ? 2 : 3;
	if (canState == 1)
		toast(canSmSw ? "CAN right: PACE done, secure messaging works" : "CAN right: PACE done");
	else if (canState == 2)
		msgBox("CAN", "Wrong CAN: the card refused PACE with %s.\n(A wrong CAN costs no PIN try.)", canText);
	else
		msgBox("CAN", "PACE failed: %s", canWhy);
}

static void canDone(s64 v)
{
	canValue = v;
	snprintf(canText, sizeof(canText), "%06lld", v);
	jobStart("PACE with the CAN", runCan, doneCan, true);
}

static void checkCan(void)
{
	if (ed.pace < 0) {
		msgBox("CAN", ed.accessLen ? "This chip's PACE variant isn't one the app does yet (ECDH generic "
			"mapping with AES only)." : "No EF.CardAccess: this chip has no PACE (a BAC-only passport).");
		return;
	}
	entryDec("CAN", "The 6-digit card access number, printed on the card (German ID card: bottom right of "
		"the front).", 0, 999999, canValue < 0 ? 0 : canValue, canDone);
}

// --- the screen ---

#define INFO_ROWS 7

static void eidDraw(void)
{
	char s[160];
	u32 txt = uiCol[COL_TEXT], dim = uiCol[COL_DIM];
	bool de = eidIsGermanId(&ed);
	uiHeader("ID document", de ? "TR-03110" : "ICAO 9303");

	float y = 26;
	uiText(12, y, S_TITLE, uiCol[COL_ACCENT], "%s", de ? "German ID card" : ed.accessLen ? "eMRTD with PACE" :
		"eMRTD");
	int o = 0;
	*s = 0;
	for (int i = 0; i < ed.napps; i++) {
		const char *n = eidAppName(ed.app[i].aid, ed.app[i].aidLen);
		char h[33];
		if (!n && *ed.app[i].label) n = ed.app[i].label;
		if (!n) scHex(h, ed.app[i].aid, ed.app[i].aidLen), n = h;
		o += snprintf(s + o, sizeof(s) - o, "%s%s", o ? "  " : "", n);
	}
	if (o) uiTextRight(UI_W - 12, y + 2, S_SMALL, dim, "%s", uiFit(s, 200, S_SMALL));
	y += 18;
	*s = 0;
	if (ed.extIn || ed.extOut) snprintf(s, sizeof(s), "Extended length: %lu bytes in, %lu out", ed.extIn, ed.extOut);
	else snprintf(s, sizeof(s), "No extended length info");
	uiText(12, y, S_SMALL, dim, "%s", s);
	y += SMALL_H + 4;

	u32 col;
	const char *pin = eidPinText(ed.pinSw, &col);
	if (pin) uiText(12, y, S_BODY, uiCol[col], "%s", pin);
	else if (ed.pinSw) uiText(12, y, S_BODY, dim, "No eID PIN (MSE:Set AT: %04X)", ed.pinSw);
	else uiText(12, y, S_BODY, dim, "%s", ed.accessLen ? "No PACE variant the app does" : "No PACE (BAC only)");
	y += LINE_H;
	if (canState == 1)
		uiText(12, y, S_BODY, uiCol[COL_OK], "CAN %s right: PACE done%s", canText,
			canSmSw == 0x9000 ? ", secure messaging works" : canSmSw ? "" : " (secure messaging failed)");
	else if (canState == 2)
		uiText(12, y, S_BODY, uiCol[COL_ERR], "CAN %s wrong", canText);
	else if (canState == 3)
		snprintf(s, sizeof(s), "PACE failed: %s", canWhy), uiText(12, y, S_BODY, uiCol[COL_WARN], "%s", uiFit(s, UI_W - 24, S_BODY));
	else
		uiText(12, y, S_BODY, dim, "%s", ed.pace >= 0 ? "CAN not checked yet" : "");
	y += LINE_H + 4;

	// EF.CardAccess
	float h = INFO_ROWS * SMALL_H + 6;
	uiRect(8, y, UI_W - 16, h + SMALL_H, uiCol[COL_PANEL]);
	if (!ed.accessLen) {
		uiText(14, y + 3, S_SMALL, dim, "No EF.CardAccess");
	} else {
		uiText(14, y + 3, S_SMALL, dim, "EF.CardAccess: %d entr%s (%u bytes)", ed.ninfo, ed.ninfo == 1 ? "y" : "ies",
			ed.accessLen);
		if (ed.ninfo > INFO_ROWS) uiTextRight(UI_W - 14, y + 3, S_SMALL, dim, "%d-%d of %d  " BTN_UD, il.top + 1,
			il.top + INFO_ROWS < ed.ninfo ? il.top + INFO_ROWS : ed.ninfo, ed.ninfo);
		for (int i = 0; i < INFO_ROWS && il.top + i < ed.ninfo; i++) {
			const EidInfo *x = &ed.info[il.top + i];
			eidInfoText(x, s, sizeof(s));
			uiText(14, y + 3 + (i + 1) * SMALL_H, S_SMALL, il.top + i == ed.pace ? uiCol[COL_ACCENT] : txt, "%s",
				uiFit(s, UI_W - 28, S_SMALL));
		}
	}
	y += h + SMALL_H + 2;
	if (de) uiText(12, y, S_SMALL, dim, "%s", "Name, photo, MRZ: only for terminals with a government certificate");

	uiFooter(ed.pace >= 0 ? BTN_A " check CAN   " BTN_X " read again   " BTN_B " back" : BTN_X " read again   " BTN_B " back");
}

static void eidInput(u32 kDown, u32 kRepeat)
{
	int max = ed.ninfo > INFO_ROWS ? ed.ninfo - INFO_ROWS : 0;
	if (kRepeat & KEY_UP) il.top--;
	if (kRepeat & KEY_DOWN) il.top++;
	il.top = il.top < 0 ? 0 : il.top > max ? max : il.top;
	if ((kDown & KEY_A) && ed.pace >= 0) checkCan();
	if (kDown & KEY_X) {
		appBack();
		eidOpenTool();
	}
	if (kDown & KEY_B) appBack();
}

static const Screen eidScreen = { NULL, eidInput, eidDraw };
