// Card emulation screens (emu.c): an NFC Forum Type 4 tag carrying an NDEF message, a card's UID for
// UID-only readers, and an APDU log that shows what a reader sends.

#include <stdio.h>
#include <string.h>
#include <3ds.h>

#include "app.h"
#include "emu.h"
#include "entry.h"
#include "ndef.h"
#include "probe.h"
#include "ui.h"

static enum { MODE_NDEF, MODE_UID, MODE_LOG } mode;
static EmuId runId; // MODE_UID: what to be
static bool emuOk;
static int nrules;

// The message's first record in words (and how many there are).
static void describeMsg(const u8 *msg, u32 len, char *out, u32 max)
{
	NdefRec recs[NDEF_MAX_RECS];
	if (!len) {
		snprintf(out, max, "an empty NDEF message");
		return;
	}
	int n = ndefParse(msg, len, recs, NDEF_MAX_RECS);
	if (n <= 0) {
		snprintf(out, max, "%lu bytes, not a valid NDEF message", (unsigned long)len);
		return;
	}
	char s[200];
	ndefDescribe(&recs[0], s, sizeof(s));
	if (n > 1) snprintf(out, max, "%s (+%d more record%s)", s, n - 1, n > 2 ? "s" : "");
	else snprintf(out, max, "%s", s);
}

static void runEmu(void)
{
	if (mode == MODE_LOG) nrules = emuLogLoad();
	emuOk = emuRun(mode == MODE_UID ? &runId : NULL, mode == MODE_NDEF ? emuNdefApdu : emuLogApdu);
	emuLogClose();
}

static void doneEmu(void)
{
	if (!emuOk) {
		msgBox("Emulate", "The chip did not take the card mode setup.");
		return;
	}
	if (mode == MODE_NDEF && emuNdefWrites()) {
		u32 len;
		const u8 *msg = emuNdefGet(&len);
		char s[300];
		describeMsg(msg, len, s, sizeof(s));
		msgBox("Emulate", "A reader wrote a new message onto the 3DS:\n%s", s);
		return;
	}
	if (mode != MODE_NDEF && emu.apdus) {
		msgBox("APDU log", "%lu APDU%s in %lu session%s, appended to\n" EMU_APDU_LOG, (unsigned long)emu.apdus,
			emu.apdus == 1 ? "" : "s", (unsigned long)emu.sessions, emu.sessions == 1 ? "" : "s");
		return;
	}
	if (emu.id.sak & 0x20)
		toast("Stopped: %lu reader session%s, %lu APDU%s", (unsigned long)emu.sessions, emu.sessions == 1 ? "" : "s",
			(unsigned long)emu.apdus, emu.apdus == 1 ? "" : "s");
	else toast("Stopped: %lu reader field%s", (unsigned long)emu.fields, emu.fields == 1 ? "" : "s");
}

static float emuView(float x, float y, float w)
{
	u32 dim = uiCol[COL_DIM], txt = uiCol[COL_TEXT];
	float y0 = y;
	char u[32], s[300];
	emuUidHex(&emu.id, u);
	const char *what = mode == MODE_NDEF ? "Type 4 tag" : mode == MODE_LOG ? "APDU log" : "UID only";
	uiText(x, y, S_SMALL, dim, "%s, UID %s, ATQA %02X%02X, SAK %02X", what, u, emu.id.atqa[1], emu.id.atqa[0], emu.id.sak);
	y += SMALL_H + 2;
	bool iso = emu.id.sak & 0x20;
	const char *st = emu.active ? "Reader connected" : emu.field ? (iso ? "Reader field, not connected" : "Reader field")
	                                                             : "Waiting for a reader";
	uiText(x, y, S_BODY, uiCol[emu.active ? COL_OK : emu.field ? COL_WARN : COL_ACCENT], "%s", st);
	if (iso)
		uiTextRight(x + w, y + 2, S_SMALL, dim, "%lu field%s, %lu session%s, %lu APDU%s", (unsigned long)emu.fields,
			emu.fields == 1 ? "" : "s", (unsigned long)emu.sessions, emu.sessions == 1 ? "" : "s",
			(unsigned long)emu.apdus, emu.apdus == 1 ? "" : "s");
	else uiTextRight(x + w, y + 2, S_SMALL, dim, "%lu field%s", (unsigned long)emu.fields, emu.fields == 1 ? "" : "s");
	y += LINE_H + 2;
	if (mode == MODE_NDEF) {
		u32 len;
		const u8 *msg = emuNdefGet(&len);
		describeMsg(msg, len, s, sizeof(s));
		u32 wr = emuNdefWrites();
		uiText(x, y, S_SMALL, wr ? uiCol[COL_WARN] : txt, "%s", uiFit(s, w, S_SMALL));
		y += SMALL_H;
		if (wr) uiText(x, y, S_SMALL, uiCol[COL_WARN], "Written by a reader (%lu UPDATE BINARY)", (unsigned long)wr);
		else uiText(x, y, S_SMALL, dim, "Readers may overwrite it (the tag is writable)");
	} else if (mode == MODE_LOG) {
		uiText(x, y, S_SMALL, txt, "%d answer%s from " EMU_RULES ", else 6A82 / 6D00", nrules, nrules == 1 ? "" : "s");
		y += SMALL_H;
		uiText(x, y, S_SMALL, dim, "Every APDU goes to " EMU_APDU_LOG);
	} else if (iso) {
		uiText(x, y, S_SMALL, txt, "ISO-DEP: the ROM answers RATS, APDUs get 6A82 / 6D00");
		y += SMALL_H;
		uiText(x, y, S_SMALL, dim, "Every APDU goes to " EMU_APDU_LOG);
	} else {
		uiText(x, y, S_SMALL, txt, "Anticollision only: for readers that just check the UID");
		y += SMALL_H;
		uiText(x, y, S_SMALL, dim, "Reading memory or authenticating gets no answer");
	}
	y += SMALL_H + 4;
	u32 n = emu.nlog < EMU_LOG_N ? emu.nlog : EMU_LOG_N;
	for (u32 i = 0; i < n; i++, y += 11)
		uiMonoS(x, y, 0.34f, 5.6f, dim, emu.log[(emu.nlog - n + i) % EMU_LOG_N]);
	return y - y0;
}

static void start(void)
{
	jobNextHint("Tap a phone on the bottom screen.");
	jobStartView(mode == MODE_NDEF ? "Emulating a tag" : mode == MODE_LOG ? "APDU log" : "Emulating a UID", runEmu,
		doneEmu, true, emuView);
}

void emuStartNdef(const u8 *msg, u32 len)
{
	mode = MODE_NDEF;
	emuNdefSet(msg, len);
	start();
}

static void startUid(const EmuId *id)
{
	mode = MODE_UID;
	runId = *id;
	start();
}

void emuStartUid(const Card *c)
{
	EmuId id = { .uidLen = c->uidLen, .sak = c->sak };
	memcpy(id.uid, c->uid, c->uidLen);
	memcpy(id.atqa, c->atqa, 2);
	startUid(&id);
}

void emuStartMfuNdef(const MfuDump *d, const char *name)
{
	static u8 mem[4 * MFU_MAX_PAGES];
	u32 n = 0, off, len;
	int end = d->info.type ? d->info.type->userEnd : d->pages;
	for (int p = 4; p < end && p < d->pages && d->valid[p]; p++, n += 4)
		memcpy(mem + n, d->data[p], 4);
	int t = ndefFindTlv(mem, n, &off, &len);
	if (t <= 0) {
		msgBox("Emulate", t < 0 ? "The TLVs in %s's user memory are broken." : "%s holds no NDEF message.", name);
		return;
	}
	if (len > EMU_NDEF_MAX) {
		msgBox("Emulate", "The NDEF message of %s is too long (%lu bytes, %d at most).", name, (unsigned long)len,
			EMU_NDEF_MAX);
		return;
	}
	emuStartNdef(mem + off, len);
}

static void urlDone(const char *s)
{
	u8 msg[600];
	if (!*s) return;
	u32 n = ndefUri(s, msg, sizeof(msg));
	if (!n) {
		msgBox("Emulate", "That is too long for an NDEF record here.");
		return;
	}
	emuStartNdef(msg, n);
}

static void startUrl(void)
{
	entryText("Emulate a URL", "https://..., tel:..., mailto:...", "https://", 511, 0, urlDone);
}

static void textDone(const char *s)
{
	u8 msg[600];
	if (!*s) return;
	u32 n = ndefText("en", s, msg, sizeof(msg));
	if (!n) {
		msgBox("Emulate", "That is too long for an NDEF record here.");
		return;
	}
	emuStartNdef(msg, n);
}

static void startText(void)
{
	entryText("Emulate text", "A text record (language en).", "", 511, 0, textDone);
}

static void startEmpty(void)
{
	emuStartNdef(NULL, 0);
}

// --- a UID, typed or from a card ---

static EmuId form = { { 0x01, 0x02, 0x03, 0x04 }, 4, { 0x04, 0x00 }, 0x08 };

static void uidV(char *o)
{
	emuUidHex(&form, o);
	sprintf(o + strlen(o), " (%d bytes)", form.uidLen);
}

static void uidSet(const char *s)
{
	u8 b[10];
	int n = 0;
	for (unsigned v; n < 10 && s[2 * n] && s[2 * n + 1] && sscanf(s + 2 * n, "%2x", &v) == 1; n++) b[n] = v;
	if (n != 4 && n != 7 && n != 10) {
		msgBox("UID", "A UID has 4, 7 or 10 bytes (%d typed).", n);
		return;
	}
	memcpy(form.uid, b, n);
	form.uidLen = n;
}

static void uidE(void)
{
	char cur[24];
	emuUidHex(&form, cur);
	entryText("UID", "4, 7 or 10 bytes in hex.", cur, 20, ENTRY_HEX, uidSet);
}

static void atqaV(char *o)
{
	sprintf(o, "%02X%02X", form.atqa[1], form.atqa[0]);
}

static void atqaSet(const u8 *b, u32 len)
{
	form.atqa[1] = b[0], form.atqa[0] = b[1];
}

static void atqaE(void)
{
	u8 cur[2] = { form.atqa[1], form.atqa[0] };
	entryHex("ATQA", "As pm3 shows it (0004 Classic 1K, 0044 Ultralight / NTAG). The UID size bits follow the "
		"UID's length.", 2, cur, atqaSet);
}

static void sakV(char *o)
{
	sprintf(o, "%02X%s", form.sak, form.sak & 0x20 ? " (ISO-DEP)" : "");
}

static void sakSet(const u8 *b, u32 len)
{
	form.sak = b[0];
}

static void sakE(void)
{
	entryHex("SAK", "08 Classic 1K, 18 Classic 4K, 00 Ultralight / NTAG, 20 ISO-DEP (gets RATS, APDUs logged).", 1,
		&form.sak, sakSet);
}

static const Field uidFields[] = { { "UID", uidV, uidE }, { "ATQA", atqaV, atqaE }, { "SAK", sakV, sakE } };

static int uidCount(void)
{
	return 3;
}

static void uidRun(void)
{
	startUid(&form);
}

static void startTyped(void)
{
	if (card.uidLen) { // the last card the app saw
		memcpy(form.uid, card.uid, card.uidLen);
		form.uidLen = card.uidLen;
		memcpy(form.atqa, card.atqa, 2);
		form.sak = card.sak;
	}
	formOpen("Emulate a UID", "Emulate", "What a reader sees in anticollision. Only readers that check nothing but "
		"the UID take it: no memory, no keys.", uidFields, uidCount, uidRun);
}

static bool scanned;

static void runScan(void)
{
	scanned = cardWait();
}

static void doneScan(void)
{
	if (scanned) startTyped();
}

static void startScan(void)
{
	jobStart("Scanning the card to copy", runScan, doneScan, true);
}

static void startLog(void)
{
	mode = MODE_LOG;
	start();
}

static const MenuEntry emuEntries[] = {
	{ "NDEF tag: URL", "Act as an NFC Forum Type 4 tag holding a URL: a phone held to the 3DS opens it. The tag is "
	                   "writable, so a phone can also write a new message onto it.", startUrl },
	{ "NDEF tag: text", "The same with a text record (language en).", startText },
	{ "NDEF tag: empty", "An empty, writable tag: write a message onto the 3DS with a phone (NFC Tools and the like) "
	                     "and see what it wrote.", startEmpty },
	{ "Copy a card's UID", "Scan a card, then answer with its UID, ATQA and SAK (editable first). For readers that "
	                       "only check the UID.", startScan },
	{ "Card UID", "Type a UID, ATQA and SAK (the last card scanned to start with).", startTyped },
	{ "APDU log", "Act as an empty smart card and see what a reader sends. Answers come from " EMU_RULES
	              " (\"<command prefix> <response>\" in hex per line), else 6A82 / 6D00.", startLog },
};

static void emuExtra(float x, float y, float w)
{
	uiTextWrap(x, y, w, S_SMALL, uiCol[COL_DIM], "The 3DS answers as a card through its NFC antenna under the bottom "
		"screen. A phone works with a quick tap on the bottom screen. Readers like a Proxmark want the 3DS lying "
		"on them, bottom screen down.");
}

static Menu emuMenu = { "Emulate (card mode)", emuEntries, sizeof(emuEntries) / sizeof(emuEntries[0]), emuExtra };

static void emuMenuInput(u32 kDown, u32 kRepeat)
{
	menuInput(&emuMenu, kDown, kRepeat);
}

static void emuMenuDraw(void)
{
	menuDraw(&emuMenu);
}

static const Screen emuMenuScreen = { NULL, emuMenuInput, emuMenuDraw };

void emuOpenMenu(void)
{
	appScreen(&emuMenuScreen);
}
