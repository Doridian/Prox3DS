// Card emulation screens: the 3DS as an NFC Forum Type 4 tag carrying an NDEF message (emu.c).

#include <stdio.h>
#include <string.h>
#include <3ds.h>

#include "app.h"
#include "emu.h"
#include "entry.h"
#include "ndef.h"
#include "probe.h"
#include "ui.h"

static bool emuOk;

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
	emuOk = emuRun(emuNdefApdu);
}

static void doneEmu(void)
{
	if (!emuOk) {
		msgBox("Emulate", "The chip did not take the card mode setup.");
		return;
	}
	if (emuNdefWrites()) {
		u32 len;
		const u8 *msg = emuNdefGet(&len);
		char s[300];
		describeMsg(msg, len, s, sizeof(s));
		msgBox("Emulate", "A reader wrote a new message onto the 3DS:\n%s", s);
		return;
	}
	toast("Stopped: %lu reader session%s, %lu APDU%s", (unsigned long)emu.sessions, emu.sessions == 1 ? "" : "s",
		(unsigned long)emu.apdus, emu.apdus == 1 ? "" : "s");
}

static float emuView(float x, float y, float w)
{
	u32 dim = uiCol[COL_DIM], txt = uiCol[COL_TEXT];
	float y0 = y;
	uiText(x, y, S_SMALL, dim, "Type 4 tag, UID %02X %02X %02X %02X, ATQA 0004, SAK 20", emu.uid[0],
		emu.uid[1], emu.uid[2], emu.uid[3]);
	y += SMALL_H + 2;
	const char *st = emu.active ? "Reader connected" : emu.field ? "Reader field, not connected" : "Waiting for a reader";
	uiText(x, y, S_BODY, uiCol[emu.active ? COL_OK : emu.field ? COL_WARN : COL_ACCENT], "%s", st);
	uiTextRight(x + w, y + 2, S_SMALL, dim, "%lu field%s, %lu session%s, %lu APDU%s", (unsigned long)emu.fields,
		emu.fields == 1 ? "" : "s", (unsigned long)emu.sessions, emu.sessions == 1 ? "" : "s", (unsigned long)emu.apdus,
		emu.apdus == 1 ? "" : "s");
	y += LINE_H + 2;
	char s[300];
	u32 len;
	const u8 *msg = emuNdefGet(&len);
	describeMsg(msg, len, s, sizeof(s));
	u32 wr = emuNdefWrites();
	uiText(x, y, S_SMALL, wr ? uiCol[COL_WARN] : txt, "%s", uiFit(s, w, S_SMALL));
	y += SMALL_H;
	if (wr) uiText(x, y, S_SMALL, uiCol[COL_WARN], "Written by a reader (%lu UPDATE BINARY)", (unsigned long)wr);
	else uiText(x, y, S_SMALL, dim, "Readers may overwrite it (the tag is writable)");
	y += SMALL_H + 4;
	u32 n = emu.nlog < EMU_LOG_N ? emu.nlog : EMU_LOG_N;
	for (u32 i = 0; i < n; i++, y += 11)
		uiMonoS(x, y, 0.34f, 5.6f, dim, emu.log[(emu.nlog - n + i) % EMU_LOG_N]);
	return y - y0;
}

static void start(const u8 *msg, u32 len)
{
	emuNdefSet(msg, len);
	jobNextHint("Tap a phone on the bottom screen.");
	jobStartView("Emulating a tag", runEmu, doneEmu, true, emuView);
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
	start(msg, n);
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
	start(msg, n);
}

static void startText(void)
{
	entryText("Emulate text", "A text record (language en).", "", 511, 0, textDone);
}

static void startEmpty(void)
{
	start(NULL, 0);
}

static const MenuEntry emuEntries[] = {
	{ "NDEF tag: URL", "Act as an NFC Forum Type 4 tag holding a URL: a phone held to the 3DS opens it. The tag is "
	                   "writable, so a phone can also write a new message onto it.", startUrl },
	{ "NDEF tag: text", "The same with a text record (language en).", startText },
	{ "NDEF tag: empty", "An empty, writable tag: write a message onto the 3DS with a phone (NFC Tools and the like) "
	                     "and see what it wrote.", startEmpty },
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
