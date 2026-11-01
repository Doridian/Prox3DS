// Amiibo screen (NTAG215): the figure decrypted with this console's own keys (amiibo.h), and copying it
// onto a blank NTAG215, its save data kept or reset to a new figure, optionally locked like a real one.

#include <stdio.h>
#include <string.h>
#include <3ds.h>

#include "amiibo.h"
#include "app.h"
#include "mfu.h"
#include "probe.h"
#include "ui.h"

enum { AM_READ, AM_COPY, AM_FILE };

// am / amTag / amCard: what the screen shows (UI thread only); the job's copies are taken over in done()
static Amiibo am, amJob;
static u8 amTag[AMIIBO_TAG], amJobTag[AMIIBO_TAG];
static Card amCard, amJobCard;
static char amName[64], amJobName[64]; // where it came from: "" = a card, else the dump's file name
static int amMode;
static bool amFresh, amLock;
// 1 ok, 0 refused (amWhy), -1 chip, -2 no card / cancelled, -3 the source card itself, -4 not an
// NTAG215, -5 no keys
static int amResult;
static char amWhy[120];

static const Screen amiiboScreen;

static void tagFromDump(const MfuDump *d, u8 *tag)
{
	memset(tag, 0, AMIIBO_TAG);
	for (int p = 0; p < AMIIBO_TAG / 4 && p < d->pages; p++)
		if (d->valid[p]) memcpy(tag + 4 * p, d->data[p], 4);
}

static bool isAmiiboTag(const MfuDump *d)
{
	if (!d->info.type || strcmp(d->info.type->name, "NTAG215")) return false;
	for (int p = 0; p < 0x82; p++) // what the HMACs cover; PWD / PACK read as zeros anyway
		if (!d->valid[p]) return false;
	return true;
}

// Card from a tag's pages 0-1 (UID0-2, BCC0, UID3-6)
static void cardFromTag(const u8 *tag, Card *c)
{
	memset(c, 0, sizeof(*c));
	c->uidLen = 7;
	memcpy(c->uid, tag, 3);
	memcpy(c->uid + 3, tag + 4, 4);
	c->atqa[1] = 0x44;
}

static int readBack(void)
{
	static MfuDump d;
	int r = mfuDumpCard(&d, NULL);
	if (r <= 0) {
		snprintf(amWhy, sizeof(amWhy), "%s", mfuWhy());
		return r;
	}
	if (!isAmiiboTag(&d)) return -4;
	amJobCard = card;
	amJobName[0] = 0;
	tagFromDump(&d, amJobTag);
	amiiboUnpack(amJobTag, &amJob);
	return 1;
}

static void runAmiibo(void)
{
	if (!amiiboKeysLoad()) {
		amResult = -5;
		return;
	}
	if (amMode == AM_FILE) {
		amiiboUnpack(amJobTag, &amJob);
		amResult = 1;
		return;
	}
	amResult = -2;
	if (!cardWait()) return;
	if (amMode == AM_COPY) {
		static u8 img[AMIIBO_TAG];
		u8 head[16];
		MfuInfo in;
		if (card.uidLen == amCard.uidLen && !memcmp(card.uid, amCard.uid, card.uidLen)) {
			amResult = -3;
			goto out;
		}
		if ((amResult = mfuIdentify(&in)) > 0 && (amResult = mfuRead(0, head)) > 0) {
			amResult = amiiboImage(&am, head, amFresh, img);
			if (amResult <= 0) snprintf(amWhy, sizeof(amWhy), "%s", amiiboWhy());
			else if ((amResult = mfuAmiiboWrite(img, false)) > 0 && amLock) amResult = mfuAmiiboWrite(img, true);
			if (amResult <= 0 && !amWhy[0]) snprintf(amWhy, sizeof(amWhy), "%s", mfuWhy());
		} else {
			snprintf(amWhy, sizeof(amWhy), "%s", mfuWhy());
		}
		logp("amiibo copy (%s%s): %s\n", amFresh ? "fresh" : "kept", amLock ? ", locked" : "", amResult > 0 ? "ok" : amWhy);
		if (amResult <= 0) goto out;
	}
	amResult = readBack();
out:
	iso14aParity(true);
}

static void doneAmiibo(void)
{
	switch (amResult) {
	case -2: return;
	case -1: msgBox("Amiibo", "The chip stopped answering."); return;
	case -3:
		msgBox("Amiibo", "That is the Amiibo itself: take it off and put the blank NTAG215 on the reader.");
		return;
	case -4:
		msgBox("Amiibo", amMode == AM_COPY ? "Written, but the read-back is not a whole NTAG215."
			: "Not an Amiibo: an Amiibo is an NTAG215 whose first 130 pages all read.");
		return;
	case -5: msgBox("Amiibo", "Could not get the Amiibo keys from this console:\n%s", amiiboWhy()); return;
	case 0:
		msgBox("Amiibo", amMode == AM_COPY ? "Not written: %s" : "No Ultralight / NTAG answer: %s", amWhy);
		return;
	}
	am = amJob;
	memcpy(amTag, amJobTag, AMIIBO_TAG);
	amCard = amJobCard;
	memcpy(amName, amJobName, sizeof(amName));
	if (appTop() != &amiiboScreen) appScreen(&amiiboScreen);
	if (amMode == AM_COPY)
		toast(am.ok ? "Copied and read back: it verifies" : "Copied, but the read-back does NOT verify");
}

static void start(int mode)
{
	amMode = mode;
	amWhy[0] = 0;
	jobStart(mode == AM_COPY ? "Writing the Amiibo" : mode == AM_FILE ? "Decrypting" : "Reading the Amiibo", runAmiibo,
		doneAmiibo, mode != AM_FILE);
}

static void copyGo(void)
{
	start(AM_COPY);
}

static void copyAsk(bool fresh, bool lock)
{
	amFresh = fresh, amLock = lock;
	confirm(lock ? "Copy and lock" : "Copy", copyGo,
		"Take the Amiibo off and put a blank NTAG215 on the reader.\n"
		"It gets this figure%s, signed for its own UID.\n%s",
		fresh ? " as a new one (no owner, nickname or game data)" : " with its owner, nickname and game data",
		lock ? "Then it is LOCKED like a real Amiibo, for good: this app can't rewrite it (games still save to it)."
		     : "Not locked: it can be written again; the 3DS reads it all the same.");
}

static void copyKeep(void) { copyAsk(false, false); }
static void copyKeepLock(void) { copyAsk(false, true); }
static void copyFresh(void) { copyAsk(true, false); }
static void copyFreshLock(void) { copyAsk(true, true); }

static void actions(void)
{
	static const MenuItem items[] = {
		{ "Copy onto a blank NTAG215", copyKeep },
		{ "Copy and lock (permanent)", copyKeepLock },
		{ "Copy as a new figure (reset)", copyFresh },
		{ "New figure, locked (permanent)", copyFreshLock },
	};
	if (!am.ok) {
		msgBox("Amiibo", "It does not verify with this console's keys, so there is nothing to copy.");
		return;
	}
	popup("Amiibo", items, 4);
}

static void amiiboInput(u32 kDown, u32 kRepeat)
{
	if (kDown & KEY_A) start(AM_READ);
	if (kDown & KEY_X) actions();
	if (kDown & KEY_B) appBack();
}

static void fmtDate(char *out, u16 v)
{
	if (v) sprintf(out, "%d-%02d-%02d", 2000 + (v >> 9), v >> 5 & 15, v & 31);
	else strcpy(out, "-");
}

static void row(float *y, const char *label, u32 col, const char *fmt, const char *val)
{
	uiText(14, *y, S_SMALL, uiCol[COL_DIM], "%s", label);
	char s[120];
	snprintf(s, sizeof(s), fmt, val);
	uiText(110, *y, S_SMALL, col, "%s", uiFit(s, UI_W - 124, S_SMALL));
	*y += SMALL_H + 3;
}

static void amiiboDraw(void)
{
	static const char *const figTypes[] = { "figure", "card", "yarn", "band" };
	char uid[32], s[120], d1[16], d2[16];
	uidHex(&amCard, uid, " ");
	uiHeader("Amiibo", uid);
	u32 txt = uiCol[COL_TEXT];
	float y = 28;
	if (amName[0]) uiTextRight(UI_W - 12, y + 2, S_SMALL, uiCol[COL_DIM], "%s", uiFit(strcpy(s, amName), 200, S_SMALL));
	const u8 *c = am.charId;
	uiText(12, y, S_BODY, txt, "%02X%02X %02X%02X %02X%02X %02X%02X", c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]);
	y += LINE_H + 4;
	if (am.ok) uiText(12, y, S_SMALL, uiCol[COL_OK], "Verified with this console's keys (set %d)", am.set);
	else uiText(12, y, S_SMALL, uiCol[COL_ERR], "Does NOT verify with this console's keys: not an Amiibo, or damaged");
	y += SMALL_H + 8;
	snprintf(s, sizeof(s), "character %02X%02X, variant %02X, %s", c[0], c[1], c[2], c[3] < 4 ? figTypes[c[3]] : "type ?");
	row(&y, "Figure", txt, "%s", s);
	snprintf(s, sizeof(s), "model %02X%02X, series %02X", c[4], c[5], c[6]);
	row(&y, "Model", txt, "%s", s);
	row(&y, "Nickname", am.nickname[0] ? txt : uiCol[COL_DIM], "%s", am.nickname[0] ? am.nickname : "(none)");
	if (am.ok) {
		row(&y, "Owner", am.registered ? txt : uiCol[COL_DIM], "%s", am.registered ? am.owner : "not set up (new figure)");
		fmtDate(d1, am.setupDate), fmtDate(d2, am.writeDate);
		row(&y, "Set up", am.setupDate ? txt : uiCol[COL_DIM], "%s", d1);
		snprintf(s, sizeof(s), "%s, %u writes", d2, am.writes);
		row(&y, "Last written", txt, "%s", s);
		snprintf(s, sizeof(s), "app ID %08lX", (unsigned long)am.appId);
		row(&y, "Game data", am.hasAppData ? txt : uiCol[COL_DIM], "%s", am.hasAppData ? s : "none");
	}
	const u8 *p2 = amTag + 8;
	snprintf(s, sizeof(s), "static lock %02X%02X: %s", p2[2], p2[3], p2[2] || p2[3] ? "locked like a real Amiibo" : "not locked");
	row(&y, "Tag", txt, "%s", s);
	uiFooter(am.ok ? BTN_A " read again   " BTN_X " copy   " BTN_B " back" : BTN_A " read again   " BTN_B " back");
}

static const Screen amiiboScreen = { NULL, amiiboInput, amiiboDraw };

void amiiboOpenCard(void)
{
	start(AM_READ);
}

void amiiboOpenDump(const MfuDump *d, const char *name)
{
	if (!isAmiiboTag(d)) {
		msgBox("Amiibo", "%s is not a whole NTAG215 dump.", name);
		return;
	}
	tagFromDump(d, amJobTag);
	cardFromTag(amJobTag, &amJobCard);
	snprintf(amJobName, sizeof(amJobName), "%s", name);
	start(AM_FILE);
}
