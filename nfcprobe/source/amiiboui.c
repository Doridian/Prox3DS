// Amiibo screen (NTAG215): the figure decrypted with this console's own keys (amiibo.h), and copying it
// onto a blank NTAG215, its save data kept or reset to a new figure, optionally locked like a real one.
// The Amiibo menu: the figure list (amiibodb.h) to name figures and make new ones from.

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <3ds.h>

#include "amiibo.h"
#include "amiibodb.h"
#include "app.h"
#include "mfu.h"
#include "probe.h"
#include "ui.h"

enum { AM_READ, AM_COPY, AM_FILE, AM_LOCK, AM_NEW };

// am / amTag / amCard: what the screen shows (UI thread only); the job's copies are taken over in done()
static Amiibo am, amJob;
static u8 amTag[AMIIBO_TAG], amJobTag[AMIIBO_TAG];
static Card amCard, amJobCard;
static char amName[64], amJobName[64]; // where it came from: "" = a card, else the dump's file name
static int amMode;
static bool amFresh, amLock;
// what a copy writes (the figure shown, or a new one of amNewId made in the job); amSrcCard: the card
// it came from, which a copy refuses to overwrite
static Amiibo amSrc;
static Card amSrcCard;
static u8 amNewId[8];
// 1 ok, 0 refused (amWhy), -1 chip, -2 no card / cancelled, -3 the source card itself (copy) / another
// card (lock), -4 not an NTAG215, -5 no keys
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

static bool tagLocked(const u8 *tag)
{
	return tag[10] || tag[11];
}

// The lock stage on the unlocked Amiibo shown: the same image rewritten (so PWD / PACK are surely the
// ones the UID gives: AUTH0 turns the password on), PWD_AUTH checked for PACK 8080, then lock bytes and
// config, for good.
static int lockShown(void)
{
	static u8 img[AMIIBO_TAG];
	u8 pack[2];
	int r;
	if (card.uidLen != amCard.uidLen || memcmp(card.uid, amCard.uid, card.uidLen)) return -3;
	if (!amiiboImage(&am, amTag, false, img)) {
		snprintf(amWhy, sizeof(amWhy), "%s", amiiboWhy());
		return 0;
	}
	if ((r = mfuAmiiboWrite(img, false)) <= 0) return r;
	if ((r = mfuPwdAuth(img + 4 * 0x85, pack)) <= 0) {
		snprintf(amWhy, sizeof(amWhy), "the password just written does not authenticate: %s", mfuWhy());
		return r;
	}
	if (pack[0] != 0x80 || pack[1] != 0x80) {
		snprintf(amWhy, sizeof(amWhy), "PACK %02X%02X, not 8080", pack[0], pack[1]);
		return 0;
	}
	return mfuAmiiboWrite(img, true);
}

// A read that gets no answer mid-way ends the dump there (right after the lock writes, once): up to 3
// tries, the card reactivated in between.
static int readBack(void)
{
	static MfuDump d;
	for (int t = 0; t < 3; t++) {
		if (t && !iso14aStart()) return -1;
		int r = mfuDumpCard(&d, NULL);
		if (r < 0) return -1;
		if (!r) {
			snprintf(amWhy, sizeof(amWhy), "%s", mfuWhy());
			continue;
		}
		if (!isAmiiboTag(&d)) {
			if (d.info.type && !strcmp(d.info.type->name, "NTAG215")) continue; // pages missing: again
			return -4;
		}
		amJobCard = card;
		amJobName[0] = 0;
		tagFromDump(&d, amJobTag);
		amiiboUnpack(amJobTag, &amJob);
		return 1;
	}
	return amWhy[0] ? 0 : -4;
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
	if (amMode == AM_NEW && !amiiboNew(amNewId, &amSrc)) {
		amResult = 0;
		snprintf(amWhy, sizeof(amWhy), "%s", amiiboWhy());
		goto out;
	}
	if (amMode == AM_COPY || amMode == AM_NEW) {
		static u8 img[AMIIBO_TAG];
		u8 head[16];
		MfuInfo in;
		if (card.uidLen == amSrcCard.uidLen && !memcmp(card.uid, amSrcCard.uid, card.uidLen)) {
			amResult = -3;
			goto out;
		}
		if ((amResult = mfuIdentify(&in)) > 0 && (amResult = mfuRead(0, head)) > 0) {
			amResult = amiiboImage(&amSrc, head, amFresh, img);
			if (amResult <= 0) snprintf(amWhy, sizeof(amWhy), "%s", amiiboWhy());
			else if ((amResult = mfuAmiiboWrite(img, false)) > 0 && amLock) amResult = mfuAmiiboWrite(img, true);
			if (amResult <= 0 && !amWhy[0]) snprintf(amWhy, sizeof(amWhy), "%s", mfuWhy());
		} else {
			snprintf(amWhy, sizeof(amWhy), "%s", mfuWhy());
		}
		logp("amiibo %s (%s%s): %s\n", amMode == AM_NEW ? "new" : "copy", amFresh ? "fresh" : "kept", amLock ? ", locked" : "",
			amResult > 0 ? "ok" : amWhy);
		if (amResult <= 0) goto out;
	}
	if (amMode == AM_LOCK) {
		amResult = lockShown();
		if (amResult <= 0 && amResult != -3 && !amWhy[0]) snprintf(amWhy, sizeof(amWhy), "%s", mfuWhy());
		logp("amiibo lock: %s\n", amResult > 0 ? "ok" : amResult == -3 ? "another card" : amWhy);
		if (amResult <= 0) goto out;
	}
	amResult = readBack();
	if (!amResult && amMode != AM_READ) amResult = -4; // written: only the read-back failed
out:
	iso14aParity(true);
}

static bool dbTried;

// The figure list, loaded the first time it is needed
static void dbEnsure(void)
{
	if (dbTried) return;
	dbTried = true;
	int n = amiiboDbLoad(NULL);
	logp("amiibo: figure list: %d figures%s%s\n", n, n ? "" : ", ", n ? "" : amiiboDbWhy());
}

static void doneAmiibo(void)
{
	bool wrote = amMode == AM_COPY || amMode == AM_NEW;
	switch (amResult) {
	case -2: return;
	case -1: msgBox("Amiibo", "The chip stopped answering."); return;
	case -3:
		msgBox("Amiibo", amMode == AM_LOCK ? "That is another card than the one shown: nothing was written."
			: "That is the Amiibo itself: take it off and put the blank NTAG215 on the reader.");
		return;
	case -4:
		msgBox("Amiibo", wrote || amMode == AM_LOCK
			? "Written, but reading it back failed (not all 130 Amiibo pages read).\nRead it again (" BTN_A ") to check."
			: "Not an Amiibo: an Amiibo is an NTAG215 whose first 130 pages all read.");
		return;
	case -5: msgBox("Amiibo", "Could not get the Amiibo keys from this console:\n%s", amiiboWhy()); return;
	case 0:
		msgBox("Amiibo", wrote ? "Not written: %s" : amMode == AM_LOCK ? "Not locked: %s"
			: "No Ultralight / NTAG answer: %s", amWhy);
		return;
	}
	dbEnsure();
	am = amJob;
	memcpy(amTag, amJobTag, AMIIBO_TAG);
	amCard = amJobCard;
	memcpy(amName, amJobName, sizeof(amName));
	if (appTop() != &amiiboScreen) appScreen(&amiiboScreen);
	if (wrote)
		toast(am.ok ? "Written and read back: it verifies" : "Written, but the read-back does NOT verify");
	if (amMode == AM_LOCK)
		toast(tagLocked(amTag) ? "Locked and read back" : "Written, but the lock bytes read back clear");
}

static void start(int mode)
{
	amMode = mode;
	amWhy[0] = 0;
	jobStart(mode == AM_LOCK ? "Locking the Amiibo" : mode == AM_COPY || mode == AM_NEW ? "Writing the Amiibo" : mode == AM_FILE ? "Decrypting" : "Reading the Amiibo", runAmiibo,
		doneAmiibo, mode != AM_FILE);
}

static void copyGo(void)
{
	start(AM_COPY);
}

static void copyAsk(bool fresh, bool lock)
{
	amFresh = fresh, amLock = lock;
	amSrc = am, amSrcCard = amCard;
	confirm(lock ? "Copy and lock" : "Copy", copyGo,
		"Take the Amiibo off and put a blank NTAG215 on the reader.\n"
		"It gets this figure%s, signed for its own UID.\n%s",
		fresh ? " as a new one (no owner, nickname or game data)" : " with its owner, nickname and game data",
		lock ? "Then it is LOCKED like a real Amiibo, for good: this app can't rewrite it (games still save to it)."
		     : "Not locked: it can be written again; the 3DS reads it all the same.");
}

static void lockGo(void)
{
	start(AM_LOCK);
}

static void lockAsk2(void)
{
	confirm("Really lock it?", lockGo, "Last chance. Once locked, this tag can never be rewritten or reused for "
		"another Amiibo, by this app or anything else. Games can still save to it.\nLock it for good?");
}

static void lockAsk(void)
{
	char uid[32];
	uidHex(&amCard, uid, "");
	confirm("Lock the Amiibo", lockAsk2, "Lock %s like a real Amiibo? It sets the lock bits and the config, and the "
		"password goes live. This is PERMANENT.\nLeave this tag on the reader.", uid);
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
	static MenuItem withLock[5];
	memcpy(withLock, items, sizeof(items));
	withLock[4] = (MenuItem){ "Lock this tag (permanent)", lockAsk };
	// only for the card just read: a dump can't be locked, a locked tag is already
	popup("Amiibo", withLock, !amName[0] && !tagLocked(amTag) ? 5 : 4);
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

static void fmtId(char *out, const u8 *c)
{
	sprintf(out, "%02X%02X %02X%02X %02X%02X %02X%02X", c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]);
}

static void amiiboDraw(void)
{
	static const char *const figTypes[] = { "figure", "card", "yarn", "band" };
	char uid[32], s[120], d1[16], d2[16], id[24];
	uidHex(&amCard, uid, " ");
	uiHeader("Amiibo", uid);
	u32 txt = uiCol[COL_TEXT];
	float y = 28, right = 12;
	const u8 *c = am.charId;
	const AmiiboDbEnt *e = amiiboDbFind(c);
	fmtId(id, c);
	if (amName[0]) right += uiTextWidth(S_SMALL, uiFit(strcpy(s, amName), 200, S_SMALL)) + 10;
	if (amName[0]) uiTextRight(UI_W - 12, y + 2, S_SMALL, uiCol[COL_DIM], "%s", s);
	snprintf(s, sizeof(s), "%s", e ? e->name : id);
	uiText(12, y, S_BODY, txt, "%s", uiFit(s, UI_W - 12 - right, S_BODY));
	y += LINE_H + 4;
	if (am.ok) uiText(12, y, S_SMALL, uiCol[COL_OK], "Verified with this console's keys (set %d)", am.set);
	else uiText(12, y, S_SMALL, uiCol[COL_ERR], "Does NOT verify with this console's keys: not an Amiibo, or damaged");
	y += SMALL_H + 8;
	const char *ch = amiiboDbCharacter(c), *game = amiiboDbGame(c), *type = amiiboDbType(c), *ser = amiiboDbSeries(c);
	char t[16];
	if (!type) type = c[3] < 4 ? figTypes[c[3]] : (sprintf(t, "type %02X", c[3]), t);
	if (game && ch && !strcmp(game, ch)) game = NULL;
	if (ch) snprintf(s, sizeof(s), "%s%s%s%s, variant %02X, %s", ch, game ? " (" : "", game ? game : "", game ? ")" : "", c[2], type);
	else snprintf(s, sizeof(s), "character %02X%02X, variant %02X, %s", c[0], c[1], c[2], type);
	row(&y, "Figure", txt, "%s", s);
	if (ser) snprintf(s, sizeof(s), "%s, %s series", id, ser);
	else snprintf(s, sizeof(s), "%s, model %02X%02X, series %02X", id, c[4], c[5], c[6]);
	row(&y, "Model", e ? txt : uiCol[COL_WARN], "%s", s);
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
	snprintf(s, sizeof(s), "static lock %02X%02X: %s", p2[2], p2[3], tagLocked(amTag) ? "locked like a real Amiibo" : "not locked");
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

// --- the figure list: new figures ---

#define LIST_ROWS 11

static int *vis, nvis; // the figures shown (indexes into the list): all, or those matching filter
static char filter[48];
static UiList fl;

static bool has(const char *s, const char *f)
{
	for (; s && *s; s++) {
		int i = 0;
		while (f[i] && tolower((u8)s[i]) == tolower((u8)f[i])) i++;
		if (!f[i]) return true;
	}
	return false;
}

static bool matches(const AmiiboDbEnt *e)
{
	return !filter[0] || has(e->name, filter) || has(e->series, filter) || has(amiiboDbGame(e->id), filter)
		|| has(amiiboDbCharacter(e->id), filter);
}

static void listFilter(void)
{
	int n = amiiboDbCount();
	free(vis);
	vis = malloc((n ? n : 1) * sizeof(int));
	nvis = 0;
	for (int i = 0; vis && i < n; i++)
		if (matches(amiiboDbAt(i))) vis[nvis++] = i;
	fl.sel = fl.top = 0;
}

static const AmiiboDbEnt *listSel(void)
{
	return nvis ? amiiboDbAt(vis[fl.sel]) : NULL;
}

static void newGo(void)
{
	start(AM_NEW);
}

static void newAsk(bool lock)
{
	const AmiiboDbEnt *e = listSel();
	memcpy(amNewId, e->id, 8);
	amFresh = true, amLock = lock;
	memset(&amSrcCard, 0, sizeof(amSrcCard));
	char id[24];
	fmtId(id, e->id);
	confirm(lock ? "New Amiibo, locked" : "New Amiibo", newGo,
		"Put a blank NTAG215 on the reader.\nIt becomes a new %s (%s): not set up yet, signed for its own UID "
		"with this console's keys.\n%s", e->name, id,
		lock ? "Then it is LOCKED like a real Amiibo, for good: this app can't rewrite it (games still save to it)."
		     : "Not locked: it can be written again; the 3DS reads it all the same.");
}

static void newPlain(void) { newAsk(false); }
static void newLocked(void) { newAsk(true); }

// Previous (dir -1) / next series in the list shown
static void seriesJump(int dir)
{
	if (!nvis) return;
	const char *cur = listSel()->series;
	int i = fl.sel;
	if (dir > 0) {
		while (i < nvis && !strcmp(amiiboDbAt(vis[i])->series, cur)) i++;
		if (i == nvis) return;
	} else {
		while (i > 0 && !strcmp(amiiboDbAt(vis[i - 1])->series, cur)) i--; // this series' first
		if (i == fl.sel && i > 0) { // already there: the previous one's first
			cur = amiiboDbAt(vis[--i])->series;
			while (i > 0 && !strcmp(amiiboDbAt(vis[i - 1])->series, cur)) i--;
		}
	}
	fl.sel = i;
	fl.top = i; // the series starts at the top
	if (fl.top > nvis - LIST_ROWS) fl.top = nvis > LIST_ROWS ? nvis - LIST_ROWS : 0;
}

static void listInput(u32 kDown, u32 kRepeat)
{
	uiListNav(&fl, nvis, LIST_ROWS, kRepeat);
	if (kDown & KEY_L) seriesJump(-1);
	if (kDown & KEY_R) seriesJump(1);
	if (kDown & KEY_Y) {
		if (!textInput("Name, series or game (empty: all)", filter, filter, sizeof(filter))) filter[0] = 0;
		listFilter();
	}
	if ((kDown & KEY_A) && nvis) {
		static const MenuItem items[] = {
			{ "Write onto a blank NTAG215", newPlain },
			{ "Write and lock (permanent)", newLocked },
		};
		popup(listSel()->name, items, 2);
	}
	if (kDown & KEY_B) appBack();
}

static void listDraw(void)
{
	char hdr[48], s[96], id[24];
	if (filter[0]) snprintf(hdr, sizeof(hdr), "%d of %d", nvis, amiiboDbCount());
	else snprintf(hdr, sizeof(hdr), "%d figures", nvis);
	uiHeader("New Amiibo", hdr);
	if (!nvis) {
		uiTextCenter(UI_W / 2, 100, S_BODY, uiCol[COL_DIM], "No figure matches \"%s\".", filter);
		uiTextCenter(UI_W / 2, 118, S_SMALL, uiCol[COL_DIM], "Search again with " BTN_Y " (empty: all of them).");
		uiFooter(BTN_Y " search   " BTN_B " back");
		return;
	}
	for (int i = 0; i < LIST_ROWS && fl.top + i < nvis; i++) {
		const AmiiboDbEnt *e = amiiboDbAt(vis[fl.top + i]);
		float y = 24 + i * LINE_H;
		if (fl.top + i == fl.sel) uiRect(4, y - 1, UI_W - 8, LINE_H, uiCol[COL_SEL]);
		snprintf(s, sizeof(s), "%s", e->series);
		float w = uiTextWidth(S_SMALL, uiFit(s, 150, S_SMALL));
		uiTextRight(UI_W - 10, y + 1, S_SMALL, uiCol[COL_DIM], "%s", s);
		snprintf(s, sizeof(s), "%s", e->name);
		uiText(10, y, S_BODY, uiCol[COL_TEXT], "%s", uiFit(s, UI_W - 30 - w, S_BODY));
	}
	const AmiiboDbEnt *e = listSel();
	const char *ch = amiiboDbCharacter(e->id), *game = amiiboDbGame(e->id), *type = amiiboDbType(e->id);
	fmtId(id, e->id);
	float y = 24 + LIST_ROWS * LINE_H + 4;
	uiText(10, y, S_SMALL, uiCol[COL_ACCENT], "%s", id);
	snprintf(s, sizeof(s), "%s%s%s%s%s", ch ? ch : "", ch && game ? " / " : "", game ? game : "", type && (ch || game) ? ", " : "",
		type ? type : "");
	uiTextRight(UI_W - 10, y, S_SMALL, uiCol[COL_DIM], "%s", uiFit(s, UI_W - 150, S_SMALL));
	uiFooter(BTN_A " write   " BTN_Y " search   " BTN_L " prev series   " BTN_R " next series   " BTN_B " back");
}

static const Screen listScreen = { NULL, listInput, listDraw };

static void openList(void)
{
	dbEnsure();
	if (!amiiboDbCount()) {
		msgBox("New Amiibo", "No figure list yet: download it first (needs Wi-Fi).\n%s", amiiboDbWhy());
		return;
	}
	listFilter();
	appScreen(&listScreen);
}

// --- the Amiibo menu ---

static int dlResult;

static void runDownload(void)
{
	dlResult = amiiboDbDownload(AMIIBO_DB ".new");
}

static void doneDownload(void)
{
	if (!dlResult) {
		msgBox("Figure list", "Download failed: %s\n" AMIIBO_DB_URL, amiiboWhy());
		return;
	}
	int n = amiiboDbLoad(AMIIBO_DB ".new");
	if (!n) {
		remove(AMIIBO_DB ".new");
		msgBox("Figure list", "The download is not a figure list: %s", amiiboDbWhy());
		return;
	}
	remove(AMIIBO_DB);
	rename(AMIIBO_DB ".new", AMIIBO_DB);
	dbTried = true;
	logp("amiibo: figure list updated, %d figures\n", n);
	toast("Figure list: %d figures", n);
}

static void startDownload(void)
{
	jobStart("Downloading the figure list", runDownload, doneDownload, false);
}

static const MenuEntry amEntries[] = {
	{ "Read Amiibo", "Decrypt the NTAG215 on the reader with this console's own keys: figure, owner, nickname, game "
	                 "data. Copy it onto a blank NTAG215 from there.", amiiboOpenCard },
	{ "New Amiibo", "Pick a figure from the list and write it onto a blank NTAG215 as a new, not yet set up Amiibo.",
	  openList },
	{ "Download figure list", "Fetch AmiiboAPI's figure list (about 180 KB, over Wi-Fi) to " AMIIBO_DB ": figure "
	                          "names on the Amiibo screen, and the list new ones are made from.", startDownload },
};

static void amExtra(float y)
{
	dbEnsure();
	if (amiiboDbCount()) uiText(12, y, S_SMALL, uiCol[COL_DIM], "Figure list: %d figures (" AMIIBO_DB ")", amiiboDbCount());
	else uiText(12, y, S_SMALL, uiCol[COL_WARN], "No figure list yet: download it (needs Wi-Fi).");
}

static Menu amMenu = { "Amiibo", amEntries, sizeof(amEntries) / sizeof(amEntries[0]), amExtra };

static void amMenuInput(u32 kDown, u32 kRepeat)
{
	menuInput(&amMenu, kDown, kRepeat);
}

static void amMenuDraw(void)
{
	menuDraw(&amMenu);
}

void amiiboOpenMenu(void)
{
	static const Screen s = { NULL, amMenuInput, amMenuDraw };
	appScreen(&s);
}
