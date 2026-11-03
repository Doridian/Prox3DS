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
#include "entry.h"
#include "mfu.h"
#include "mfukeys.h"
#include "pm3dict.h"
#include "probe.h"
#include "ui.h"

// --- card screen ---

static Card sc;
static MfuDump sm; // identify + pages 0-3 + the config pages, for the card screen
static bool smGtu;  // a Gen4 GTU (in Ultralight mode, or it would not be here)
// The probe's results, filled by the job and taken over by the UI thread (takeProbe): the card screen
// may be drawing sm while a scan runs.
static Card scJob;
static MfuDump smJob;
static bool smGtuJob;
static int scanResult;

static const Screen cardScreen;

static int mfuProbe(void)
{
	scJob = card;
	u8 buf[16];
	int r = mfuIdentify(&smJob.info);
	memset(smJob.valid, 0, sizeof(smJob.valid));
	if (r <= 0) return r;
	const MfuType *t = smJob.info.type;
	smJob.pages = t->pages;
	// pages 0-15 (pm3's fingerprints look at 0-12), the config pages, 0x21-0x23 (Philips password)
	int want[6] = { 0, 4, 8, 12, t->cfg ? t->cfg : t == &mfuTypeULC ? 0x28 : -1, t->pages > 0x24 ? 0x20 : -1 };
	for (int i = 0; i < 6; i++) {
		if (want[i] < 0) continue;
		if ((r = mfuRead(want[i], buf)) < 0) return -1;
		for (int k = 0; r && k < 4 && want[i] + k < t->pages; k++) {
			memcpy(smJob.data[want[i] + k], buf + 4 * k, 4);
			smJob.valid[want[i] + k] = true;
		}
	}
	if (t == &mfuTypeULC) { // no lockout: the dictionary is safe
		if ((r = mfuUlcFindKey(smJob.key)) < 0) return -1;
		smJob.pwdOk = r;
	}
	u8 cfg[32];
	if ((r = mfGen4Config(mfGen4Pwd, cfg, sizeof(cfg))) < 0) return -1;
	smGtuJob = r > 0;
	return 1;
}

static void runScan(void)
{
	scanResult = 0;
	if (cardWait()) scanResult = mfuProbe();
	iso14aParity(true);
}

static void takeProbe(void)
{
	sc = scJob;
	sm = smJob;
	smGtu = smGtuJob;
}

static void mfuShow(void)
{
	takeProbe();
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
static bool rdWithPwd;
static u8 rdKey[16] = { 0xFF, 0xFF, 0xFF, 0xFF }; // the password / UL-C key to send
static Card rdCard; // with a key: the card it is meant for
static const MfuType *rdType; // and its type (a GTU can change it under the same UID)
static MfuKey rdCand; // the candidate picked (expected PACK)

static void runRead(void)
{
	rdResult = -2;
	rdPath[0] = 0;
	if (!cardWait()) return;
	if (rdWithPwd) { // nothing goes out unless it is the card the key was picked for: its AUTHLIM was looked at
		MfuInfo now;
		if (card.uidLen != rdCard.uidLen || memcmp(card.uid, rdCard.uid, card.uidLen)) {
			rdResult = -3;
			return;
		}
		if ((rdResult = mfuIdentify(&now)) <= 0) return;
		if (now.type != rdType) {
			rdResult = -3;
			return;
		}
	}
	sc = card;
	rdResult = mfuDumpCard(&rd, rdWithPwd ? rdKey : NULL);
	iso14aParity(true);
	if (rdResult > 0 && rd.pwdOk)
		mfuRememberKey(card.uid, card.uidLen, rd.key, rd.info.type == &mfuTypeULC ? 16 : 4);
	if (rdResult > 0 && mfuSaveDump(&rd, rdPath, sizeof(rdPath))) logp("saved %s\n", rdPath);
}

static void doneRead(void)
{
	if (rdResult == -2) return;
	if (rdResult == -3) {
		msgBox("Read card", "Not the card the %s was picked for\n(%s, UID %02X%02X%02X%02X...): nothing sent.",
			rdType == &mfuTypeULC ? "key" : "password", rdType->name, rdCard.uid[0], rdCard.uid[1], rdCard.uid[2], rdCard.uid[3]);
		return;
	}
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
	bool ulc = rd.info.type == &mfuTypeULC;
	char authMsg[96] = "";
	if (ulc && rd.pwdOk)
		snprintf(authMsg, sizeof(authMsg), "\n3DES key %s.", rdWithPwd ? "accepted" : "found in the dictionary");
	else if (ulc)
		snprintf(authMsg, sizeof(authMsg), "\n%s", rdWithPwd ? "3DES key refused." : "No 3DES key in the dictionary.");
	else if (rdWithPwd && rd.pwdOk && rd.info.type->cfg) {
		const u8 *pk = rd.data[rd.info.type->cfg + 3];
		snprintf(authMsg, sizeof(authMsg), "\nPassword accepted, PACK %02X%02X%s.", pk[0], pk[1],
			!rdCand.hasPack ? "" : memcmp(pk, rdCand.pack, 2) ? " (not the algorithm's)" : " (as expected)");
	} else if (rdWithPwd)
		snprintf(authMsg, sizeof(authMsg), "\nPassword %s.", rd.pwdOk ? "accepted" : "refused");
	mfuEditorOpen(&rd, rdPath);
	msgBox(mfCancel ? "Read card (stopped)" : "Read card", "%s: %d/%d pages read.%s%s\n%s", rd.info.type->name,
		got, rd.pages, authMsg, got < rd.pages ? ulc ? "\nThe rest needs the 3DES key." : "\nThe rest is password-protected." : "",
		rdPath[0] ? rdPath : "Could not save the dump to the SD card!");
}

static void startRead(void)
{
	rdWithPwd = false;
	jobStart("Reading card", runRead, doneRead, true);
}

// --- password / 3DES key picker: for the card scanned last ---

#define PICK_ROWS 10

static MfuKey pk[MFU_MAX_KEYS];
static int npk;
static UiList pl;
static u8 pkLen; // 4 = password (PWD_AUTH), 16 = UL-C 3DES key

// AUTHLIM from CFG1: -1 = unknown (the config pages are read-protected)
static int authLim(void)
{
	const MfuType *t = sm.info.type;
	return t->cfg && sm.valid[t->cfg + 1] ? sm.data[t->cfg + 1][0] & 7 : -1;
}

static void sendKey(void)
{
	rdWithPwd = true;
	rdCard = sc;
	rdType = sm.info.type;
	jobStart(pkLen == 16 ? "Reading card with 3DES key" : "Reading card with password", runRead, doneRead, true);
}

// A password goes out once, after a confirm unless the card says wrong ones are not counted.
static void sendAsk(const u8 *key)
{
	memcpy(rdKey, key, pkLen);
	int lim = authLim();
	if (pkLen == 16 || lim == 0) {
		sendKey();
		return;
	}
	char msg[200];
	int n = snprintf(msg, sizeof(msg), "Send %02X%02X%02X%02X to this card once?\n", key[0], key[1], key[2], key[3]);
	if (lim < 0)
		snprintf(msg + n, sizeof(msg) - n, "Its AUTHLIM is unknown: a wrong password\nmay count towards locking it for good.");
	else
		snprintf(msg + n, sizeof(msg) - n, "AUTHLIM %d: %d wrong password%s in a row\nlock the protected area for good.", lim, lim,
			lim == 1 ? "" : "s");
	confirm("Send password", sendKey, "%s", msg);
}

static void keyEntered(const u8 *b, u32 len)
{
	memset(&rdCand, 0, sizeof(rdCand));
	sendAsk(b);
}

static void pickInput(u32 kDown, u32 kRepeat)
{
	uiListNav(&pl, npk + 1, PICK_ROWS, kRepeat);
	if (kDown & KEY_B) appBack();
	if (kDown & KEY_A) {
		if (pl.sel == 0 && pkLen == 16) {
			entryHex("Ultralight C 3DES key", "The 16-byte 2K3DES key, as pm3 takes it (pages 2C-2F hold each half "
				"byte-reversed). A wrong one costs nothing: the UL-C has no lockout.", 16, rdKey, keyEntered);
		} else if (pl.sel == 0) {
			entryHex("Ultralight / NTAG password", "The 4-byte PWD_AUTH password (EV1, NTAG21x). It is sent once "
				"before reading: a wrong one counts against the card's AUTHLIM.", 4, rdKey, keyEntered);
		} else {
			rdCand = pk[pl.sel - 1];
			sendAsk(rdCand.key);
		}
	}
	if ((kDown & KEY_X) && pkLen == 16) startRead(); // the whole dictionary
}

static void pickDraw(void)
{
	char uid[32], hex[40];
	uidHex(&sc, uid, "");
	uiHeader(pkLen == 16 ? "Ultralight C: 3DES key" : "Ultralight / NTAG: password", uid);
	float y = 26;
	u32 warn = uiCol[COL_WARN], ok = uiCol[COL_OK];
	int lim = authLim();
	const MfuType *t = sm.info.type;
	if (pkLen == 16) {
		uiText(12, y, S_SMALL, ok, "No lockout on the Ultralight C: wrong keys cost nothing.");
		if (sm.pwdOk) {
			for (int i = 0; i < 16; i++) sprintf(hex + 2 * i, "%02X", sm.key[i]);
			uiText(12, y + SMALL_H, S_SMALL, uiCol[COL_TEXT], "The dictionary opened it: %s", hex);
		} else {
			uiText(12, y + SMALL_H, S_SMALL, warn, "No key in the dictionary opened it (" MFU_KEYS ").");
		}
	} else {
		if (lim < 0) uiText(12, y, S_SMALL, warn, "AUTHLIM unknown (config protected): a wrong password may count.");
		else if (lim == 0) uiText(12, y, S_SMALL, ok, "AUTHLIM 0: wrong passwords are not counted.");
		else uiText(12, y, S_SMALL, warn, "AUTHLIM %d: %d wrong passwords in a row lock it for good.", lim, lim);
		if (t->cfg && sm.valid[t->cfg])
			uiText(12, y + SMALL_H, S_SMALL, uiCol[COL_DIM], "%s, protected from page %d.", t->name,
				sm.data[t->cfg][3]);
		else
			uiText(12, y + SMALL_H, S_SMALL, uiCol[COL_DIM], "%s.", t->name);
	}
	y += 2 * SMALL_H + 4;
	float hexX = pkLen == 16 ? UI_W - 10 - 32 * 6.0f : UI_W - 10 - 8 * MONO_W;
	for (int i = 0; i < PICK_ROWS && pl.top + i <= npk; i++, y += LINE_H) {
		int r = pl.top + i;
		if (r == pl.sel) uiRect(4, y - 1, UI_W - 8, LINE_H, uiCol[COL_SEL]);
		if (!r) {
			uiText(10, y, S_BODY, uiCol[COL_ACCENT], pkLen == 16 ? "Type a 3DES key..." : "Type a password...");
			continue;
		}
		const MfuKey *k = &pk[r - 1];
		char label[48];
		snprintf(label, sizeof(label), "%s", k->label);
		uiText(10, y, S_BODY, uiCol[k->known ? COL_OK : k->match ? COL_ACCENT : COL_TEXT], "%s",
			uiFit(label, hexX - 26, S_BODY));
		for (int b = 0; b < k->len; b++) sprintf(hex + 2 * b, "%02X", k->key[b]);
		if (pkLen == 16) uiMonoS(hexX, y + 2, 0.36f, 6.0f, uiCol[COL_TEXT], hex);
		else uiMono(hexX, y + 1, uiCol[COL_TEXT], hex);
	}
	uiFooter(pkLen == 16 ? BTN_A " try this key   " BTN_X " try them all   " BTN_B " back"
	                     : BTN_A " send it, once   " BTN_B " back");
}

static const Screen pickScreen = { NULL, pickInput, pickDraw };

static void pickOpen(void)
{
	const MfuType *t = sm.info.type;
	if (!t->pwd && t != &mfuTypeULC) {
		msgBox("Read with password", "A %s has no password\nor key: Read card gets everything.", t->name);
		return;
	}
	pkLen = t == &mfuTypeULC ? 16 : 4;
	npk = mfuKeyList(sc.uid, sc.uidLen, &sm, pkLen, pk, MFU_MAX_KEYS);
	pl.sel = pl.top = 0;
	if (npk && (pk[0].known || pk[0].match)) pl.sel = 1;
	appScreen(&pickScreen);
}

static void donePickScan(void)
{
	if (scanResult > 0) takeProbe(), pickOpen();
	else doneScan();
}

static void startPwdRead(void)
{
	jobStart("Scanning", runScan, donePickScan, true);
}

// --- Ultralight C: change the 3DES key (the card scanned last, its key found by the dictionary) ---

static u8 ckKey[16];
static int ckResult;
static char ckWhy[64];

static void runCk(void)
{
	ckResult = -2;
	if (!cardWait()) return;
	MfuInfo now;
	if (card.uidLen != sc.uidLen || memcmp(card.uid, sc.uid, sc.uidLen)) {
		ckResult = -3;
		return;
	}
	if ((ckResult = mfuIdentify(&now)) > 0 && now.type != &mfuTypeULC) ckResult = -3;
	if (ckResult > 0) ckResult = mfuUlcSetKey(sm.key, ckKey);
	snprintf(ckWhy, sizeof(ckWhy), "%s", mfuWhy());
	if (ckResult > 0) {
		mfuRememberKey(card.uid, card.uidLen, ckKey, 16);
		memcpy(sm.key, ckKey, 16);
	}
	iso14aParity(true);
}

static void doneCk(void)
{
	char k[33];
	for (int i = 0; i < 16; i++) sprintf(k + 2 * i, "%02X", ckKey[i]);
	if (ckResult == -2) return;
	if (ckResult == -3) msgBox("Change 3DES key", "Not the Ultralight C scanned before:\nnothing written.");
	else if (ckResult < 0) msgBox("Change 3DES key", "Lost the card. If it was mid-write,\nthe key may be half changed: try both keys.");
	else if (!ckResult) msgBox("Change 3DES key", "Not done: %s", ckWhy);
	else msgBox("Change 3DES key", "Done: the card takes the new key\n%s\n(remembered for this card).", k);
}

static void ckGo(void)
{
	jobStart("Changing the 3DES key", runCk, doneCk, false);
}

static void ckEntered(const u8 *b, u32 len)
{
	char k[33], o[33];
	memcpy(ckKey, b, 16);
	for (int i = 0; i < 16; i++) sprintf(k + 2 * i, "%02X", ckKey[i]), sprintf(o + 2 * i, "%02X", sm.key[i]);
	confirm("Change 3DES key", ckGo, "Write the new key\n%s\n(now %s)?\nKeep the card on the reader: a half-written\nkey is one nobody knows.", k, o);
}

static void ckStart(void)
{
	if (!sm.pwdOk) {
		msgBox("Change 3DES key", "The current key is needed first: it is not\nin the dictionary. Read with a key, then scan again.");
		return;
	}
	entryHex("New Ultralight C 3DES key", "The new 16-byte 2K3DES key, as pm3 takes it. Written to pages 2C-2F after "
		"authenticating with the current one, then checked.", 16, sm.key, ckEntered);
}

static void ulcMenu(void)
{
	static const MenuItem items[] = { { "Read with a key", pickOpen }, { "Change the 3DES key", ckStart } };
	popup("Ultralight C", items, 2);
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
	else if (in->zeroVersion)
		uiText(14, y, S_SMALL, dim, "GET_VERSION answers zeros: taken as none");
	else
		uiText(14, y, S_SMALL, dim, "No GET_VERSION (Ultralight, UL-C or NTAG203)");
	if (smGtu) uiTextRight(UI_W - 14, y, S_SMALL, uiCol[COL_OK], "Magic: Gen4 GTU");
	y += SMALL_H;
	if (in->hasSig) {
		uiText(14, y, S_SMALL, txt, "Signature");
		uiTextRight(UI_W - 14, y, S_SMALL, uiCol[in->sigKey ? COL_OK : COL_WARN], "%s", in->sigKey ? "verified" : "NOT verified");
		if (in->sigKey) {
			char k[48];
			snprintf(k, sizeof(k), "%s", in->sigKey + (strncmp(in->sigKey, "NXP ", 4) ? 0 : 4));
			uiTextRight(UI_W - 14, y + SMALL_H, S_SMALL, dim, "%s", uiFit(k, UI_W - 14 - 280, S_SMALL));
		}
		for (int h = 0; h < 2; h++, y += SMALL_H) {
			for (int i = 0; i < 16; i++) sprintf(s + 2 * i, "%02X", in->sig[16 * h + i]);
			uiMonoS(80, y + 1, 0.36f, 6.0f, txt, s);
		}
	} else if (t == &mfuTypeULC) {
		char k[33];
		for (int i = 0; i < 16; i++) sprintf(k + 2 * i, "%02X", sm.key[i]);
		uiText(14, y, S_SMALL, txt, "3DES key");
		if (sm.pwdOk) uiMonoS(80, y + 1, 0.36f, 6.0f, txt, k);
		uiTextRight(UI_W - 14, y, S_SMALL, uiCol[sm.pwdOk ? COL_OK : COL_WARN], "%s", sm.pwdOk ? "dictionary" : "not in the dictionary");
		uiText(14, y + SMALL_H, S_SMALL, dim, "No signature on this type");
		y += 2 * SMALL_H;
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
	if (sm.info.type && !strcmp(sm.info.type->name, "NTAG215"))
		uiFooter(BTN_A " scan   " BTN_X " read   " BTN_Y " key   " BTN_R " NDEF   " BTN_L " Amiibo   " BTN_B " back");
	else
		uiFooter(BTN_A " scan again   " BTN_X " read card   " BTN_Y " with key   " BTN_R " NDEF   " BTN_B " back");
}

static void cardInput(u32 kDown, u32 kRepeat)
{
	if (kDown & KEY_A) startScan();
	if (kDown & KEY_X) startRead();
	if (kDown & KEY_Y) sm.info.type == &mfuTypeULC ? ulcMenu() : pickOpen();
	if (kDown & KEY_R) ndefOpenMfu();
	if ((kDown & KEY_L) && sm.info.type && !strcmp(sm.info.type->name, "NTAG215")) amiiboOpenCard();
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

static void fileAmiibo(void)
{
	amiiboOpenDump(&ld, files[fl.sel].name);
}

static void fileEmuNdef(void)
{
	emuStartMfuNdef(&ld, files[fl.sel].name);
}

static void fileEmuUid(void)
{
	Card c = { .atqa = { 0x44, 0x00 }, .uidLen = 7, .sak = 0x00 };
	memcpy(c.uid, ld.data[0], 3);
	memcpy(c.uid + 3, ld.data[1], 4);
	emuStartUid(&c);
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
			{ "Clone onto magic card (GTU)", fileCloneAsk }, { "Emulate its NDEF message", fileEmuNdef },
			{ "Emulate its UID", fileEmuUid }, { "Amiibo (decrypt, copy)", fileAmiibo } };
		popup(files[fl.sel].name, items, ld.pages == 135 ? 5 : 4);
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
	uiFooter(BTN_A " open   " BTN_X " write, clone, emulate   " BTN_Y " delete   " BTN_B " back");
}

static const Screen filesScreen = { filesScan, filesInput, filesDraw };

// --- menu and family ---

static void openFiles(void)
{
	appScreen(&filesScreen);
}

static void startDownload(void)
{
	pm3DictDownload("Downloading pm3's Ultralight C keys", "mfulc_default_keys.dic", MFU_PM3_KEYS, 1ull << 32, NULL);
}

static const MenuEntry mfuEntries[] = {
	{ "Scan card", "Type (GET_VERSION), originality signature, counters and tearing flags, lock bits, OTP / "
	               "capability container and the password config.", startScan },
	{ "Read card", "Dump every readable page (a password-protected area stays unread). Saved to the SD card "
	               "in pm3's format and opened in the editor.", startRead },
	{ "Read with password", "The same with a password (PWD_AUTH, 4 bytes) or an Ultralight C 3DES key first: the "
	                        "protected pages read too. Offers the one that worked before, " MFU_KEYS ", passwords "
	                        "derived from the UID (pm3 pwdgen) and the defaults, and shows the AUTHLIM.", startPwdRead },
	{ "Saved dumps", "View and edit dumps, write their user memory back onto a card, or clone them onto a Gen4 GTU.", openFiles },
	{ "Tear-off", "Cut the field N microseconds into a write (pm3 hw tearoff): scan a user page through the "
	              "EEPROM's erase and write phases, or try an EV1 counter reset (pm3 hf mfu countertear, experimental).", mfuTearMenu },
	{ "Download keys", "Fetch pm3's mfulc_default_keys.dic (Ultralight C 3DES keys, over Wi-Fi) to " MFU_PM3_KEYS
	                   ": Read with password offers its keys after the built-in ones.", startDownload },
};

static void mfuExtra(float x, float y, float w)
{
	uiText(x, y, S_SMALL, uiCol[COL_DIM], "Dumps: " MFU_DIR " (pm3 hf mfu .bin)");
	if (sc.uidLen) menuLastCard(x, y + SMALL_H, w, &sc, sm.info.type ? sm.info.type->name : cardTypeName(&sc));
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
