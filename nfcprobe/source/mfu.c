// MIFARE Ultralight / NTAG over the chip monitor, see mfu.h.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "dfcrypto.h"
#include "mfu.h"
#include "mfukeys.h"
#include "nxpsig.h"
#include "probe.h"

static char why[64];

const char *mfuWhy(void)
{
	return why;
}

#define FAIL(ret, ...) ({ snprintf(why, sizeof(why), __VA_ARGS__); return (ret); })

// name, pages, userEnd, cfg, dynLock, counters, tearing, pwd (NXP datasheets: MF0ICU1, MF0ICU2,
// NTAG203, MF0ULX1, NTAG210_212, NTAG213_215_216)
static const MfuType tUL     = { "MIFARE Ultralight", 16, 16 };
const MfuType mfuTypeULC =  { "MIFARE Ultralight C", 48, 0x28 };
static const MfuType tN203   = { "NTAG203", 42, 0x28 };
static const MfuType tUL11   = { "Ultralight EV1 (MF0UL11)", 20, 0x10, 0x10, 0, 7, true, true };
static const MfuType tUL21   = { "Ultralight EV1 (MF0UL21)", 41, 0x24, 0x25, 0x24, 7, true, true };
static const MfuType tN210   = { "NTAG210", 20, 0x10, 0x10, 0, 0, false, true };
static const MfuType tN212   = { "NTAG212", 41, 0x24, 0x25, 0x24, 0, false, true };
static const MfuType tN213   = { "NTAG213", 45, 0x28, 0x29, 0x28, 4, false, true };
static const MfuType tN215   = { "NTAG215", 135, 0x82, 0x83, 0x82, 4, false, true };
static const MfuType tN216   = { "NTAG216", 231, 0xE2, 0xE3, 0xE2, 4, false, true };
// Answers GET_VERSION with something unknown: read until a page NAKs, never written.
static const MfuType tOther  = { "Ultralight / NTAG (unknown version)", MFU_MAX_PAGES - 1 };

const MfuType *mfuTypeFromVersion(const u8 v[8])
{
	// v[2] product type (03 Ultralight, 04 NTAG), v[6] storage size
	if (v[2] == 0x03 && v[6] == 0x0B) return &tUL11;
	if (v[2] == 0x03 && v[6] == 0x0E) return &tUL21;
	if (v[2] == 0x04 && v[6] == 0x0B) return &tN210;
	if (v[2] == 0x04 && v[6] == 0x0E) return &tN212;
	if (v[2] == 0x04 && v[6] == 0x0F) return &tN213;
	if (v[2] == 0x04 && v[6] == 0x11) return &tN215;
	if (v[2] == 0x04 && v[6] == 0x13) return &tN216;
	return &tOther;
}

const MfuType *mfuTypeForPages(int pages)
{
	switch (pages) {
	case 16: return &tUL;
	case 20: return &tUL11;
	case 41: return &tUL21;
	case 42: return &tN203;
	case 44: case 48: return &mfuTypeULC;
	case 45: return &tN213;
	case 135: return &tN215;
	case 231: return &tN216;
	}
	return NULL;
}

#define ACK4(x) (0x100 | (x)) // a 4-bit answer: 0xA = ACK, else NAK

// One command: the answer's length without its CRC (checked), ACK4(x) for a 4-bit answer, 0 = no or
// a broken answer, -1 = monitor error.
static int cmd(const u8 *c, u32 len, u8 *out, u32 max, int polls)
{
	MonFrame f[2];
	u8 crc[2];
	int n = iso14aDataTx(c, len, f, 2, polls);
	if (n <= 0) return n;
	const MonFrame *a = &f[n - 1];
	if (a->len == 1) return ACK4(a->data[0] & 0xF);
	if (a->len < 3 || a->len < a->regs[4]) return 0;
	iso14aCrc(a->data, a->len - 2, crc);
	if (memcmp(crc, a->data + a->len - 2, 2)) return 0;
	u32 m = a->len - 2 < max ? a->len - 2 : max;
	memcpy(out, a->data, m);
	return m;
}

// After a NAK or no answer the card is IDLE (or mid-auth): select it again. 1 ok, 0 gone, -1 monitor.
static int reselect(void)
{
	int sak = iso14aSelect();
	return sak == -2 ? -1 : sak < 0 ? 0 : 1;
}

// A command expecting `want` bytes: 1 = got them, 0 = anything else (card reselected), -1 = monitor.
static int expect(const u8 *c, u32 len, u8 *out, int want, const char *what)
{
	u8 buf[34];
	int r = cmd(c, len, buf, sizeof(buf), 4);
	if (r < 0) FAIL(-1, "%s: monitor", what);
	if (r == want) {
		memcpy(out, buf, want);
		return 1;
	}
	if (r >= ACK4(0)) snprintf(why, sizeof(why), "%s: NAK %X", what, r & 0xF);
	else if (r) snprintf(why, sizeof(why), "%s: %d bytes", what, r);
	else snprintf(why, sizeof(why), "%s: no answer", what);
	return reselect() < 0 ? -1 : 0;
}

int mfuRead(u8 page, u8 out[16])
{
	u8 c[2] = { 0x30, page };
	char what[16];
	snprintf(what, sizeof(what), "read %d", page);
	return expect(c, 2, out, 16, what);
}

int mfuPwdAuth(const u8 pwd[4], u8 pack[2])
{
	u8 c[5] = { 0x1B };
	memcpy(c + 1, pwd, 4);
	return expect(c, 5, pack, 2, "pwd auth");
}

void mfuUlcKeyPages(const u8 key[16], u8 pages[4][4])
{
	for (int i = 0; i < 16; i++) pages[i / 4][i % 4] = key[(i / 8) * 8 + 7 - i % 8];
}

void mfuUlcKeyFromPages(const u8 pages[4][4], u8 key[16])
{
	for (int i = 0; i < 16; i++) key[(i / 8) * 8 + 7 - i % 8] = pages[i / 4][i % 4];
}

int mfuUlcAuth(const u8 key[16])
{
	// 2K3DES CBC: RndB = D(ek(RndB)), then E(RndA || RndB<<8) chained on, the card's E(RndA<<8) last
	u8 c[17] = { 0x1A, 0x00 }, a[9], b[8], iv[8] = { 0 }, ra[8];
	int r = expect(c, 2, a, 9, "3DES auth");
	if (r <= 0) return r;
	if (a[0] != 0xAF) {
		snprintf(why, sizeof(why), "3DES auth: answer %02X", a[0]);
		return reselect() < 0 ? -1 : 0;
	}
	DfCipher k;
	dfCipherInit(&k, DF_2K3DES, key);
	memcpy(b, a + 1, 8);
	dfCbc(&k, iv, b, 8, false);
	for (int i = 0; i < 8; i++) ra[i] = rand();
	c[0] = 0xAF;
	memcpy(c + 1, ra, 8);
	for (int i = 0; i < 8; i++) c[9 + i] = b[(i + 1) % 8];
	dfCbc(&k, iv, c + 1, 16, true);
	if ((r = expect(c, 17, a, 9, "3DES auth")) <= 0) {
		snprintf(why, sizeof(why), "wrong 3DES key (refused)");
		return r;
	}
	dfCbc(&k, iv, a + 1, 8, false);
	for (int i = 0; i < 8; i++)
		if (a[0] || a[1 + i] != ra[(i + 1) % 8]) {
			snprintf(why, sizeof(why), "wrong 3DES key");
			return reselect() < 0 ? -1 : 0;
		}
	return 1;
}

int mfuUlcFindKey(u8 key[16])
{
	static MfuKey keys[MFU_MAX_KEYS];
	int n = mfuKeyList(card.uid, card.uidLen, NULL, 16, keys, MFU_MAX_KEYS);
	for (int i = 0; i < n && !mfCancel; i++) {
		int r = mfuUlcAuth(keys[i].key);
		if (r < 0) return -1;
		if (r) {
			memcpy(key, keys[i].key, 16);
			logp("3DES key: %s\n", keys[i].label);
			return 1;
		}
	}
	snprintf(why, sizeof(why), "no 3DES key in the dictionary");
	logp("3DES key: none of %d in the dictionary\n", n);
	return 0;
}

int mfuUlcSetKey(const u8 cur[16], const u8 key[16])
{
	if (!iso14aParity(true)) FAIL(-1, "parity on");
	int r = mfuUlcAuth(cur);
	if (r <= 0) return r;
	u8 pg[4][4], back[16];
	mfuUlcKeyPages(key, pg);
	for (int i = 0; i < 4; i++) {
		u8 c[6] = { 0xA2, 0x2C + i };
		memcpy(c + 2, pg[i], 4);
		if ((r = cmd(c, 6, back, sizeof(back), 10)) < 0) FAIL(-1, "write %X: monitor", 0x2C + i);
		if (r != ACK4(0xA)) {
			snprintf(why, sizeof(why), "write %X: %s (after %d of 4 pages)", 0x2C + i, r >= ACK4(0) ? "NAK" : "no ACK", i);
			return reselect() < 0 ? -1 : 0;
		}
	}
	if ((r = reselect()) <= 0) return r; // a fresh session for the check
	if ((r = mfuUlcAuth(key)) == 0) snprintf(why, sizeof(why), "written, but the card refuses the new key");
	return r;
}

int mfuIdentify(MfuInfo *in)
{
	memset(in, 0, sizeof(*in));
	if (!iso14aParity(true)) FAIL(-1, "parity on");
	u8 c[2] = { 0x60 }, buf[16];
	int r = expect(c, 1, in->version, 8, "version");
	if (r == 0) r = expect(c, 1, in->version, 8, "version"); // one lost answer made an NTAG215 an NTAG203
	if (r < 0) return -1;
	static const u8 zero[8];
	if (r && !memcmp(in->version, zero, 8)) in->zeroVersion = true, r = 0;
	if (r) {
		in->hasVersion = true;
		const MfuType *t = in->type = mfuTypeFromVersion(in->version);
		c[0] = 0x3C, c[1] = 0;
		if ((r = expect(c, 2, in->sig, 32, "signature")) < 0) return -1;
		in->hasSig = r;
		if (r) {
			in->sigKey = nxpSigCheck(SIG_MFU, card.uid, card.uidLen, in->sig, 32);
			logp("signature: %s\n", in->sigKey ? in->sigKey : "NOT verified by an NXP key");
		}
		for (int i = 0; i < 3; i++) {
			if (t->counters & 1 << i) {
				c[0] = 0x39, c[1] = i;
				if ((r = expect(c, 2, in->cnt[i], 3, "counter")) < 0) return -1;
				in->cntOk |= r << i;
			}
			if (t->tearing) {
				c[0] = 0x3E, c[1] = i;
				if ((r = expect(c, 2, in->cnt[i] + 3, 1, "tearing")) < 0) return -1;
				in->tearOk |= r << i;
			}
		}
		return 1;
	}
	// No GET_VERSION: the UL-C answers its 3DES AUTH (AF + ek(RndB)), the NTAG203 has a page 0x29.
	c[0] = 0x1A, c[1] = 0;
	u8 ek[9];
	if ((r = expect(c, 2, ek, 9, "auth")) < 0) return -1;
	if (r && ek[0] == 0xAF) {
		in->type = &mfuTypeULC;
		return reselect(); // drop the half-done auth
	}
	if ((r = mfuRead(0x29, buf)) < 0) return -1;
	in->type = r ? &tN203 : &tUL;
	if ((r = mfuRead(0, buf)) <= 0) return r; // still there, and an Ultralight at all
	return 1;
}

int mfuWritePage(const MfuType *t, u8 page, const u8 data[4])
{
	if (page < 4 || page >= t->userEnd) FAIL(0, "page %d is not user memory", page);
	if (!iso14aParity(true)) FAIL(-1, "parity on");
	u8 c[6] = { 0xA2, page }, back[16];
	memcpy(c + 2, data, 4);
	int r = cmd(c, 6, back, sizeof(back), 10); // the ACK comes after the EEPROM write
	if (r < 0) FAIL(-1, "write %d: monitor", page);
	if (r != ACK4(0xA)) {
		if (r >= ACK4(0)) snprintf(why, sizeof(why), "write %d: NAK %X (locked or password?)", page, r & 0xF);
		else snprintf(why, sizeof(why), "write %d: no ACK", page);
		return reselect() < 0 ? -1 : 0;
	}
	if ((r = mfuRead(page, back)) <= 0) return r;
	if (memcmp(back, data, 4)) FAIL(0, "write %d: verify mismatch", page);
	return 1;
}

static int writeRaw1(u8 page, const u8 data[4], bool noVerify);

// A raw page write (no range check) + read-back unless noVerify, three tries (an ACK gets lost now and
// then; rewriting the same data is harmless). The callers check the page.
static int writeRaw(u8 page, const u8 data[4], bool noVerify)
{
	int r = 0;
	for (int t = 0; t < 3 && !r; t++) r = writeRaw1(page, data, noVerify);
	return r;
}

static int writeRaw1(u8 page, const u8 data[4], bool noVerify)
{
	if (!iso14aParity(true)) FAIL(-1, "parity on");
	u8 c[6] = { 0xA2, page }, back[16];
	memcpy(c + 2, data, 4);
	int r = cmd(c, 6, back, sizeof(back), 10);
	if (r < 0) FAIL(-1, "write %d: monitor", page);
	if (r != ACK4(0xA)) {
		snprintf(why, sizeof(why), "write %d: %s", page, r >= ACK4(0) ? "NAK" : "no ACK");
		return reselect() < 0 ? -1 : 0;
	}
	if (noVerify) return 1;
	if ((r = mfuRead(page, back)) <= 0) return r;
	if (memcmp(back, data, 4)) FAIL(0, "write %d: verify mismatch", page);
	return 1;
}

int mfuAmiiboWrite(const u8 *tag, bool lock)
{
	MfuInfo in;
	u8 p[16];
	int r = mfuIdentify(&in);
	if (r <= 0) return r;
	if (in.type != &tN215 || !in.hasSig) FAIL(0, "not an NTAG215 (with a signature): %s", in.type ? in.type->name : "?");
	if ((r = mfuRead(0, p)) <= 0) return r;
	if (memcmp(p, tag, 9)) FAIL(0, "the image is for UID %02X%02X%02X%02X%02X%02X%02X, not this tag", tag[0], tag[1],
		tag[2], tag[4], tag[5], tag[6], tag[7]);
	if (!lock) {
		if (p[10] || p[11]) FAIL(0, "static lock bytes already set (%02X%02X)", p[10], p[11]);
		if ((r = mfuRead(0x82, p)) <= 0) return r;
		if (p[0] || p[1] || p[2]) FAIL(0, "dynamic lock bytes already set");
		if (p[7] < 0x82) FAIL(0, "password-protected from page %d", p[7]);
		// CC (OTP: ORs into E1 10 3E 00), the data, PWD, PACK
		if ((r = writeRaw(3, tag + 12, false)) <= 0) return r;
		for (int pg = 4; pg < 0x82; pg++)
			if ((r = writeRaw(pg, tag + 4 * pg, false)) <= 0) return r;
		if ((r = writeRaw(0x85, tag + 4 * 0x85, true)) <= 0) return r; // PWD / PACK read back as zeros
		return writeRaw(0x86, tag + 4 * 0x86, true);
	}
	// the one-way part (Tagmo's order): dynamic lock, CFG0 (AUTH0), CFG1 (ACCESS: config locked), static lock
	if ((r = writeRaw(0x82, tag + 4 * 0x82, false)) <= 0) return r;
	if ((r = writeRaw(0x83, tag + 4 * 0x83, false)) <= 0) return r;
	if ((r = writeRaw(0x84, tag + 4 * 0x84, false)) <= 0) return r;
	if ((r = writeRaw(2, tag + 8, true)) <= 0) return r; // bytes 0-1 (BCC1, internal) are read-only
	if ((r = mfuRead(0, p)) <= 0) return r;
	if (p[10] != tag[10] || p[11] != tag[11]) FAIL(0, "static lock bytes read back %02X%02X", p[10], p[11]);
	return 1;
}

int mfuNdefWrite(const MfuType *t, const u8 cc[4], const u8 *data, u32 n)
{
	if (cc[0] != 0xE1) FAIL(0, "no NDEF capability container (CC %02X%02X%02X%02X)", cc[0], cc[1], cc[2], cc[3]);
	if (cc[3] >> 4) FAIL(0, "the CC says read-only (%02X)", cc[3]);
	u32 room = cc[2] * 8, user = (t->userEnd - 4) * 4;
	if (room > user) room = user;
	if (n > room) FAIL(0, "%lu bytes don't fit the tag's %lu", (unsigned long)n, (unsigned long)room);
	u32 pages = (n + 3) / 4;
	u8 p[4];
	if (pages > 1) { // empty message first: a write cut short then leaves an empty tag, not a mix
		static const u8 empty[4] = { 0x03, 0x00, 0xFE, 0x00 };
		int r = mfuWritePage(t, 4, empty);
		if (r <= 0) return r;
		for (u32 i = 1; i < pages; i++) {
			memset(p, 0, 4);
			memcpy(p, data + 4 * i, n - 4 * i < 4 ? n - 4 * i : 4);
			if ((r = mfuWritePage(t, 4 + i, p)) <= 0) return r;
		}
	}
	memset(p, 0, 4);
	memcpy(p, data, n < 4 ? n : 4);
	return mfuWritePage(t, 4, p);
}

static int auth(MfuDump *d, u8 pack[2])
{
	return d->info.type == &mfuTypeULC ? mfuUlcAuth(d->key) : mfuPwdAuth(d->key, pack);
}

int mfuDumpCard(MfuDump *d, const u8 *key)
{
	memset(d, 0, sizeof(*d));
	int r = mfuIdentify(&d->info);
	if (r <= 0) return r;
	const MfuType *t = d->info.type;
	bool ulc = t == &mfuTypeULC;
	u8 pack[2] = { 0 }, buf[16];
	if (key && (t->pwd || ulc)) {
		memcpy(d->key, key, ulc ? 16 : 4);
		if ((r = auth(d, pack)) < 0) return -1;
		d->pwdOk = r;
		logp("%s: %s\n", ulc ? "3DES key" : "password", r ? "ok" : mfuWhy());
	} else if (ulc) {
		if ((r = mfuUlcFindKey(d->key)) < 0) return -1;
		d->pwdOk = r;
	}
	d->pages = t->pages;
	progOp("Reading pages");
	for (int p = 0; p < d->pages && !mfCancel; p += 4) {
		progStep(p, d->pages);
		if ((r = mfuRead(p, buf)) < 0) return -1;
		if (!r) { // once more: a lost answer must not end the dump (the reselect dropped the auth)
			if (d->pwdOk && auth(d, pack) < 0) return -1;
			if ((r = mfuRead(p, buf)) < 0) return -1;
		}
		if (r) {
			for (int k = 0; k < 4 && p + k < d->pages; k++) {
				memcpy(d->data[p + k], buf + 4 * k, 4);
				d->valid[p + k] = true;
			}
			continue;
		}
		logp("page %d on: %s\n", p, mfuWhy());
		if (t == &tOther) d->pages = p; // the end of memory, or the protected area
		// The protected area runs from AUTH0 to the end. A READ that starts below it but reaches into
		// it rolls over to page 0 instead, so the last 4 pages are read again one at a time.
		if (d->pwdOk && auth(d, pack) < 0) return -1;
		for (int q = p - 3 > 0 ? p - 3 : 1; q < p && d->valid[q]; q++) {
			if ((r = mfuRead(q, buf)) < 0) return -1;
			if (!r) {
				for (int k = q; k < p; k++) d->valid[k] = false;
				break;
			}
			memcpy(d->data[q], buf, 4);
		}
		break;
	}
	if (d->pwdOk && t->cfg) { // PWD and PACK read as zeros
		memcpy(d->data[t->cfg + 2], d->key, 4);
		memcpy(d->data[t->cfg + 3], pack, 2);
	}
	if (ulc) { // the key pages read as zeros (a GTU: the key in clear): only the key that worked counts
		if (d->pwdOk) mfuUlcKeyPages(d->key, d->data + 0x2C);
		for (int p = 0x2C; p < 0x30; p++) d->valid[p] = d->pwdOk;
	}
	return 1;
}

int mfuRestore(const MfuDump *d, int *written)
{
	MfuInfo cur;
	*written = 0;
	int r = mfuIdentify(&cur);
	if (r <= 0) return r;
	const MfuType *t = cur.type;
	int end = d->info.type ? d->info.type->userEnd : d->pages;
	if (end > d->pages) end = d->pages;
	if (!t->userEnd) FAIL(0, "unknown card type");
	if (end > t->userEnd) FAIL(0, "the dump has %d user pages, the card %d", end - 4, t->userEnd - 4);
	u8 buf[16];
	progOp("Writing pages");
	for (int p = 4; p < end; p += 4) {
		if (mfCancel) FAIL(0, "stopped");
		progStep(p - 4, end - 4);
		if ((r = mfuRead(p, buf)) <= 0) return r;
		for (int k = 0; k < 4 && p + k < end; k++) {
			int q = p + k;
			if (!d->valid[q] || !memcmp(buf + 4 * k, d->data[q], 4)) continue;
			if ((r = mfuWritePage(t, q, d->data[q])) <= 0) return r;
			++*written;
		}
	}
	return 1;
}

// --- Gen4 GTU in Ultralight mode (pm3 doc/magic_cards_notes.md, hf_mf_ultimatecard.lua) ---
// Page n is the first 4 bytes of backdoor block n. GET_VERSION answers from pages FA-FB, READ_SIG from
// F2-F9, PWD_AUTH checks page E5; the PACK is page 13 on versions 6666 / 06A0 (E6 on others).

static int gtuPage(u8 page, const u8 data[4])
{
	u8 b[16] = { 0 };
	memcpy(b, data, 4);
	int r = mfGen4Write(mfGen4Pwd, page, b);
	if (r <= 0) snprintf(why, sizeof(why), "page %02X: %s", page, mfWhy());
	return r;
}

// The password a clone gets: the dump's, unless it was never known (zeros, not read with it).
static void clonePwd(const MfuDump *d, u8 pwd[4])
{
	const MfuType *t = d->info.type;
	static const u8 zero[4];
	memset(pwd, 0xFF, 4);
	if (t->cfg && d->valid[t->cfg + 2] && (d->pwdOk || memcmp(d->data[t->cfg + 2], zero, 4)))
		memcpy(pwd, d->data[t->cfg + 2], 4);
}

int mfuCloneToGtu(const MfuDump *d)
{
	const MfuType *t = d->info.type;
	if (!t) FAIL(0, "unknown dump type");
	if (!d->valid[0] || !d->valid[1] || !d->valid[2]) FAIL(0, "the dump has no UID (pages 0-2)");
	u8 cfg[32], ver[8];
	int r = mfGen4Config(mfGen4Pwd, cfg, sizeof(cfg));
	if (r < 0) return -1;
	if (!r) FAIL(0, "not a Gen4 GTU (password 00000000)");
	if (r != MF_GEN4_CFG) FAIL(0, "GTU config is %d bytes", r);
	int vn = mfGen4Version(mfGen4Pwd, ver, sizeof(ver));
	if (vn < 0) return -1;
	bool pack13 = vn >= 2 && ((ver[vn - 2] == 0x66 && ver[vn - 1] == 0x66) || (ver[vn - 2] == 0x06 && ver[vn - 1] == 0xA0));
	u8 mode = t == &mfuTypeULC ? 2 : t == &tUL || t == &tN203 ? 3 : d->info.version[2] == 0x04 ? 1 : 0;
	u8 want[MF_GEN4_CFG];
	memcpy(want, cfg, MF_GEN4_CFG);
	want[0] = 1;    // Ultralight protocol
	want[1] = 1;    // 7-byte UID (pages 0-1)
	want[24] = 0x44; // ATQA 0044, swapped
	want[25] = 0x00;
	want[26] = 0x00; // SAK
	want[27] = mode;
	if (memcmp(want, cfg, MF_GEN4_CFG)) {
		logp("gtu: Ultralight mode %d\n", mode);
		if ((r = mfGen4SetConfig(mfGen4Pwd, want)) <= 0) {
			snprintf(why, sizeof(why), "config: %s", mfWhy());
			return r;
		}
		if (!iso14aStart()) FAIL(-1, "reactivate after the mode switch");
	}
	u8 pwd[4], pack[4] = { 0 };
	clonePwd(d, pwd);
	if (t->cfg && d->valid[t->cfg + 3]) memcpy(pack, d->data[t->cfg + 3], 2);
	// Pages 1 and 0 last: they change the UID, which later SELECTs use.
	// Config pages the dump lacks (read-protected on the original) get the factory defaults: no
	// password protection, not whatever the GTU held there.
	static const u8 cfgDefault[2][4] = { { 0x00, 0x00, 0x00, 0xFF }, { 0x00, 0x05, 0x00, 0x00 } };
	// UL-C: the key pages from the dump (pm3 dumps may stop before them), else the factory key;
	// lock / counter / AUTH0 / AUTH1 the dump lacks: factory (AUTH0 30 = no auth needed)
	static const u8 ulcDefault[4][4] = { { 0 }, { 0 }, { 0x30 }, { 0 } };
	static const u8 ulcFactory[16] = { 0x49, 0x45, 0x4D, 0x4B, 0x41, 0x45, 0x52, 0x42, 0x21, 0x4E, 0x41, 0x43, 0x55,
		0x4F, 0x59, 0x46 };
	bool ulc = t == &mfuTypeULC;
	u8 ulcKey[16], kp[4][4];
	memcpy(ulcKey, ulcFactory, 16);
	static const u8 zero[16];
	if (ulc && d->pages >= 0x30 && d->valid[0x2C] && d->valid[0x2D] && d->valid[0x2E] && d->valid[0x2F])
		mfuUlcKeyFromPages(d->data + 0x2C, ulcKey);
	if (ulc && !memcmp(ulcKey, zero, 16)) { // what a dump without the key holds (pm3's too)
		logp("gtu: key pages all zero (not read?): factory key\n");
		memcpy(ulcKey, ulcFactory, 16);
	}
	mfuUlcKeyPages(ulcKey, kp);
	int end = ulc ? 0x30 : d->pages;
	progOp("Writing pages");
	for (int p = 2; p < end; p++) {
		if (mfCancel) FAIL(0, "stopped");
		progStep(p - 2, end - 2);
		const u8 *data = t->cfg && p == t->cfg + 2 ? pwd : d->data[p];
		if (ulc && p >= 0x2C) {
			data = kp[p - 0x2C];
		} else if (ulc && p >= 0x28 && !(p < d->pages && d->valid[p])) {
			logp("gtu: page %d not in the dump, factory default\n", p);
			data = ulcDefault[p - 0x28];
		} else if (!d->valid[p] && t->cfg && p >= t->cfg && p < t->cfg + 2) {
			logp("gtu: page %d not in the dump, factory default\n", p);
			data = cfgDefault[p - t->cfg];
		} else if (!d->valid[p] && !(t->cfg && p >= t->cfg + 2 && p < t->cfg + 4)) {
			continue;
		}
		if ((r = gtuPage(p, data)) <= 0) return r;
	}
	for (int i = 0; i < 8; i++)
		if ((r = gtuPage(0xF2 + i, d->info.sig + 4 * i)) <= 0) return r;
	if ((r = gtuPage(0xFA, d->info.version)) <= 0 || (r = gtuPage(0xFB, d->info.version + 4)) <= 0) return r;
	if (t->pwd) {
		if ((r = gtuPage(0xE5, pwd)) <= 0) return r;
		if (!pack13 && (r = gtuPage(0xE6, pack)) <= 0) return r;
		if (pack13 && t->cfg + 3 != 0x13) logp("gtu: PACK = page 13 (user memory) on this GTU\n");
	}
	if ((r = gtuPage(1, d->data[1])) <= 0 || (r = gtuPage(0, d->data[0])) <= 0) return r;

	// Read it back as a reader would.
	if (!iso14aStart()) FAIL(-1, "reactivate after the clone");
	static MfuDump back;
	if ((r = mfuDumpCard(&back, t->pwd ? pwd : ulc ? ulcKey : NULL)) <= 0) return r;
	if (back.info.type != t) FAIL(0, "reads back as %s", back.info.type->name);
	if (ulc && !back.pwdOk) FAIL(0, "the clone refuses the 3DES key");
	if (d->info.hasSig && memcmp(back.info.sig, d->info.sig, 32)) FAIL(0, "signature differs");
	for (int p = 0; p < d->pages; p++) {
		if (!d->valid[p] || (t->cfg && p >= t->cfg + 2 && p < t->cfg + 4)) continue; // PWD/PACK read as 00
		if (ulc && p >= 0x2C) continue; // the key: checked by the auth above
		if (!back.valid[p]) FAIL(0, "page %d does not read back", p);
		if (memcmp(back.data[p], d->data[p], 4)) FAIL(0, "page %d differs", p);
	}
	return 1;
}

bool mfuWriteDump(const MfuDump *d, const char *path)
{
	u8 hdr[MFU_HDR] = { 0 };
	memcpy(hdr, d->info.version, 8);
	hdr[11] = d->pages - 1;
	memcpy(hdr + 12, d->info.sig, 32);
	memcpy(hdr + 44, d->info.cnt, 12);
	FILE *f = fopen(path, "wb");
	if (!f) return false;
	static const u8 zero[4];
	bool ok = fwrite(hdr, 1, MFU_HDR, f) == MFU_HDR;
	for (int p = 0; p < d->pages; p++) ok &= fwrite(d->valid[p] ? d->data[p] : zero, 1, 4, f) == 4;
	ok &= !fclose(f);
	char tpath[300];
	snprintf(tpath, sizeof(tpath), "%.*s.txt", (int)(strlen(path) - 4), path);
	bool any = false;
	for (int p = 0; p < d->pages; p++) any |= !d->valid[p];
	if (!any) {
		remove(tpath);
		return ok;
	}
	if (!ok || !(f = fopen(tpath, "w"))) return false;
	for (int p = 0, n = 0; p < d->pages; p++)
		if (!d->valid[p]) fprintf(f, "%s %d", n++ ? "" : "# unread:", p);
	fprintf(f, "\n");
	return !fclose(f);
}

bool mfuParseDump(MfuDump *d, const u8 *raw, int n)
{
	memset(d, 0, sizeof(*d));
	if (n >= MFU_HDR + 4 && n - MFU_HDR == 4 * (raw[11] + 1)) {
		memcpy(d->info.version, raw, 8);
		memcpy(d->info.sig, raw + 12, 32);
		memcpy(d->info.cnt, raw + 44, 12);
		for (int i = 0; i < 8; i++) d->info.hasVersion |= raw[i];
		for (int i = 0; i < 32; i++) d->info.hasSig |= raw[12 + i];
		raw += MFU_HDR;
		n -= MFU_HDR;
	} else if (n % 4 || n < 64 || n > 4 * MFU_MAX_PAGES) {
		return false; // pm3's old headerless dumps are plain pages
	}
	d->pages = n / 4;
	memcpy(d->data, raw, n);
	for (int p = 0; p < d->pages; p++) d->valid[p] = true;
	d->info.type = d->info.hasVersion ? mfuTypeFromVersion(d->info.version) : mfuTypeForPages(d->pages);
	if (d->info.type == &tOther) d->info.type = NULL;
	if (d->info.type) {
		d->info.cntOk = d->info.type->counters;
		d->info.tearOk = d->info.type->tearing ? 7 : 0;
	}
	return true;
}

bool mfuLoadDump(MfuDump *d, const char *path)
{
	static u8 raw[MFU_HDR + 4 * MFU_MAX_PAGES + 1];
	FILE *f = fopen(path, "rb");
	if (!f) return false;
	int n = fread(raw, 1, sizeof(raw), f);
	fclose(f);
	if (!mfuParseDump(d, raw, n)) return false;
	char tpath[300], line[1200];
	snprintf(tpath, sizeof(tpath), "%.*s.txt", (int)(strlen(path) - 4), path);
	if ((f = fopen(tpath, "r"))) {
		while (fgets(line, sizeof(line), f)) {
			int p, pos;
			if (strncmp(line, "# unread:", 9)) continue;
			for (char *s = line + 9; sscanf(s, "%d%n", &p, &pos) == 1; s += pos)
				if (p >= 0 && p < d->pages) d->valid[p] = false;
		}
		fclose(f);
	}
	return true;
}

bool mfuSaveDump(const MfuDump *d, char *path, u32 pathMax)
{
	// UID from pages 0-1 (7 bytes, BCC0 skipped), else the activation's
	char uid[21] = "";
	if (d->valid[0] && d->valid[1]) {
		const u8 u[7] = { d->data[0][0], d->data[0][1], d->data[0][2], d->data[1][0], d->data[1][1], d->data[1][2],
			d->data[1][3] };
		for (int i = 0; i < 7; i++) sprintf(uid + 2 * i, "%02X", u[i]);
	} else {
		for (int i = 0; i < card.uidLen; i++) sprintf(uid + 2 * i, "%02X", card.uid[i]);
	}
	mkdir(MF_DIR, 0777);
	mkdir(MFU_DIR, 0777);
	struct stat st;
	snprintf(path, pathMax, MFU_DIR "/%s.bin", uid);
	for (int i = 2; !stat(path, &st) && i < 1000; i++) snprintf(path, pathMax, MFU_DIR "/%s-%d.bin", uid, i);
	return mfuWriteDump(d, path);
}
