// MIFARE Ultralight / NTAG over the chip monitor, see mfu.h.

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include "mfu.h"
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

int mfuIdentify(MfuInfo *in)
{
	memset(in, 0, sizeof(*in));
	if (!iso14aParity(true)) FAIL(-1, "parity on");
	u8 c[2] = { 0x60 }, buf[16];
	int r = expect(c, 1, in->version, 8, "version");
	if (r < 0) return -1;
	if (r) {
		in->hasVersion = true;
		const MfuType *t = in->type = mfuTypeFromVersion(in->version);
		c[0] = 0x3C, c[1] = 0;
		if ((r = expect(c, 2, in->sig, 32, "signature")) < 0) return -1;
		in->hasSig = r;
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

int mfuDumpCard(MfuDump *d, const u8 *pwd)
{
	memset(d, 0, sizeof(*d));
	int r = mfuIdentify(&d->info);
	if (r <= 0) return r;
	const MfuType *t = d->info.type;
	u8 pack[2] = { 0 }, buf[16];
	if (pwd && t->pwd) {
		if ((r = mfuPwdAuth(pwd, pack)) < 0) return -1;
		d->pwdOk = r;
		logp("password %02X%02X%02X%02X: %s\n", pwd[0], pwd[1], pwd[2], pwd[3], r ? "ok" : mfuWhy());
	}
	d->pages = t->pages;
	for (int p = 0; p < d->pages && !mfCancel; p += 4) {
		if ((r = mfuRead(p, buf)) < 0) return -1;
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
		if (d->pwdOk && mfuPwdAuth(pwd, pack) < 0) return -1;
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
		memcpy(d->data[t->cfg + 2], pwd, 4);
		memcpy(d->data[t->cfg + 3], pack, 2);
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
	for (int p = 4; p < end; p += 4) {
		if (mfCancel) FAIL(0, "stopped");
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

bool mfuLoadDump(MfuDump *d, const char *path)
{
	static u8 raw[MFU_HDR + 4 * MFU_MAX_PAGES + 1];
	memset(d, 0, sizeof(*d));
	FILE *f = fopen(path, "rb");
	if (!f) return false;
	int n = fread(raw, 1, sizeof(raw), f);
	fclose(f);
	const u8 *data = raw;
	if (n >= MFU_HDR + 4 && n - MFU_HDR == 4 * (raw[11] + 1)) {
		memcpy(d->info.version, raw, 8);
		memcpy(d->info.sig, raw + 12, 32);
		memcpy(d->info.cnt, raw + 44, 12);
		for (int i = 0; i < 8; i++) d->info.hasVersion |= raw[i];
		for (int i = 0; i < 32; i++) d->info.hasSig |= raw[12 + i];
		data += MFU_HDR;
		n -= MFU_HDR;
	} else if (n % 4 || n < 64 || n > 4 * MFU_MAX_PAGES) {
		return false; // pm3's old headerless dumps are plain pages
	}
	d->pages = n / 4;
	memcpy(d->data, data, n);
	for (int p = 0; p < d->pages; p++) d->valid[p] = true;
	d->info.type = d->info.hasVersion ? mfuTypeFromVersion(d->info.version) : mfuTypeForPages(d->pages);
	if (d->info.type == &tOther) d->info.type = NULL;
	if (d->info.type) {
		d->info.cntOk = d->info.type->counters;
		d->info.tearOk = d->info.type->tearing ? 7 : 0;
	}
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
