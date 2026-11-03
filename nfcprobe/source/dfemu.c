// DESFire card emulation from a saved info file (desfire.c dfLoadInfo): the host answers every command as
// ISO-DEP DATA (emu.c emuRun), native frames or ISO 7816 wrapped (90 cmd 00 00 Lc data 00 -> data 91 st).
// What the file holds is what a reader gets: GetVersion, application / file IDs, key settings and versions,
// file settings, the contents that were read (free, or with a key the dictionary found), free memory, the
// originality signature, DF names. EV1 authentication (AA AES, 1A ISO 2K3DES / 3K3DES) with the keys the file
// has; after it the answers carry their CMAC or come encrypted (full mode), as desfire.c expects them on the
// reader side. Writes are refused (permission denied); refused parts answer with the status they had.
#include <string.h>
#include <3ds.h>

#include "dfcrypto.h"
#include "dfemu.h"

#define FRAME 59 // answer bytes per native frame (the rest after AF)

static DfInfo info;
static DfApp *app; // NULL: the PICC level
static struct {
	bool on;
	u8 keyNo;
	DfCipher c;
	u8 iv[16];
} ses;
static struct { // a running authentication: after AF ek(RndB)
	bool on, known;
	u8 keyNo, rl;
	DfCipher k;
	u8 rb[16], iv[16];
} au;
static u8 out[1024]; // the answer still to send (AF frames), status last
static u32 outLen, outOff;
static u8 outSt;
static bool outVersion; // GetVersion: 7-byte frames first
static u32 rng;

void dfEmuSet(const DfInfo *d)
{
	info = *d;
}

const DfInfo *dfEmuInfo(void)
{
	return &info;
}

static void rnd(u8 *p, u32 n)
{
	if (!rng) rng = (u32)osGetTime() * 2654435761u | 1;
	while (n--) {
		rng ^= rng << 13, rng ^= rng >> 17, rng ^= rng << 5;
		*p++ = rng >> 24;
	}
}

static u32 le24(const u8 *p)
{
	return p[0] | p[1] << 8 | p[2] << 16;
}

static void put24(u8 *p, u32 v)
{
	p[0] = v, p[1] = v >> 8, p[2] = v >> 16;
}

static DfFile *file(u8 fid)
{
	for (int i = 0; app && i < app->nfiles; i++)
		if (app->files[i].fid == fid) return &app->files[i];
	return NULL;
}

static const DfKey *key(u8 k)
{
	if (!app) return k == 0 ? &info.piccKey : NULL;
	return k < 14 && k < (app->maxKeys & 0xF) ? &app->keys[k] : NULL;
}

// The answer: data (len) and status into out; in a session an OK answer gets its CMAC (plain / MAC mode) or
// is encrypted with its CRC32 (full), and any other status ends the session.
static void answer(const u8 *d, u32 len, u8 st, bool full)
{
	if (len > sizeof(out) - 32) len = sizeof(out) - 32;
	memmove(out, d, len);
	outLen = len, outOff = 0, outSt = st, outVersion = false;
	if (!ses.on) return;
	if (st && st != 0xAF) {
		ses.on = false;
		return;
	}
	u8 bs = ses.c.bs, mac[16];
	if (full) {
		out[len] = st;
		u32 crc = dfCrc32(out, len + 1);
		out[len] = crc, out[len + 1] = crc >> 8, out[len + 2] = crc >> 16, out[len + 3] = crc >> 24;
		u32 p = (len + 4 + bs - 1) / bs * bs;
		memset(out + len + 4, 0, p - len - 4);
		dfCbc(&ses.c, ses.iv, out, p, true);
		outLen = p;
	} else {
		out[len] = st;
		dfCmac(&ses.c, ses.iv, out, len + 1, mac);
		memcpy(out + len, mac, 8);
		outLen = len + 8;
	}
}

static void status(u8 st)
{
	answer(NULL, 0, st, false);
}

// Free access, or the session's key is the file's read or read/write key.
static bool mayRead(const DfFile *f)
{
	if (f->len < 4) return false;
	u16 ar = f->set[2] | f->set[3] << 8;
	u8 r = ar >> 12, rw = ar >> 4 & 0xF;
	return r == 0xE || rw == 0xE || (ses.on && (ses.keyNo == r || ses.keyNo == rw));
}

static bool fullMode(const DfFile *f)
{
	return ses.on && (f->set[1] & 3) == 3;
}

static void authStart(u8 cmd, const u8 *p, u32 n)
{
	ses.on = au.on = false;
	if (n < 1) return status(0x7E);
	const DfKey *k = key(p[0]);
	if (!k) return status(0x40);
	bool aes = (app ? app->maxKeys : info.maxKeys) >> 6 == 2;
	if ((cmd == 0xAA) != aes) return status(0xAE);
	au.known = k->known && (k->type == DF_AES) == aes;
	au.keyNo = p[0];
	u8 type = au.known ? k->type : aes ? DF_AES : DF_2K3DES;
	dfCipherInit(&au.k, type, au.known ? k->key : (const u8 *)"nfcprobe-unknown-key-pad");
	au.rl = type == DF_2K3DES ? 8 : 16;
	rnd(au.rb, au.rl);
	u8 e[16];
	memcpy(e, au.rb, au.rl);
	memset(au.iv, 0, sizeof(au.iv));
	dfCbc(&au.k, au.iv, e, au.rl, true);
	au.on = true;
	answer(e, au.rl, 0xAF, false);
}

// AF ek(RndA || rol(RndB)) -> 00 ek(rol(RndA)), the session key as desfire.c dfAuth derives it.
static void authFinish(const u8 *p, u32 n)
{
	au.on = false;
	u8 rl = au.rl, b[32], ra[16];
	if (n != 2u * rl) return status(0x7E);
	memcpy(b, p, n);
	dfCbc(&au.k, au.iv, b, n, false);
	if (!au.known || memcmp(b + rl, au.rb + 1, rl - 1) || b[2 * rl - 1] != au.rb[0]) return status(0xAE);
	memcpy(ra, b, rl);
	for (u32 i = 0; i < rl; i++) b[i] = ra[(i + 1) % rl];
	dfCbc(&au.k, au.iv, b, rl, true);
	const DfKey *k = key(au.keyNo);
	u8 sk[24], *rb = au.rb;
	memcpy(sk, ra, 4), memcpy(sk + 4, rb, 4);
	if (k->type == DF_2K3DES) {
		bool same = true;
		for (int i = 0; i < 8; i++) same &= !((k->key[i] ^ k->key[i + 8]) & 0xFE);
		if (same) memcpy(sk + 8, sk, 8);
		else memcpy(sk + 8, ra + 4, 4), memcpy(sk + 12, rb + 4, 4);
	} else if (k->type == DF_3K3DES) {
		memcpy(sk + 8, ra + 6, 4), memcpy(sk + 12, rb + 6, 4);
		memcpy(sk + 16, ra + 12, 4), memcpy(sk + 20, rb + 12, 4);
	} else {
		memcpy(sk + 8, ra + 12, 4), memcpy(sk + 12, rb + 12, 4);
	}
	answer(b, rl, 0x00, false); // before the session: no MAC on this one
	dfCipherInit(&ses.c, k->type, sk);
	memset(ses.iv, 0, sizeof(ses.iv));
	ses.keyNo = au.keyNo, ses.on = true;
}

// ReadData / ReadRecords / GetValue from the contents the file holds.
static void readFile(u8 cmd, const u8 *p, u32 n)
{
	if (n < (cmd == 0x6C ? 1u : 7u)) return status(0x7E);
	DfFile *f = file(p[0]);
	if (!f) return status(0xF0);
	if (f->st || f->len < 4) return status(f->st ? f->st : 0x9D);
	u8 type = f->set[0];
	if ((cmd == 0x6C) != (type == 2) || (cmd == 0xBB) != (type == 3 || type == 4)) return status(0x9E);
	if (!mayRead(f)) return status(0x9D);
	if (!f->hasData) return status(0x9D); // not read when the file was saved
	if (f->dataSt) return status(f->dataSt);
	const u8 *data = info.pool + f->dataOff;
	u32 dl = f->dataLen;
	static u8 buf[1024];
	if (cmd == 0x6C) return answer(data, dl < 4 ? dl : 4, 0, fullMode(f));
	if (cmd == 0xBD) { // the saved part of the file; beyond it (an info file keeps up to DF_MAX_DATA): zeros
		u32 size = f->len >= 7 ? le24(f->set + 4) : dl, off = le24(p + 1), len = le24(p + 4);
		if (off > size || (len && off + len > size)) return status(0xBE);
		if (!len) len = size - off;
		if (len > sizeof(buf) - 64) len = sizeof(buf) - 64;
		for (u32 i = 0; i < len; i++) buf[i] = off + i < dl ? data[off + i] : 0;
		return answer(buf, len, 0, fullMode(f));
	}
	// records, oldest first as read; offset counts back from the newest
	u32 rs = f->len >= 13 ? le24(f->set + 4) : 0, have = rs ? dl / rs : 0, off = le24(p + 1), cnt = le24(p + 4);
	if (!rs || off >= have) return status(0xBE);
	if (!cnt) cnt = have - off;
	if (cnt > have - off) return status(0xBE);
	u32 first = have - off - cnt, len = cnt * rs;
	if (len > sizeof(buf) - 64) len = (sizeof(buf) - 64) / rs * rs;
	memcpy(buf, data + first * rs, len);
	answer(buf, len, 0, fullMode(f));
}

static void native(const u8 *c, u32 len)
{
	u8 cmd = c[0], b[256];
	const u8 *p = c + 1;
	u32 n = len - 1, k = 0;
	if (cmd == 0xAF) {
		if (au.on) return authFinish(p, n);
		if (outOff < outLen) return; // the next frame of the answer
		return status(0x1C);
	}
	if (cmd != 0xAA && cmd != 0x1A) au.on = false;
	// in a session the reader runs its CMAC over every command: so does the card
	if (ses.on && cmd != 0x5A && cmd != 0xAA && cmd != 0x1A) {
		u8 mac[16];
		dfCmac(&ses.c, ses.iv, c, len, mac);
	}
	switch (cmd) {
	case 0x60: // GetVersion: hardware, then AF software, AF UID / batch / production week
		memcpy(b, info.ver, 28);
		answer(b, info.verLen > 21 ? info.verLen : 21, 0, false);
		outVersion = true;
		return;
	case 0x5A: { // SelectApplication
		ses.on = false;
		if (n != 3) return status(0x7E);
		u32 aid = le24(p);
		if (!aid) {
			app = NULL;
			return status(0);
		}
		for (int i = 0; i < info.napps && i < DF_MAX_APPS; i++)
			if (info.apps[i].aid == aid) {
				if (info.apps[i].selSt) return status(info.apps[i].selSt);
				app = &info.apps[i];
				return status(0);
			}
		return status(0xA0);
	}
	case 0xAA: case 0x1A:
		return authStart(cmd, p, n);
	case 0x6A: // GetApplicationIDs
		if (app) return status(0x1C);
		if (info.appSt) return status(info.appSt);
		for (int i = 0; i < info.napps && i < DF_MAX_APPS && k < 250; i++, k += 3) put24(b + k, info.apps[i].aid);
		return answer(b, k, 0, false);
	case 0x6D: // GetDFNames: AID, ISO FID, DF name of the ISO applications
		if (app) return status(0x1C);
		for (int i = 0; i < info.napps && i < DF_MAX_APPS && k < 230; i++) {
			const DfApp *a = &info.apps[i];
			if (!a->hasIso) continue;
			put24(b + k, a->aid);
			b[k + 3] = a->isoFid, b[k + 4] = a->isoFid >> 8;
			memcpy(b + k + 5, a->name, a->nameLen);
			k += 5 + a->nameLen;
		}
		return answer(b, k, 0, false);
	case 0x45: // GetKeySettings
		if (app ? app->keySt : info.keySt) return status(app ? app->keySt : info.keySt);
		b[0] = app ? app->keySet : info.keySet, b[1] = app ? app->maxKeys : info.maxKeys;
		return answer(b, 2, 0, false);
	case 0x64: // GetKeyVersion
		if (n != 1) return status(0x7E);
		if (!app) {
			if (p[0] || info.keyVerSt) return status(p[0] ? 0x40 : info.keyVerSt);
			return answer(&info.keyVer, 1, 0, false);
		}
		if ((p[0] & 0x3F) >= (app->maxKeys & 0xF)) return status(0x40);
		b[0] = (p[0] & 0x3F) < app->nKeyVer ? app->keyVer[p[0] & 0x3F] : 0; // not in the file: 00
		return answer(b, 1, 0, false);
	case 0x6F: // GetFileIDs
		if (!app) return status(0x1C);
		if (app->fileSt) return status(app->fileSt);
		for (int i = 0; i < app->nfiles; i++) b[k++] = app->files[i].fid;
		return answer(b, k, 0, false);
	case 0xF5: { // GetFileSettings
		if (n != 1) return status(0x7E);
		DfFile *f = file(p[0]);
		if (!f) return status(0xF0);
		if (f->st) return status(f->st);
		return answer(f->set, f->len, 0, false);
	}
	case 0xBD: case 0xBB: case 0x6C:
		return readFile(cmd, p, n);
	case 0x6E: // GetFreeMemory
		if (!info.hasFree) return status(0x1C);
		put24(b, info.freeMem);
		return answer(b, 3, 0, false);
	case 0x3C: // Read_Sig: 90 with the signature
		if (!info.hasSig) return status(0x1C);
		memcpy(out, info.sig, 56);
		outLen = 56, outOff = 0, outSt = 0x90, outVersion = false;
		return;
	case 0x51: // GetCardUID (full mode, the PICC master key's session)
		if (!ses.on || app || ses.keyNo) return status(0xAE);
		return answer(info.realUid, 7, 0, true);
	case 0x3D: case 0x3B: case 0xDB: case 0x0C: case 0xDC: case 0x1C: case 0xC7: case 0xC4: case 0x54: case 0x5F:
	case 0xCA: case 0xDA: case 0xCD: case 0xCB: case 0xCC: case 0xC0: case 0xC1: case 0xDF: case 0xFC: case 0x5C:
		return status(0x9D); // writes and changes: a saved card is read only
	}
	status(0x1C);
}

// The next native frame of the answer: up to FRAME bytes, AF while more follow (GetVersion: 7 + 7 + rest).
static u32 frame(u8 *resp, u32 max, u8 *st)
{
	u32 left = outLen - outOff, m = left > FRAME ? FRAME : left;
	if (outVersion && outOff < 14) m = 7;
	if (m > max) m = max;
	memcpy(resp, out + outOff, m);
	outOff += m;
	*st = outOff < outLen ? 0xAF : outSt;
	return m;
}

u32 dfEmuApdu(const u8 *c, u32 len, u8 *resp, u32 max)
{
	if (!c) { // a new session
		app = NULL;
		ses.on = au.on = false;
		outLen = outOff = 0;
		return 0;
	}
	if (!len || max < 8) return 0;
	u8 st;
	if (len >= 5 && c[0] == 0x90 && !c[2] && !c[3]) { // wrapped: 90 cmd 00 00 [Lc data] [00]
		u8 nc[256];
		u32 lc = len > 5 ? c[4] : 0;
		if (len > 5 && 5 + lc > len) return resp[0] = 0x67, resp[1] = 0, 2;
		nc[0] = c[1];
		memcpy(nc + 1, c + 5, lc);
		native(nc, 1 + lc);
		u32 m = frame(resp, max - 2, &st);
		resp[m] = 0x91, resp[m + 1] = st;
		return m + 2;
	}
	if (len >= 5 && c[0] == 0x00 && c[1] == 0xA4 && c[2] == 0x04) { // ISO SELECT by DF name
		u32 lc = c[4];
		for (int i = 0; i < info.napps && i < DF_MAX_APPS && 5 + lc <= len; i++) {
			DfApp *a = &info.apps[i];
			if (a->hasIso && a->nameLen == lc && !memcmp(a->name, c + 5, lc)) {
				app = a;
				ses.on = false;
				return resp[0] = 0x90, resp[1] = 0, 2;
			}
		}
		return resp[0] = 0x6A, resp[1] = 0x82, 2;
	}
	if (c[0] == 0x00) return resp[0] = 0x6D, resp[1] = 0, 2; // other ISO commands
	native(c, len);
	u32 m = frame(resp + 1, max - 1, &st);
	resp[0] = st;
	return m + 1;
}
