// DESFire card emulation from a saved info file (desfire.c dfLoadInfo): the host answers every command as
// ISO-DEP DATA (emu.c emuRun), native frames or ISO 7816 wrapped (90 cmd 00 00 Lc data 00 -> data 91 st).
// What the file holds is what a reader gets: GetVersion, application / file IDs, key settings and versions,
// file settings, the contents that were read (free, or with a key the dictionary found), free memory, the
// originality signature, DF names. EV1 authentication (AA AES, 1A ISO 2K3DES / 3K3DES) with the keys the file
// has; after it the answers carry their CMAC or come encrypted (full mode), as desfire.c expects them on the
// reader side. Also the legacy D40 authentication (0A, DES / 2K3DES: MAC4 and CRC16 on file reads only) and
// EV2 (71 / 77, AES: TI and command counter, MACt on what came MACed), as pm3 talks them.
// Writes (WriteData, WriteRecord, Credit / Debit, ClearRecordFile) with the file's access rights and comm mode;
// standard files change at once, backup / value / record files on CommitTransaction (AbortTransaction, a
// select, authentication or the field going drop them). Afterwards dfEmuSave keeps what readers wrote.
// Key / settings / application changes are refused (permission denied); refused parts answer with the
// status they had.
#include <string.h>
#include <3ds.h>

#include "dfcrypto.h"
#include "dfemu.h"

#define FRAME 59 // answer bytes per native frame (the rest after AF)

static DfInfo info, pend; // as committed, with the open transaction (same pool layout)
static u16 cap[DF_MAX_APPS][DF_MAX_FILES]; // pool room of each file's contents
static bool recOpen[DF_MAX_APPS][DF_MAX_FILES]; // the transaction's new record started
static bool txOpen;    // pend differs from info
static u32 writes;     // write commands that took (committed)
static DfApp *app; // NULL: the PICC level
enum { SM_NONE, SM_D40, SM_EV1, SM_EV2 };
static struct {
	u8 mode; // SM_*
	u8 keyNo;
	DfCipher c;   // the session key; EV2: SesAuthENCKey
	u8 iv[16];    // EV1: the running IV
	DfCipher mac; // EV2: SesAuthMACKey
	u8 ti[4];     // EV2: transaction identifier (kept for a NonFirst after an error), command counter
	bool hasTi;
	u16 ctr;
	bool macIn;   // EV2: this command came with its MAC
} ses;
static struct { // a running authentication: after AF ek(RndB)
	bool on, known;
	u8 cmd, keyNo, rl;
	DfCipher k;
	u8 rb[16], iv[16];
} au;
static u8 out[1024]; // the answer still to send (AF frames), status last
static u8 in[1100];  // a command coming in AF frames
static u32 inLen, inNeed;
static u32 outLen, outOff;
static u8 outSt;
static bool outVersion; // GetVersion: 7-byte frames first
static u32 rng;

static u32 le24(const u8 *p);

// Room for a file's contents: standard / backup up to DF_MAX_DATA, value 4, records as many as fit.
static u32 fileCap(const DfFile *f)
{
	u8 t = f->set[0];
	if (f->len < 7) return f->dataLen;
	u32 sz = le24(f->set + 4);
	if (t <= 1) return sz < DF_MAX_DATA ? sz : DF_MAX_DATA;
	if (t == 2) return 4;
	if (f->len < 13 || !sz) return f->dataLen;
	u32 m = le24(f->set + 7) * sz, lim = DF_MAX_DATA / sz * sz;
	return m < lim ? m : lim;
}

// The info, its pool laid out again with room for each file to grow into (writes).
void dfEmuSet(const DfInfo *d)
{
	info = *d;
	u32 total = 0;
	bool grow = true;
	for (int pass = 0; pass < 2; pass++) {
		info.poolUsed = 0;
		for (int i = 0; i < d->napps && i < DF_MAX_APPS; i++)
			for (int j = 0; j < d->apps[i].nfiles; j++) {
				const DfFile *f = &d->apps[i].files[j];
				if (!f->hasData) continue;
				u32 c = fileCap(f);
				if (!grow || c < f->dataLen) c = f->dataLen;
				if (pass) {
					memcpy(info.pool + info.poolUsed, d->pool + f->dataOff, f->dataLen);
					memset(info.pool + info.poolUsed + f->dataLen, 0, c - f->dataLen);
					info.apps[i].files[j].dataOff = info.poolUsed;
				} else total += c;
				cap[i][j] = c;
				info.poolUsed += c;
			}
		if (!pass && total > sizeof(info.pool)) grow = false;
	}
	pend = info;
	memset(recOpen, 0, sizeof(recOpen));
	txOpen = false, writes = 0;
}

u32 dfEmuWrites(void)
{
	return writes;
}

bool dfEmuSave(char *path, u32 max)
{
	return dfSaveInfo(&info, path, max);
}

static void abortTx(void)
{
	if (txOpen) pend = info;
	memset(recOpen, 0, sizeof(recOpen));
	txOpen = false;
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

// ISO 14443-A CRC (D40 full mode), appended LSB first
static void crcA(const u8 *p, u32 len, u8 *out)
{
	u32 c = 0x6363;
	while (len--) {
		u8 b = *p++ ^ c;
		b ^= b << 4;
		c = (c >> 8) ^ (b << 8) ^ (b << 3) ^ (b >> 4);
	}
	out[0] = c, out[1] = c >> 8;
}

// EV2: MACt = the odd bytes of CMAC(SesAuthMACKey, code || CmdCtr || TI || data) (desfire.c ev2Mac)
static void ev2Mac(u8 code, const u8 *p, u32 len, u8 *mac)
{
	u8 m[1100], iv[16] = { 0 }, full[16];
	m[0] = code, m[1] = ses.ctr, m[2] = ses.ctr >> 8;
	memcpy(m + 3, ses.ti, 4);
	memcpy(m + 7, p, len);
	dfCmac(&ses.mac, iv, m, 7 + len, full);
	for (int i = 0; i < 8; i++) mac[i] = full[2 * i + 1];
}

// EV2 full mode IV: E(SesAuthENCKey, A55A (command) / 5AA5 (answer) || TI || CmdCtr || 0..)
static void ev2Iv(bool cmd, u8 *iv)
{
	memset(iv, 0, 16);
	iv[0] = cmd ? 0xA5 : 0x5A, iv[1] = cmd ? 0x5A : 0xA5;
	memcpy(iv + 2, ses.ti, 4);
	iv[6] = ses.ctr, iv[7] = ses.ctr >> 8;
	dfBlock(&ses.c, iv, true);
}

// D40 MAC: the first 4 bytes of the last block of the zero-padded data CBC-enciphered from IV 0
static void d40Mac(const u8 *p, u32 len, u8 *mac)
{
	u8 t[1040], iv[8] = { 0 };
	u32 pl = (len + 7) / 8 * 8;
	memcpy(t, p, len);
	memset(t + len, 0, pl - len);
	dfCbc(&ses.c, iv, t, pl, true);
	memcpy(mac, t + pl - 8, 4);
}

// The answer: data (len) and status into out. comm is the file's communication mode for the data commands
// (0 plain, 1 MAC, 3 full), 0 for the rest, 3 for GetCardUID. In a session an OK answer is secured as the
// session's kind wants it; any other status ends the session.
static void answer(const u8 *d, u32 len, u8 st, u8 comm)
{
	if (len > sizeof(out) - 32) len = sizeof(out) - 32;
	memmove(out, d, len);
	outLen = len, outOff = 0, outSt = st, outVersion = false;
	if (!ses.mode) return;
	if (st && st != 0xAF && st != 0x90) {
		ses.mode = SM_NONE;
		return;
	}
	u8 bs = ses.c.bs, mac[16], iv[16] = { 0 };
	if (ses.mode == SM_D40) { // the DES CBC chain from IV 0 on each answer, the card only enciphers
		u32 p = (len + (comm == 3 ? 2 : 0) + bs - 1) / bs * bs;
		if (comm == 3) {
			crcA(out, len, out + len);
			memset(out + len + 2, 0, p - len - 2);
			dfCbc(&ses.c, iv, out, p, true);
			outLen = p;
		} else if (comm == 1 && len) {
			d40Mac(out, len, out + len);
			outLen = len + 4;
		}
		return;
	}
	if (ses.mode == SM_EV2) {
		ses.ctr++;
		if (comm == 3 && len) {
			u32 p = (len + 16) / 16 * 16;
			out[len] = 0x80;
			memset(out + len + 1, 0, p - len - 1);
			ev2Iv(false, iv);
			dfCbc(&ses.c, iv, out, p, true);
			len = p;
		}
		if (comm == 3 || comm == 1 || ses.macIn) ev2Mac(st, out, len, out + len), len += 8;
		outLen = len;
		return;
	}
	if (comm == 3) {
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
	answer(NULL, 0, st, 0);
}

// Access rights nibbles: read 12, write 8, read/write 4, change 0. Free (E) or the session's key.
static bool allowed(u8 key)
{
	return key == 0xE || (ses.mode && ses.keyNo == key);
}

static bool may(const DfFile *f, bool r, bool w)
{
	if (f->len < 4) return false;
	u16 ar = f->set[2] | f->set[3] << 8;
	return allowed(ar >> 4 & 0xF) || (r && allowed(ar >> 12)) || (w && allowed(ar >> 8 & 0xF));
}

static bool mayRead(const DfFile *f)
{
	return may(f, true, false);
}

// The file's comm mode as the session runs it: 0 plain, 1 MAC, 3 full.
static u8 commOf(const DfFile *f)
{
	u8 m = f->set[1] & 3;
	return ses.mode && m != 2 ? m : 0;
}

// 0A (D40, DES / 2K3DES), 1A (ISO, DES / 2K3DES / 3K3DES), AA (AES), 71 / 77 (EV2 First / NonFirst, AES):
// AF ek(RndB). A key the file doesn't have still gets its challenge, and the refusal after it.
static void authStart(u8 cmd, const u8 *p, u32 n)
{
	ses.mode = SM_NONE, au.on = false;
	abortTx();
	if (cmd != 0x77) ses.hasTi = false;
	if (n < 1) return status(0x7E);
	const DfKey *k = key(p[0]);
	if (!k) return status(0x40);
	u8 kt = (app ? app->maxKeys : info.maxKeys) >> 6; // 0 DES / 2K3DES, 1 3K3DES, 2 AES
	if (cmd == 0x0A ? kt != 0 : cmd == 0x1A ? kt > 1 : kt != 2) return status(0xAE);
	if (cmd == 0x77 && !ses.hasTi) return status(0xAE);
	u8 type = kt == 2 ? DF_AES : kt == 1 ? DF_3K3DES : DF_2K3DES;
	au.known = k->known && k->type == type;
	au.cmd = cmd, au.keyNo = p[0];
	dfCipherInit(&au.k, type, au.known ? k->key : (const u8 *)"prox3ds-unknown-key-pad");
	au.rl = type == DF_2K3DES ? 8 : 16;
	rnd(au.rb, au.rl);
	u8 e[16];
	memcpy(e, au.rb, au.rl);
	memset(au.iv, 0, sizeof(au.iv));
	dfCbc(&au.k, au.iv, e, au.rl, true);
	au.on = true;
	answer(e, au.rl, 0xAF, 0);
}

// AF ek(RndA || rol(RndB)) -> 00 ek(rol(RndA)), the session keys as desfire.c dfAuth / authEv2 derive them.
// D40: the reader deciphers in CBC send mode (y_i = D(x_i ^ y_i-1)), IV 0 each way. EV1: the IV runs on from
// ek(RndB). EV2: IV 0, the answer E(TI || rol(RndA) || PDcap2 || PCDcap2) (First) or E(rol(RndA)) (NonFirst).
static void authFinish(const u8 *p, u32 n)
{
	au.on = false;
	u8 rl = au.rl, b[32], ra[16], iv[16] = { 0 };
	bool d40 = au.cmd == 0x0A, ev2 = au.cmd == 0x71 || au.cmd == 0x77;
	if (n != 2u * rl) return status(0x7E);
	memcpy(b, p, n);
	if (d40) {
		dfBlock(&au.k, b, true), dfBlock(&au.k, b + 8, true);
		for (int i = 0; i < 8; i++) b[8 + i] ^= p[i];
	} else {
		dfCbc(&au.k, ev2 ? iv : au.iv, b, n, false);
	}
	if (!au.known || memcmp(b + rl, au.rb + 1, rl - 1) || b[2 * rl - 1] != au.rb[0]) return status(0xAE);
	memcpy(ra, b, rl);
	const DfKey *k = key(au.keyNo);
	u8 *rb = au.rb, *rot = b + (au.cmd == 0x71 ? 4 : 0);
	for (u32 i = 0; i < rl; i++) rot[i] = ra[(i + 1) % rl];
	if (ev2) {
		u32 m = rl;
		if (au.cmd == 0x71) {
			rnd(ses.ti, 4);
			memcpy(b, ses.ti, 4);
			memset(b + 20, 0, 12);
			m = 32;
		}
		memset(iv, 0, 16);
		dfCbc(&au.k, iv, b, m, true);
		answer(b, m, 0x00, 0);
		u8 sv[32] = { 0xA5, 0x5A, 0x00, 0x01, 0x00, 0x80 }, ke[16], km[16];
		memcpy(sv + 6, ra, 8);
		for (int i = 0; i < 6; i++) sv[8 + i] ^= rb[i];
		memcpy(sv + 14, rb + 6, 10);
		memcpy(sv + 24, ra + 8, 8);
		memset(iv, 0, 16);
		dfCmac(&au.k, iv, sv, 32, ke);
		sv[0] = 0x5A, sv[1] = 0xA5;
		memset(iv, 0, 16);
		dfCmac(&au.k, iv, sv, 32, km);
		dfCipherInit(&ses.c, DF_AES, ke);
		dfCipherInit(&ses.mac, DF_AES, km);
		if (au.cmd == 0x71) ses.ctr = 0;
		ses.hasTi = true;
		ses.keyNo = au.keyNo, ses.mode = SM_EV2;
		return;
	}
	if (d40) dfBlock(&au.k, b, true);
	else dfCbc(&au.k, au.iv, b, rl, true);
	u8 sk[24];
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
	answer(b, rl, 0x00, 0); // before the session: no MAC on this one
	dfCipherInit(&ses.c, k->type, sk);
	memset(ses.iv, 0, sizeof(ses.iv));
	ses.keyNo = au.keyNo, ses.mode = d40 ? SM_D40 : SM_EV1;
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
	if (cmd == 0x6C) return answer(data, dl < 4 ? dl : 4, 0, f->set[1] & 3);
	if (cmd == 0xBD) { // the saved part of the file; beyond it (an info file keeps up to DF_MAX_DATA): zeros
		u32 size = f->len >= 7 ? le24(f->set + 4) : dl, off = le24(p + 1), len = le24(p + 4);
		if (off > size || (len && off + len > size)) return status(0xBE);
		if (!len) len = size - off;
		if (len > sizeof(buf) - 64) len = sizeof(buf) - 64;
		for (u32 i = 0; i < len; i++) buf[i] = off + i < dl ? data[off + i] : 0;
		return answer(buf, len, 0, f->set[1] & 3);
	}
	// records, oldest first as read; offset counts back from the newest
	u32 rs = f->len >= 13 ? le24(f->set + 4) : 0, have = rs ? dl / rs : 0, off = le24(p + 1), cnt = le24(p + 4);
	if (!rs || off >= have) return status(0xBE);
	if (!cnt) cnt = have - off;
	if (cnt > have - off) return status(0xBE);
	u32 first = have - off - cnt, len = cnt * rs;
	if (len > sizeof(buf) - 64) len = (sizeof(buf) - 64) / rs * rs;
	memcpy(buf, data + first * rs, len);
	answer(buf, len, 0, f->set[1] & 3);
}

// --- writes ---

static bool writeCmd(u8 c)
{
	return c == 0x3D || c == 0x3B || c == 0x0C || c == 0xDC || c == 0x1C;
}

// What follows the plain header of a write: the data as the file's comm mode sends it in the session.
static u32 secLen(u8 comm, u32 dl)
{
	u8 bs = ses.c.bs;
	if (comm == 1) return dl + (ses.mode == SM_D40 ? 4 : 8);
	if (comm != 3) return dl;
	if (ses.mode == SM_D40) return (dl + 2 + 7) / 8 * 8;
	if (ses.mode == SM_EV1) return (dl + 4 + bs - 1) / bs * bs;
	return (dl + 16) / 16 * 16 + 8;
}

// The whole length of a write command (code included) once its header is in, 0 = not a write / unknown.
static u32 writeLen(const u8 *c, u32 len)
{
	u32 hdr = c[0] == 0x3D || c[0] == 0x3B ? 7 : 1;
	if (!writeCmd(c[0]) || len < 1 + hdr) return 0;
	const DfFile *f = file(c[1]);
	if (!f) return 0;
	return 1 + hdr + secLen(commOf(f), hdr == 7 ? le24(c + 5) : 4);
}

// The plain data (dl bytes) of a write to f from what follows the header (n bytes, the EV1 CMAC / EV2 MACt
// already checked and taken off): D40 MAC4; full mode deciphered, its CRC / padding checked. 0 = ok, else
// the status: 7E length, 1E integrity.
static u8 writeData(const u8 *c, u32 hdr, const u8 *p, u32 n, const DfFile *f, u32 dl, u8 *d)
{
	u8 comm = commOf(f);
	if (comm == 1 && ses.mode == SM_D40) {
		u8 m[4];
		if (n != dl + 4) return 0x7E;
		d40Mac(p, dl, m);
		if (memcmp(m, p + dl, 4)) return 0x1E;
		n -= 4;
	} else if (comm == 1 && ses.mode == SM_EV2 && !ses.macIn) {
		return 0x1E;
	}
	if (comm != 3) {
		if (n != dl) return n == dl + 8 ? 0x1E : 0x7E; // EV1: a CMAC that did not check
		memcpy(d, p, dl);
		return 0;
	}
	if (n != secLen(3, dl) - (ses.mode == SM_EV2 ? 8 : 0)) return 0x7E;
	if (ses.mode == SM_EV2 && !ses.macIn) return 0x1E;
	u8 t[1100], iv[16] = { 0 };
	memcpy(t, p, n);
	if (ses.mode == SM_D40) { // the reader deciphered in send mode: x_i = E(y_i) ^ y_i-1
		for (u32 o = 0; o < n; o += 8) {
			dfBlock(&ses.c, t + o, true);
			for (int i = 0; i < 8; i++) t[o + i] ^= o ? p[o - 8 + i] : 0;
		}
		u8 crc[2];
		crcA(t, dl, crc);
		if (memcmp(crc, t + dl, 2)) return 0x1E;
		for (u32 i = dl + 2; i < n; i++)
			if (t[i]) return 0x1E;
	} else if (ses.mode == SM_EV1) { // CRC32 over code || header || data, zero padding; the IV runs on
		dfCbc(&ses.c, ses.iv, t, n, false);
		u8 m[1100];
		memcpy(m, c, 1 + hdr);
		memcpy(m + 1 + hdr, t, dl);
		u32 crc = dfCrc32(m, 1 + hdr + dl);
		if (t[dl] != (u8)crc || t[dl + 1] != (u8)(crc >> 8) || t[dl + 2] != (u8)(crc >> 16) || t[dl + 3] != (u8)(crc >> 24))
			return 0x1E;
		for (u32 i = dl + 4; i < n; i++)
			if (t[i]) return 0x1E;
	} else { // EV2: 80 padding
		ev2Iv(true, iv);
		dfCbc(&ses.c, iv, t, n, false);
		if (t[dl] != 0x80) return 0x1E;
		for (u32 i = dl + 1; i < n; i++)
			if (t[i]) return 0x1E;
	}
	memcpy(d, t, dl);
	return 0;
}

static s32 val32(const u8 *p)
{
	return (s32)(p[0] | p[1] << 8 | p[2] << 16 | (u32)p[3] << 24);
}

// WriteData / WriteRecord / Credit / Debit / LimitedCredit (refused) / ClearRecordFile.
static void writeFile(const u8 *c, const u8 *p, u32 n)
{
	u8 cmd = c[0];
	u32 hdr = cmd == 0x3D || cmd == 0x3B ? 7 : 1;
	if (n < hdr) return status(0x7E);
	DfFile *f = file(p[0]);
	if (!f) return status(0xF0);
	if (f->st || f->len < 7) return status(f->st ? f->st : 0x9D);
	u8 type = f->set[0];
	bool std = cmd == 0x3D && type <= 1, rec = (cmd == 0x3B || cmd == 0xEB) && (type == 3 || type == 4);
	if (!std && !rec && !((cmd == 0x0C || cmd == 0xDC || cmd == 0x1C) && type == 2)) return status(0x9E);
	// Credit and ClearRecordFile want the read/write key, Debit any of read / write / read-write
	if (cmd == 0x0C || cmd == 0xEB ? !may(f, false, false) : !may(f, cmd == 0xDC, true)) return status(0x9D);
	if (cmd == 0x1C) return status(0x9D); // LimitedCredit: not kept track of
	if (!f->hasData) return status(0x9D); // contents unknown: nothing to write into
	int ai = app - info.apps, fi = f - app->files;
	DfFile *pf = &pend.apps[ai].files[fi];
	u8 *pp = pend.pool + pf->dataOff;
	u32 room = cap[ai][fi];
	static u8 d[1024];
	if (cmd == 0xEB) {
		pf->dataLen = 0, put24(pf->set + 10, 0);
		recOpen[ai][fi] = false, txOpen = true;
		return status(0);
	}
	u32 dl = hdr == 7 ? le24(p + 4) : 4;
	if (dl > sizeof(d)) return status(0x7E);
	u8 e = writeData(c, hdr, p + hdr, n - hdr, f, dl, d);
	if (e) return status(e);
	if (std) {
		u32 off = le24(p + 1), size = le24(f->set + 4);
		if (!dl || off + dl > size) return status(0xBE);
		if (off + dl > room) return status(0x0E); // past what is kept of the file
		memcpy(pp + off, d, dl);
		if (pf->dataLen < off + dl) pf->dataLen = off + dl;
		if (type == 0) { // standard: at once
			memcpy(info.pool + f->dataOff, pp, room);
			f->dataLen = pf->dataLen;
			writes++;
		} else txOpen = true;
		return status(0);
	}
	if (rec) {
		u32 rs = le24(f->set + 4), max = room / rs, off = le24(p + 1), cnt = pf->dataLen / rs;
		if (!dl || off + dl > rs) return status(0xBE);
		if (!recOpen[ai][fi]) { // a new record: the oldest goes when a cyclic file is full
			if (cnt >= max) {
				if (type == 3 || max < 2) return status(0xBE);
				memmove(pp, pp + rs, (cnt - 1) * rs);
				cnt--;
			}
			memset(pp + cnt * rs, 0, rs);
			cnt++;
			pf->dataLen = cnt * rs, put24(pf->set + 10, cnt);
			recOpen[ai][fi] = true;
		}
		memcpy(pp + (cnt - 1) * rs + off, d, dl);
		txOpen = true;
		return status(0);
	}
	s32 v = val32(pp), amt = val32(d), lo = val32(f->set + 4), hi = val32(f->set + 8);
	if (amt < 0) return status(0x7E);
	s64 nv = cmd == 0x0C ? (s64)v + amt : (s64)v - amt;
	if (nv < lo || nv > hi) return status(0xBE);
	pp[0] = nv, pp[1] = nv >> 8, pp[2] = nv >> 16, pp[3] = nv >> 24;
	txOpen = true;
	return status(0);
}

static void commit(void)
{
	if (txOpen) {
		for (int i = 0; i < info.napps && i < DF_MAX_APPS; i++)
			for (int j = 0; j < info.apps[i].nfiles; j++) {
				DfFile *f = &info.apps[i].files[j], *pf = &pend.apps[i].files[j];
				if (f->dataLen != pf->dataLen || memcmp(f->set, pf->set, sizeof(f->set)) ||
					(f->hasData && memcmp(info.pool + f->dataOff, pend.pool + pf->dataOff, cap[i][j])))
					writes++;
			}
		info = pend;
	}
	memset(recOpen, 0, sizeof(recOpen));
	txOpen = false;
	status(0);
}

static void native(const u8 *c, u32 len)
{
	if (inNeed) { // a write coming in AF frames: the rest, then the whole command
		if (c[0] != 0xAF || inLen + len - 1 > inNeed) {
			inNeed = 0;
			if (c[0] == 0xAF) return status(0x7E);
		} else {
			memcpy(in + inLen, c + 1, len - 1);
			inLen += len - 1;
			if (inLen < inNeed) {
				outLen = outOff = 0, outSt = 0xAF, outVersion = false;
				return;
			}
			inNeed = 0;
			c = in, len = inLen;
		}
	} else if (writeCmd(c[0])) {
		u32 need = writeLen(c, len);
		if (need > sizeof(in)) return status(0x7E);
		if (need > len) {
			memcpy(in, c, len);
			inLen = len, inNeed = need;
			outLen = outOff = 0, outSt = 0xAF, outVersion = false;
			return;
		}
	}
	u8 cmd = c[0], b[256];
	const u8 *p = c + 1;
	u32 n = len - 1, k = 0;
	if (cmd == 0xAF) {
		if (au.on) return authFinish(p, n);
		if (outOff < outLen) return; // the next frame of the answer
		return status(0x1C);
	}
	bool auth = cmd == 0x0A || cmd == 0x1A || cmd == 0xAA || cmd == 0x71 || cmd == 0x77;
	if (!auth) au.on = false;
	ses.macIn = false;
	// EV1: the reader runs its CMAC over every command, so does the card. EV2: a command that ends in its
	// MACt (the reader's MAC / full mode) gets one on the answer too.
	// A MAC-mode write carries the CMAC: off it comes. A full-mode write runs the IV through its data instead.
	if (ses.mode == SM_EV1 && cmd != 0x5A && !auth) {
		u8 mac[16], iv[16];
		const DfFile *f = writeCmd(cmd) && n ? file(p[0]) : NULL;
		memcpy(iv, ses.iv, 16);
		if (f && commOf(f) == 3) {
		} else if (f && len >= 9 && (dfCmac(&ses.c, iv, c, len - 8, mac), !memcmp(mac, c + len - 8, 8))) {
			memcpy(ses.iv, iv, 16);
			n -= 8;
		} else {
			dfCmac(&ses.c, ses.iv, c, len, mac);
		}
	} else if (ses.mode == SM_EV2 && len >= 9 && !auth) {
		u8 mac[8];
		ev2Mac(cmd, p, n - 8, mac);
		if (!memcmp(mac, c + len - 8, 8)) ses.macIn = true, n -= 8;
	}
	switch (cmd) {
	case 0x60: // GetVersion: hardware, then AF software, AF UID / batch / production week
		memcpy(b, info.ver, 28);
		answer(b, info.verLen > 21 ? info.verLen : 21, 0, 0);
		outVersion = true;
		return;
	case 0x5A: { // SelectApplication
		ses.mode = SM_NONE, ses.hasTi = false;
		abortTx();
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
	case 0x0A: case 0x1A: case 0xAA: case 0x71: case 0x77:
		return authStart(cmd, p, n);
	case 0x6A: // GetApplicationIDs
		if (app) return status(0x1C);
		if (info.appSt) return status(info.appSt);
		for (int i = 0; i < info.napps && i < DF_MAX_APPS && k < 250; i++, k += 3) put24(b + k, info.apps[i].aid);
		return answer(b, k, 0, 0);
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
		return answer(b, k, 0, 0);
	case 0x45: // GetKeySettings
		if (app ? app->keySt : info.keySt) return status(app ? app->keySt : info.keySt);
		b[0] = app ? app->keySet : info.keySet, b[1] = app ? app->maxKeys : info.maxKeys;
		return answer(b, 2, 0, 0);
	case 0x64: // GetKeyVersion
		if (n != 1) return status(0x7E);
		if (!app) {
			if (p[0] || info.keyVerSt) return status(p[0] ? 0x40 : info.keyVerSt);
			return answer(&info.keyVer, 1, 0, 0);
		}
		if ((p[0] & 0x3F) >= (app->maxKeys & 0xF)) return status(0x40);
		b[0] = (p[0] & 0x3F) < app->nKeyVer ? app->keyVer[p[0] & 0x3F] : 0; // not in the file: 00
		return answer(b, 1, 0, 0);
	case 0x6F: // GetFileIDs
		if (!app) return status(0x1C);
		if (app->fileSt) return status(app->fileSt);
		for (int i = 0; i < app->nfiles; i++) b[k++] = app->files[i].fid;
		return answer(b, k, 0, 0);
	case 0xF5: { // GetFileSettings
		if (n != 1) return status(0x7E);
		DfFile *f = file(p[0]);
		if (!f) return status(0xF0);
		if (f->st) return status(f->st);
		return answer(f->set, f->len, 0, 0);
	}
	case 0xBD: case 0xBB: case 0x6C:
		return readFile(cmd, p, n);
	case 0x6E: // GetFreeMemory
		if (!info.hasFree) return status(0x1C);
		put24(b, info.freeMem);
		return answer(b, 3, 0, 0);
	case 0x3C: // Read_Sig: 90 with the signature
		if (!info.hasSig) return status(0x1C);
		return answer(info.sig, 56, 0x90, 3);
	case 0x51: // GetCardUID (full mode, the PICC master key's session)
		if (!ses.mode || app || ses.keyNo) return status(0xAE);
		return answer(info.realUid, 7, 0, 3);
	case 0x3D: case 0x3B: case 0x0C: case 0xDC: case 0x1C: case 0xEB:
		return writeFile(c, p, n);
	case 0xC7: // CommitTransaction
		if (!app) return status(0x1C);
		return commit();
	case 0xA7: // AbortTransaction
		if (!app) return status(0x1C);
		abortTx();
		return status(0);
	case 0xDB: case 0xC4: case 0x54: case 0x5F: case 0xCA: case 0xDA: case 0xCD: case 0xCB: case 0xCC: case 0xC0:
	case 0xC1: case 0xDF: case 0xFC: case 0x5C:
		return status(0x9D); // keys, settings, applications, files: not changed here
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
		ses.mode = SM_NONE, ses.hasTi = au.on = false;
		abortTx();
		inNeed = 0;
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
				ses.mode = SM_NONE, ses.hasTi = false;
				abortTx();
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
