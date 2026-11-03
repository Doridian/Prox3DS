// HID iClass card math, see iclass.h. No hardware here (the host sim builds it too).
// The cipher, key diversification and elite keys derived from loclass (C) 2014 Martin Holst Swende and the Proxmark3 contributors, GPL-3.0-or-later; the config block and
// credential decoding from Proxmark3 (C) Proxmark3 contributors, GPL-3.0-or-later. See CREDITS.md.

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "dfcrypto.h"
#include "iclass.h"

typedef uint32_t w32; // u32 is 64 bits in the host sim
typedef uint64_t w64;

void icCrc(const u8 *data, u32 len, u8 out[2])
{
	w32 crc = 0xE012;
	for (u32 i = 0; i < len; i++) {
		crc ^= data[i];
		for (int b = 0; b < 8; b++) crc = crc & 1 ? crc >> 1 ^ 0x8408 : crc >> 1;
	}
	out[0] = crc;
	out[1] = crc >> 8;
}

bool icCrcOk(const u8 *frame, u32 len)
{
	u8 c[2];
	if (len < 3) return false;
	icCrc(frame, len - 2, c);
	return c[0] == frame[len - 2] && c[1] == frame[len - 1];
}

// --- the cipher (pm3 optimized_cipher.c) ---

typedef struct {
	u8 l, r, b;
	uint16_t t;
} IcState;

static u8 selLut[256];

static void selInit(void)
{
	if (selLut[1]) return; // entry 1 is 3
	for (int r = 0; r < 256; r++) {
		u8 ls2 = r << 2, a = r & ls2, o = r | ls2, n = r & ~ls2;
		u8 z0 = (a >> 5) ^ (n >> 4) ^ (o >> 3);
		u8 z1 = (o >> 6) ^ (o >> 1) ^ (r >> 5) ^ r;
		u8 z2 = (n >> 4) ^ (a >> 3) ^ r;
		selLut[r] = (z0 & 4) | (z1 & 2) | (z2 & 1);
	}
}

static void successor(const u8 *k, IcState *s, u8 y)
{
	w32 tt = s->t & 0xC533;
	tt ^= tt >> 1;
	tt ^= tt >> 4;
	tt ^= tt >> 10;
	tt ^= tt >> 8;
	tt &= 1;
	s->t = s->t >> 1 | ((tt ^ (s->r >> 7) ^ (s->r >> 3)) & 1) << 15;
	u8 ob = s->b ^ (s->b >> 6) ^ (s->b >> 5) ^ (s->b >> 4);
	s->b = s->b >> 1 | ((ob ^ s->r) & 1) << 7;
	u8 sel = (selLut[s->r] & 4) | ((selLut[s->r] ^ ((tt ^ y) << 1)) & 2) | ((selLut[s->r] ^ tt) & 1);
	u8 r = s->r;
	s->r = (k[sel] ^ s->b) + s->l;
	s->l = s->r + r;
}

static void icMac(const u8 *k, const u8 *in, u32 len, bool zeros, u8 mac[4])
{
	selInit();
	IcState s = { (k[0] ^ 0x4C) + 0xEC, (k[0] ^ 0x4C) + 0x21, 0x4C, 0xE012 };
	for (u32 i = 0; i < len; i++)
		for (int b = 0; b < 8; b++) successor(k, &s, in[i] >> b & 1);
	if (zeros)
		for (int i = 0; i < 32; i++) successor(k, &s, 0);
	for (int i = 0; i < 4; i++) {
		u8 v = 0;
		for (int b = 0; b < 8; b++) {
			v |= ((s.r & 4) >> 2) << b;
			successor(k, &s, 0);
		}
		mac[i] = v;
	}
}

void icReaderMac(const u8 divKey[8], const u8 ccnr[12], u8 mac[4])
{
	icMac(divKey, ccnr, 12, false, mac);
}

void icTagMac(const u8 divKey[8], const u8 ccnr[12], u8 mac[4])
{
	icMac(divKey, ccnr, 12, true, mac);
}

// --- key diversification (pm3 optimized_ikeys.c): k = hash0(DES(csn, K)) ---

static const u8 pi[35] = { 0x0F, 0x17, 0x1B, 0x1D, 0x1E, 0x27, 0x2B, 0x2D, 0x2E, 0x33, 0x35, 0x39, 0x36, 0x3A,
	0x3C, 0x47, 0x4B, 0x4D, 0x4E, 0x53, 0x55, 0x56, 0x59, 0x5A, 0x5C, 0x63, 0x65, 0x66, 0x69, 0x6A, 0x6C, 0x71,
	0x72, 0x74, 0x78 };

static u8 six(w64 c, int n)
{
	return c >> (42 - 6 * n) & 0x3F;
}

static void putSix(w64 *c, u8 z, int n)
{
	*c &= ~((w64)0x3F << (42 - 6 * n));
	*c |= (w64)(z & 0x3F) << (42 - 6 * n);
}

static w64 swapZ(w64 c)
{
	w64 z = 0;
	for (int i = 0; i < 8; i++) putSix(&z, six(c, i), 7 - i);
	return z | (c & 0xFFFF000000000000ULL);
}

static w64 ck(int i, int j, w64 z)
{
	while (1) {
		if (i == 1 && j == -1) return z;
		if (j == -1) {
			i--;
			j = i - 1;
			continue;
		}
		if (six(z, i) == six(z, j)) {
			w64 nz = 0;
			for (int c = 0; c < 4; c++) putSix(&nz, c == i ? j : six(z, c), c);
			z = nz;
		}
		j--;
	}
}

static w64 check(w64 z)
{
	w64 a = ck(3, 2, z), b = ck(3, 2, z << 24);
	a &= 0x00000000FFFFFF000000ULL;
	b &= 0x00000000FFFFFF000000ULL;
	return a | b >> 24;
}

static void hash0(w64 c, u8 k[8])
{
	c = swapZ(c);
	u8 x = c >> 56, y = c >> 48;
	w64 zp = 0;
	for (int n = 0; n < 4; n++) {
		putSix(&zp, six(c, n) % (63 - n) + n, n);
		putSix(&zp, six(c, n + 4) % (64 - n) + n, n + 4);
	}
	w64 zc = check(zp);
	u8 p = pi[x % 35];
	if (x & 1) p = ~p;
	// permute: p's bits from the LSB pick z[l++] + 1 (bit 1) or z[r++] (bit 0), 8 six-bit values
	u8 out[8] = { 0 };
	int l = 0, r = 4, pos = 0;
	for (int i = 0; i < 8; i++) {
		u8 v = p >> i & 1 ? six(zc, l++) + 1 : six(zc, r++);
		for (int b = 5; b >= 0; b--, pos++)
			if (v >> b & 1) out[pos >> 3] |= 0x80 >> (pos & 7);
	}
	w64 zt = 0;
	for (int i = 0; i < 8; i++) zt = zt << 8 | out[i];
	zt >>= 16;
	for (int i = 0; i < 8; i++) {
		u8 ki = (y << (7 - i)) & 0x80;
		u8 zti = six(zt, i) << 1, pb = p >> i & 1;
		if (ki) {
			ki |= ~zti & 0x7E;
			ki |= pb;
			ki += 1;
		} else {
			ki |= zti & 0x7E;
			ki |= ~pb & 1;
		}
		k[i] = ki;
	}
}

static void desEnc(const u8 key[8], const u8 in[8], u8 out[8], bool enc)
{
	static DfCipher c; // big (round keys for 3 DES + AES); the worker is the only caller
	dfCipherInit(&c, DF_DES, key);
	memcpy(out, in, 8);
	dfBlock(&c, out, enc);
}

static void diversify(const u8 csn[8], const u8 key[8], u8 div[8])
{
	u8 c[8];
	desEnc(key, csn, c, true);
	w64 v = 0;
	for (int i = 0; i < 8; i++) v = v << 8 | c[i];
	hash0(v, div);
}

// --- elite (pm3 optimized_elite.c): the key is picked from hash2(K) by hash1(csn) ---

static void permuteRev(const u8 key[8], u8 dest[8])
{
	for (int i = 0; i < 8; i++) {
		u8 v = 0;
		for (int j = 0; j < 8; j++) v |= ((key[j] >> (7 - i)) & 1) << (7 - j);
		dest[7 - i] = v;
	}
}

static u8 rr(u8 v) { return v >> 1 | v << 7; }
static u8 rl(u8 v) { return v << 1 | v >> 7; }
static u8 sw(u8 v) { return v >> 4 | v << 4; }

static void hash1(const u8 csn[8], u8 k[8])
{
	k[0] = csn[0] ^ csn[1] ^ csn[2] ^ csn[3] ^ csn[4] ^ csn[5] ^ csn[6] ^ csn[7];
	k[1] = csn[0] + csn[1] + csn[2] + csn[3] + csn[4] + csn[5] + csn[6] + csn[7];
	k[2] = rr(sw(csn[2] + k[1]));
	k[3] = rl(sw(csn[3] + k[0]));
	k[4] = ~rr(csn[4] + k[2]) + 1;
	k[5] = ~rl(csn[5] + k[3]) + 1;
	k[6] = rr(csn[6] + (k[4] ^ 0x3C));
	k[7] = rl(csn[7] + (k[5] ^ 0xC3));
	for (int i = 0; i < 8; i++) k[i] &= 0x7F;
}

static void desIclass(const u8 iclassKey[8], const u8 in[8], u8 out[8], bool enc)
{
	u8 k[8];
	permuteRev(iclassKey, k);
	desEnc(k, in, out, enc);
}

static void hash2(const u8 key[8], u8 table[128])
{
	u8 neg[8], z[8][8], y[8][8], t[8];
	for (int i = 0; i < 8; i++) neg[i] = ~key[i];
	desIclass(key, neg, z[0], true);
	desIclass(z[0], neg, y[0], false);
	for (int i = 1; i < 8; i++) {
		memcpy(t, key, 8);
		for (int n = 0; n < i; n++)
			for (int j = 0; j < 8; j++) t[j] = rl(t[j]);
		desIclass(t, z[i - 1], z[i], false);
		desIclass(t, y[i - 1], y[i], true);
	}
	for (int i = 0; i < 8; i++) {
		memcpy(table + 16 * i, y[i], 8);
		memcpy(table + 16 * i + 8, z[i], 8);
	}
}

void icDivKey(const u8 csn[8], const u8 key[8], int kind, u8 div[8])
{
	if (kind == IC_KEY_DIV) {
		memcpy(div, key, 8);
		return;
	}
	if (kind == IC_KEY_STD) {
		diversify(csn, key, div);
		return;
	}
	u8 table[128], idx[8], sel[8], selp[8];
	hash2(key, table);
	hash1(csn, idx);
	for (int i = 0; i < 8; i++) sel[i] = table[idx[i]];
	permuteRev(sel, selp);
	diversify(csn, selp, div);
}

// --- configuration block (pm3 cmdhficlass.c fuse_config / mem_app_config) ---

void icConfig(const u8 cfg[8], IcConfig *o)
{
	u8 chip = cfg[4], mem = cfg[5], fuses = cfg[7];
	memset(o, 0, sizeof(*o));
	o->appLimit = cfg[0];
	bool multi = chip & 0x10, k16 = mem & 0x80, book = mem & 0x20;
	o->books = o->pages = 1;
	if (multi && !k16 && !book) o->kbits = 2, o->areas = 2;
	else if (multi && k16 && !book) o->kbits = 16, o->areas = 2;
	else if (!multi && !k16 && !book) o->kbits = 16, o->areas = 16, o->pages = 8;
	else if (multi && k16 && book) o->kbits = 32, o->areas = 3, o->books = 2;
	else if (!multi && !k16 && book) o->kbits = 32, o->areas = 17, o->pages = 8, o->books = 2;
	else o->kbits = 32, o->areas = 2;
	u8 type = (chip & 0x10) >> 2 | (mem & 0x80) >> 6 | (mem & 0x20) >> 5;
	o->lastBlock = (type & 3) == 0 ? 0x1F : 0xFF;
	o->personalization = fuses & 0x80;
	o->coding = fuses & 0x40 ? "RFU" : fuses & 0x20 ? "ISO 14443-2 B / 15693" : "ISO 14443-B only";
	o->pagemap = (fuses & 0x18) >> 3;
	o->nonSecure = o->pagemap == 1;
	o->keysLocked = o->pagemap == 2;
	o->readAccess = fuses & 0x01;
	o->keyAccessSplit = mem & 0x01;
}

// --- credential (pm3 iclass_decode_credentials) and Wiegand formats (pm3 wiegand_formats.c) ---

static w32 par(w64 v)
{
	v ^= v >> 32;
	v ^= v >> 16;
	v ^= v >> 8;
	v ^= v >> 4;
	v ^= v >> 2;
	return (v ^ v >> 1) & 1;
}
#define EVEN(x) par(x)
#define ODD(x)  (par(x) ^ 1)

static w64 field(w64 v, u8 n, int start, int len) // bits start.. from the MSB (bit 0) of an n-bit value
{
	return v >> (n - start - len) & (((w64)1 << len) - 1);
}

static w32 bitAt(w64 v, u8 n, int pos)
{
	return v >> (n - 1 - pos) & 1;
}

typedef struct {
	const char *id, *name;
	u8 bits;
	bool (*unpack)(w64 v, IcCredential *o); // fills fc / cn / hasFc, returns the parity check
} WgFormat;

static bool wgH10301(w64 v, IcCredential *o)
{
	w32 bot = v;
	o->cn = bot >> 1 & 0xFFFF, o->fc = bot >> 17 & 0xFF, o->hasFc = true;
	return ODD(bot >> 1 & 0xFFF) == (bot & 1) && EVEN(bot >> 13 & 0xFFF) == (bot >> 25 & 1);
}

static bool wgC1k35s(w64 v, IcCredential *o)
{
	w32 bot = v, mid = v >> 32;
	o->cn = bot >> 1 & 0xFFFFF, o->fc = (mid & 1) << 11 | bot >> 21, o->hasFc = true;
	return EVEN((mid & 1) ^ (bot & 0xB6DB6DB6)) == (mid >> 1 & 1) &&
		ODD((mid & 3) ^ (bot & 0x6DB6DB6C)) == (bot & 1) &&
		ODD((mid & 3) ^ bot) == (mid >> 2 & 1);
}

static bool wgC1k48s(w64 v, IcCredential *o)
{
	w32 bot = v, mid = v >> 32;
	o->cn = bot >> 1 & 0x7FFFFF, o->fc = (mid & 0x3FFF) << 8 | bot >> 24, o->hasFc = true;
	return EVEN((mid & 0x1B6D) ^ (bot & 0xB6DB6DB6)) == (mid >> 14 & 1) &&
		ODD((mid & 0x36DB) ^ (bot & 0x6DB6DB6C)) == (bot & 1) &&
		ODD((mid & 0x7FFF) ^ bot) == (mid >> 15 & 1);
}

static bool wgH10306(w64 v, IcCredential *o)
{
	o->fc = field(v, 34, 1, 16), o->cn = field(v, 34, 17, 16), o->hasFc = true;
	return bitAt(v, 34, 0) == EVEN(field(v, 34, 1, 16)) && bitAt(v, 34, 33) == ODD(field(v, 34, 17, 16));
}

static bool wgH10304(w64 v, IcCredential *o)
{
	o->fc = field(v, 37, 1, 16), o->cn = field(v, 37, 17, 19), o->hasFc = true;
	return bitAt(v, 37, 0) == EVEN(field(v, 37, 1, 18)) && bitAt(v, 37, 36) == ODD(field(v, 37, 18, 18));
}

static bool wgH10302(w64 v, IcCredential *o)
{
	o->cn = field(v, 37, 1, 35), o->hasFc = false;
	return bitAt(v, 37, 0) == EVEN(field(v, 37, 1, 18)) && bitAt(v, 37, 36) == ODD(field(v, 37, 18, 18));
}

static const WgFormat formats[] = {
	{ "H10301", "HID H10301 26-bit", 26, wgH10301 },
	{ "H10306", "HID H10306 34-bit", 34, wgH10306 },
	{ "C1k35s", "HID Corporate 1000 35-bit", 35, wgC1k35s },
	{ "H10304", "HID H10304 37-bit", 37, wgH10304 },
	{ "H10302", "HID H10302 37-bit", 37, wgH10302 },
	{ "C1k48s", "HID Corporate 1000 48-bit", 48, wgC1k48s },
};

bool icWiegand(u64 v, u8 bits, IcCredential *o)
{
	for (int pass = 0; pass < 2; pass++) // parity ok first, then any format of that length
		for (u32 i = 0; i < sizeof(formats) / sizeof(formats[0]); i++) {
			if (formats[i].bits != bits) continue;
			IcCredential t = *o;
			bool ok = formats[i].unpack(v, &t);
			if (pass == 0 && !ok) continue;
			*o = t;
			o->parityOk = ok;
			snprintf(o->format, sizeof(o->format), "%s", formats[i].id);
			snprintf(o->name, sizeof(o->name), "%s", formats[i].name);
			return true;
		}
	return false;
}

void icCredential(const u8 *blocks, u32 nblocks, const u8 *key, IcCredential *o)
{
	static const u8 ff[8] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }, zero[8] = { 0 };
	memset(o, 0, sizeof(*o));
	if (nblocks < 10 || memcmp(blocks + 5 * 8, ff, 8)) return; // only legacy cards (AIA all FF)
	u8 b7[8];
	memcpy(b7, blocks + 7 * 8, 8);
	if (!memcmp(b7, ff, 8) || !memcmp(b7, zero, 8)) return;
	o->present = true;
	u8 enc = blocks[6 * 8 + 7] & 3;
	if (enc >= 2) {
		if (!key) {
			o->encrypted = true;
			return;
		}
		static DfCipher c;
		dfCipherInit(&c, enc == 3 ? DF_2K3DES : DF_DES, key);
		dfBlock(&c, b7, false);
	}
	w64 v = 0;
	for (int i = 0; i < 8; i++) v = v << 8 | b7[i];
	int n = 64;
	while (n > 0 && !(v >> (n - 1) & 1)) n--;
	// a leading sentinel 1 makes the length one more than the format's
	if (n == 27 || n == 31 || n == 34 || n == 35 || n == 36 || n == 37 || n == 38 || n == 47 || n == 49) {
		n--;
		v &= ((w64)1 << n) - 1;
	}
	o->bits = n;
	o->value = v;
	icWiegand(v, n, o);
}
