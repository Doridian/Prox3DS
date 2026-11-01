// Mifare Classic keys from the UID, see mfckeys.h. Ported from pm3 common/generator.c.

#include <stdint.h>
#include <string.h>

#include "mfckeys.h"

typedef uint32_t w32; // u32 is 64 bits in the host sim
typedef uint64_t w64;

void mfuSha1(const u8 *m, w32 len, u8 out[20]); // mfukeys.c, one block

// --- SHA-256, HMAC, HKDF (RFC 5869) for the filament spools ---

typedef struct {
	w32 h[8];
	u8 buf[64];
	w32 n;   // bytes in buf
	w64 len; // total bytes
} Sha256;

#define ROR(x, n) ((w32)(x) >> (n) | (w32)(x) << (32 - (n)))

static const w32 shaK[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static void shaBlock(Sha256 *s, const u8 *b)
{
	w32 w[64], v[8];
	for (int i = 0; i < 16; i++) w[i] = (w32)b[4 * i] << 24 | b[4 * i + 1] << 16 | b[4 * i + 2] << 8 | b[4 * i + 3];
	for (int i = 16; i < 64; i++) {
		w32 s0 = ROR(w[i - 15], 7) ^ ROR(w[i - 15], 18) ^ w[i - 15] >> 3;
		w32 s1 = ROR(w[i - 2], 17) ^ ROR(w[i - 2], 19) ^ w[i - 2] >> 10;
		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}
	memcpy(v, s->h, sizeof(v));
	for (int i = 0; i < 64; i++) {
		w32 t1 = v[7] + (ROR(v[4], 6) ^ ROR(v[4], 11) ^ ROR(v[4], 25)) + ((v[4] & v[5]) ^ (~v[4] & v[6])) + shaK[i] + w[i];
		w32 t2 = (ROR(v[0], 2) ^ ROR(v[0], 13) ^ ROR(v[0], 22)) + ((v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]));
		memmove(v + 1, v, 7 * sizeof(w32));
		v[4] += t1;
		v[0] = t1 + t2;
	}
	for (int i = 0; i < 8; i++) s->h[i] += v[i];
}

static void shaInit(Sha256 *s)
{
	static const w32 iv[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
	memcpy(s->h, iv, sizeof(iv));
	s->n = 0, s->len = 0;
}

static void shaAdd(Sha256 *s, const u8 *m, w32 len)
{
	s->len += len;
	while (len--) {
		s->buf[s->n++] = *m++;
		if (s->n == 64) shaBlock(s, s->buf), s->n = 0;
	}
}

static void shaDone(Sha256 *s, u8 out[32])
{
	w64 bits = s->len * 8;
	u8 pad = 0x80, z = 0;
	shaAdd(s, &pad, 1);
	while (s->n != 56) shaAdd(s, &z, 1);
	for (int i = 7; i >= 0; i--) {
		u8 b = bits >> (8 * i);
		shaAdd(s, &b, 1);
	}
	for (int i = 0; i < 32; i++) out[i] = s->h[i / 4] >> (24 - 8 * (i % 4));
}

// HMAC-SHA256 over two concatenated parts (a key over 64 bytes isn't needed here)
static void hmac(const u8 *key, w32 klen, const u8 *m1, w32 l1, const u8 *m2, w32 l2, u8 out[32])
{
	u8 k[64] = { 0 }, ih[32];
	memcpy(k, key, klen);
	Sha256 s;
	for (int i = 0; i < 64; i++) k[i] ^= 0x36;
	shaInit(&s), shaAdd(&s, k, 64), shaAdd(&s, m1, l1), shaAdd(&s, m2, l2), shaDone(&s, ih);
	for (int i = 0; i < 64; i++) k[i] ^= 0x36 ^ 0x5C;
	shaInit(&s), shaAdd(&s, k, 64), shaAdd(&s, ih, 32), shaDone(&s, out);
}

static void hkdf(const u8 *salt, w32 slen, const u8 *ikm, w32 ilen, const u8 *info, w32 nlen, u8 *out, w32 olen)
{
	u8 prk[32], t[32 + 64 + 1];
	w32 tl = 0;
	hmac(salt, slen, ikm, ilen, NULL, 0, prk);
	for (u8 i = 1; olen; i++) {
		memcpy(t + tl, info, nlen); // T(i) = HMAC(PRK, T(i-1) || info || i)
		t[tl + nlen] = i;
		u8 h[32];
		hmac(prk, 32, t, tl + nlen + 1, NULL, 0, h);
		w32 n = olen < 32 ? olen : 32;
		memcpy(out, h, n);
		out += n, olen -= n;
		memcpy(t, h, 32), tl = 32;
	}
}

// --- the KDFs: key as a 48-bit number, 0 = doesn't apply ---

static w64 be(const u8 *b, int n)
{
	w64 v = 0;
	while (n--) v = v << 8 | *b++;
	return v;
}

static int saflok(const u8 *uid, int sec, bool kb, w64 *key)
{
	static const w64 lut[16] = {
		0xf057b39ee3d8, 0x969d954ac157, 0x8f43580d2c9d, 0xffcce0050c43, 0x341b15a690cc, 0x89585612e71b,
		0xbb74b0953658, 0xfb97f84b5b74, 0xc9d188359f92, 0x8f92e97f5897, 0x166ca2b09fd1, 0x27dd93101c6c,
		0xda3e3fd649dd, 0x58dded078e3e, 0x5cd005cfd907, 0x118dd00187d0,
	};
	if (sec > 15) return 0;
	if (kb || sec == 2 || sec == 3) *key = 0xFFFFFFFFFFFF;
	else if (sec == 1) *key = 0x2a2c13cc242a;
	else {
		w64 h = (uid[3] >> 4) + (uid[2] >> 4) + (uid[0] & 0xF);
		*key = (h + (be(uid, 4) << 8) + lut[h & 0xF] + (h << 40)) & 0xFFFFFFFFFFFF;
	}
	return 1;
}

static int mizip(const u8 *uid, int sec, bool kb, w64 *key)
{
	static const w64 xa[4] = { 0x09125a2589e5, 0xAB75C937922F, 0xE27241AF2C09, 0x317AB72F4490 };
	static const w64 xb[4] = { 0xF12C8453D821, 0x73E799FE3241, 0xAA4D137656AE, 0xB01327272DFD };
	static const u8 ia[6] = { 0, 1, 2, 3, 0, 1 }, ib[6] = { 2, 3, 0, 1, 2, 3 };
	if (sec > 4) return 0;
	if (!sec) {
		*key = kb ? 0xB4C132439eef : 0xA0A1A2A3A4A5;
		return 1;
	}
	w64 x = (kb ? xb : xa)[sec - 1], k = 0;
	for (int i = 0; i < 6; i++) k = k << 8 | (uid[(kb ? ib : ia)[i]] ^ (u8)(x >> (40 - 8 * i)));
	*key = k;
	return 1;
}

static int disney(const u8 *uid, int sec, bool kb, w64 *key)
{
	if (sec > 4) return 0;
	u8 in[38] = { 0x0A, 0x14, 0xFD, 0x05, 0x07, 0xFF, 0x4B, 0xCD, 0x02, 0x6B, 0xA8, 0x3F, 0x0A, 0x3B, 0x89, 0xA9 }, h[20];
	memcpy(in + 16, uid, 7);
	memcpy(in + 23, "(c) Disney 2013", 15);
	mfuSha1(in, sizeof(in), h);
	*key = (w64)h[3] << 40 | (w64)h[2] << 32 | (w64)h[1] << 24 | (w64)h[0] << 16 | (w64)h[7] << 8 | h[6];
	return 1;
}

static w64 skyCrc(w64 r, u8 b)
{
	r ^= (w64)b << 40;
	for (int i = 0; i < 8; i++) r = (r & 0x800000000000) ? (r << 1) ^ 0x42f0e1eba9ea3693 : r << 1;
	return r;
}

static int skylanders(const u8 *uid, int sec, bool kb, w64 *key)
{
	if (sec > 15) return 0;
	if (kb) *key = 0;
	else if (!sec) *key = 0x4B0B20107CCB;
	else {
		w64 h = 0x9AE903260CC4;
		for (int i = 0; i < 4; i++) h = skyCrc(h, uid[i]);
		h = skyCrc(h, sec) & 0xFFFFFFFFFFFF;
		w64 k = 0;
		for (int i = 0; i < 6; i++) k = k << 8 | (u8)(h >> (8 * i)); // byte-reversed
		*key = k;
	}
	return 1;
}

static int bambu(const u8 *uid, int sec, bool kb, w64 *key)
{
	static const u8 salt[16] = { 0x9a, 0x75, 0x9c, 0xf2, 0xc4, 0xf7, 0xca, 0xff, 0x22, 0x2c, 0xb9, 0x76, 0x9b, 0x41, 0xbc, 0x96 };
	if (sec > 15) return 0;
	u8 k[16 * 6];
	hkdf(salt, sizeof(salt), uid, 4, (const u8 *)(kb ? "RFID-B" : "RFID-A"), 7, k, sizeof(k)); // with the NUL, as pm3
	*key = be(k + 6 * sec, 6);
	return 1;
}

static int snapmaker(const u8 *uid, int sec, bool kb, w64 *key)
{
	if (sec > 15) return 0;
	const char *salt = kb ? "Snapmaker_qwertyuiop[,.;]_1q2w3e" : "Snapmaker_qwertyuiop[,.;]";
	char info[12] = "key_a_";
	info[4] = kb ? 'b' : 'a';
	int n = 6;
	if (sec >= 10) info[n++] = '1';
	info[n++] = '0' + sec % 10;
	u8 k[6];
	hkdf((const u8 *)salt, strlen(salt), uid, 4, (const u8 *)info, n, k, 6);
	*key = be(k, 6);
	return 1;
}

static int vanderbilt(const u8 *uid, int sec, bool kb, w64 *key)
{
	if (sec > 39) return 0;
	int trailer = (sec < 32 ? sec * 4 : 128 + (sec - 32) * 16) + 3;
	*key = 0x416363657300 | (trailer & 0xFF); // "Acces" + the trailer's block number
	return 1;
}

static const struct {
	const char *name;
	int uidLen; // 0 = any
	int (*fn)(const u8 *uid, int sec, bool kb, w64 *key);
} kdfs[] = {
	{ "Saflok / Maid", 4, saflok },
	{ "MIZIP", 4, mizip },
	{ "Disney Infinity", 7, disney },
	{ "Skylanders", 4, skylanders },
	{ "Bambu Lab spool", 4, bambu },
	{ "Snapmaker spool", 4, snapmaker },
	{ "Vanderbilt ACT", 0, vanderbilt },
};
const int mfcNumKdfs = sizeof(kdfs) / sizeof(kdfs[0]);

const char *mfcKdfName(int kdf)
{
	return kdfs[kdf].name;
}

int mfcKdfKey(int kdf, const u8 *uid, int uidLen, int sector, bool keyB, u8 out[6])
{
	w64 k;
	if (kdfs[kdf].uidLen && kdfs[kdf].uidLen != uidLen) return 0;
	if (!kdfs[kdf].fn(uid, sector, keyB, &k)) return 0;
	for (int i = 0; i < 6; i++) out[i] = k >> (40 - 8 * i);
	return 1;
}

int mfcKdfKeys(const u8 *uid, int uidLen, int sector, bool keyB, u8 (*out)[6], const char **names)
{
	int n = 0;
	for (int i = 0; i < mfcNumKdfs && n < MFC_KDF_MAX; i++) {
		u8 k[6];
		if (!mfcKdfKey(i, uid, uidLen, sector, keyB, k)) continue;
		int j = 0;
		while (j < n && memcmp(out[j], k, 6)) j++;
		if (j < n) continue; // another KDF gives it too (FFFFFFFFFFFF...)
		memcpy(out[n], k, 6);
		if (names) names[n] = kdfs[i].name;
		n++;
	}
	return n;
}
