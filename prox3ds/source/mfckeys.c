// Mifare Classic keys from the UID, see mfckeys.h. Ported from pm3 common/generator.c.

#include <stdint.h>
#include <string.h>

#include "mfckeys.h"
#include "sha1.h"

typedef uint32_t w32; // u32 is 64 bits in the host sim
typedef uint64_t w64;

void mfuSha1(const u8 *m, w32 len, u8 out[20]); // mfukeys.c, one block

// --- HMAC-SHA256, HKDF (RFC 5869) for the filament spools ---

// HMAC-SHA256 over two concatenated parts (a key over 64 bytes isn't needed here)
static void hmac(const u8 *key, w32 klen, const u8 *m1, w32 l1, const u8 *m2, w32 l2, u8 out[32])
{
	u8 k[64] = { 0 }, ih[32];
	memcpy(k, key, klen);
	Sha256 s;
	for (int i = 0; i < 64; i++) k[i] ^= 0x36;
	sha256Init(&s), sha256Add(&s, k, 64), sha256Add(&s, m1, l1), sha256Add(&s, m2, l2), sha256Done(&s, ih);
	for (int i = 0; i < 64; i++) k[i] ^= 0x36 ^ 0x5C;
	sha256Init(&s), sha256Add(&s, k, 64), sha256Add(&s, ih, 32), sha256Done(&s, out);
}

void hmacSha256(const u8 *key, u32 klen, const u8 *m1, u32 l1, const u8 *m2, u32 l2, u8 out[32])
{
	hmac(key, klen, m1, l1, m2, l2, out);
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
