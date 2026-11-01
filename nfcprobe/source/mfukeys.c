// Ultralight / NTAG passwords and Ultralight C keys to offer, see mfukeys.h.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "mfukeys.h"

typedef uint32_t w32; // u32 is 64 bits in the host sim

#define ROL(x, n) ((w32)(x) << ((n) & 31) | (w32)(x) >> ((32 - ((n) & 31)) & 31))
#define ROR(x, n) ROL(x, 32 - (n))

// --- hashes for the Xiaomi (SHA-1) and NTAG tools (MD5) passwords: one block, 7 bytes in ---

void mfuSha1(const u8 *m, w32 len, u8 out[20]) // also mfckeys.c
{
	u8 b[64] = { 0 };
	memcpy(b, m, len);
	b[len] = 0x80;
	b[62] = len * 8 >> 8, b[63] = len * 8;
	w32 w[80], h[5] = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 };
	for (int i = 0; i < 16; i++) w[i] = b[4 * i] << 24 | b[4 * i + 1] << 16 | b[4 * i + 2] << 8 | b[4 * i + 3];
	for (int i = 16; i < 80; i++) w[i] = ROL(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
	w32 a = h[0], bb = h[1], c = h[2], d = h[3], e = h[4];
	for (int i = 0; i < 80; i++) {
		w32 f, k;
		if (i < 20) f = (bb & c) | (~bb & d), k = 0x5A827999;
		else if (i < 40) f = bb ^ c ^ d, k = 0x6ED9EBA1;
		else if (i < 60) f = (bb & c) | (bb & d) | (c & d), k = 0x8F1BBCDC;
		else f = bb ^ c ^ d, k = 0xCA62C1D6;
		w32 t = ROL(a, 5) + f + e + k + w[i];
		e = d, d = c, c = ROL(bb, 30), bb = a, a = t;
	}
	h[0] += a, h[1] += bb, h[2] += c, h[3] += d, h[4] += e;
	for (int i = 0; i < 20; i++) out[i] = h[i / 4] >> (24 - 8 * (i % 4));
}

static void md5(const u8 *m, w32 len, u8 out[16])
{
	static const u8 r[64] = { 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20,
		5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10,
		15, 21, 6, 10, 15, 21, 6, 10, 15, 21 };
	static const w32 k[64] = { 0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
		0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
		0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6,
		0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681,
		0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa, 0xd4ef3085,
		0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
		0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82,
		0xbd3af235, 0x2ad7d2bb, 0xeb86d391 };
	u8 b[64] = { 0 };
	memcpy(b, m, len);
	b[len] = 0x80;
	b[56] = len * 8, b[57] = len * 8 >> 8;
	w32 w[16], h[4] = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 };
	for (int i = 0; i < 16; i++) w[i] = b[4 * i] | b[4 * i + 1] << 8 | b[4 * i + 2] << 16 | b[4 * i + 3] << 24;
	w32 a = h[0], bb = h[1], c = h[2], d = h[3];
	for (int i = 0; i < 64; i++) {
		w32 f;
		int g;
		if (i < 16) f = (bb & c) | (~bb & d), g = i;
		else if (i < 32) f = (d & bb) | (~d & c), g = (5 * i + 1) % 16;
		else if (i < 48) f = bb ^ c ^ d, g = (3 * i + 5) % 16;
		else f = c ^ (bb | ~d), g = 7 * i % 16;
		w32 t = d;
		d = c, c = bb;
		bb += ROL(a + f + k[i] + w[g], r[i]);
		a = t;
	}
	h[0] += a, h[1] += bb, h[2] += c, h[3] += d;
	for (int i = 0; i < 16; i++) out[i] = h[i / 4] >> (8 * (i % 4));
}

// CRC-16/CCITT, MSB first, from init (pm3 crc16_fast(.., false, false))
static u16 crc16(const u8 *p, w32 len, u16 crc)
{
	while (len--) {
		crc ^= *p++ << 8;
		for (int i = 0; i < 8; i++) crc = crc & 0x8000 ? crc << 1 ^ 0x1021 : crc << 1;
	}
	return crc;
}

// --- pm3 common/generator.c ---

static void transformD(u8 *ru)
{
	static const w32 c[] = { 0x6D835AFC, 0x7D15CD97, 0x0942B409, 0x32F9C923, 0xA811FB02, 0x64F121E8, 0xD1CC8B4E,
		0xE8873E6F, 0x61399BBB, 0xF1B91926, 0xAC661520, 0xA21A31C9, 0xD424808D, 0xFE118E07, 0xD18E728D, 0xABAC9E17,
		0x18066433, 0x00E18E79, 0x65A77305, 0x5AE9E297, 0x11FC628C, 0x7BB3431F, 0x942A8308, 0xB2F8FD20, 0x5728B869,
		0x30726D5A };
	int p = 0;
	w32 v1 = (ru[3] << 24 | ru[2] << 16 | ru[1] << 8 | ru[0]) + c[p++];
	w32 v2 = (ru[7] << 24 | ru[6] << 16 | ru[5] << 8 | ru[4]) + c[p++];
	for (int i = 0; i < 12; i += 2) {
		w32 t1 = ROL(v1 ^ v2, v2) + c[p++];
		w32 t2 = ROL(v2 ^ t1, t1) + c[p++];
		v1 = ROL(t1 ^ t2, t2) + c[p++];
		v2 = ROL(t2 ^ v1, v1) + c[p++];
	}
	for (int i = 0; i < 4; i++) ru[i] = v1 >> 8 * i, ru[4 + i] = v2 >> 8 * i;
}

static w32 be32(const u8 *b)
{
	return b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3];
}

static w32 bswap(w32 x)
{
	return x >> 24 | (x >> 8 & 0xFF00) | (x << 8 & 0xFF0000) | x << 24;
}

u32 mfuPwdGen(char algo, const u8 uid[7], const u8 *mfg)
{
	switch (algo) {
	case 'A': {
		static const w32 x[] = { 0x4f2711c1, 0x07D7BB83, 0x9636EF07, 0xB5F4460E, 0xF271141C, 0x7D7BB038, 0x636EF871,
			0x5F4468E3, 0x271149C7, 0xD7BB0B8F, 0x36EF8F1E, 0xF446863D, 0x7114947A, 0x7BB0B0F5, 0x6EF8F9EB, 0x44686BD7,
			0x11494fAF, 0xBB0B075F, 0xEF8F96BE, 0x4686B57C, 0x1494F2F9, 0xB0B07DF3, 0xF8F963E6, 0x686B5FCC, 0x494F2799,
			0x0B07D733, 0x8F963667, 0x86B5F4CE, 0x94F2719C, 0xB07D7B38, 0xF9636E70, 0x6B5F44E0 };
		w32 e = x[(uid[3] ^ uid[4] ^ uid[5] ^ uid[6]) % 32];
		u8 p[4] = { (e >> 24) ^ uid[1] ^ uid[2] ^ uid[3], (e >> 16) ^ uid[0] ^ uid[2] ^ uid[4],
			(e >> 8) ^ uid[0] ^ uid[1] ^ uid[5], e ^ uid[6] };
		return be32(p);
	}
	case 'B': {
		u8 p[4] = { uid[1] ^ uid[3] ^ 0xAA, uid[2] ^ uid[4] ^ 0x55, uid[3] ^ uid[5] ^ 0xAA, uid[4] ^ uid[6] ^ 0x55 };
		return be32(p);
	}
	case 'C': {
		w32 base[8] = { 0xffffffff, 0x28ffffff, 0x43202963, 0x7279706f, 0x74686769, 0x47454c20, 0x3032204f, 0xaaaa3431 };
		memcpy(base, uid, 7); // little-endian words, as on the ARM pm3 runs on
		w32 pwd = 0;
		for (int i = 0; i < 8; i++) pwd = base[i] + ROR(pwd, 25) + ROR(pwd, 10) - pwd;
		return bswap(pwd);
	}
	case 'D': {
		u8 ru[8] = { 0 }, r = (uid[1] + uid[3] + uid[5]) & 7;
		for (int i = 0; i < 7; i++) ru[(i + r) & 7] = uid[i];
		transformD(ru);
		r = (ru[0] + ru[2] + ru[4] + ru[6]) & 3;
		w32 pwd = 0;
		for (int i = 0; i < 4; i++) pwd = ru[i + r] + (pwd << 8);
		return bswap(pwd);
	}
	case 'E': {
		u8 h[20];
		mfuSha1(uid, 7, h);
		return (w32)h[h[0] % 20] << 24 | h[(h[0] + 5) % 20] << 16 | h[(h[0] + 13) % 20] << 8 | h[(h[0] + 17) % 20];
	}
	case 'F': {
		u8 h[16];
		md5(uid, 7, h);
		return be32(h);
	}
	case 'G': {
		u16 c1 = crc16(uid, 7, 0x49A3), c2 = crc16(mfg, 10, c1);
		return (w32)(c2 >> 8 | (c2 & 0xFF) << 8) << 16 | (c1 >> 8 | (c1 & 0xFF) << 8);
	}
	}
	return 0xFFFFFFFF;
}

static u16 packGen(char algo, const u8 uid[7], const u8 *mfg)
{
	switch (algo) {
	case 'A': return (uid[0] ^ uid[1] ^ uid[2]) << 8 | (uid[2] ^ 8);
	case 'B': return 0x8080;
	case 'C': return 0xAA55;
	case 'D': {
		u8 ru[8] = { 0 }, r = (uid[2] + uid[5]) & 7;
		for (int i = 0; i < 7; i++) ru[(i + r) & 7] = uid[i];
		transformD(ru);
		w32 p = 0;
		for (int i = 0; i < 8; i++) p += ru[i] * 13;
		p = (p ^ 0x5555) & 0xFFFF;
		return p >> 8 | (p & 0xFF) << 8;
	}
	case 'E': return 0xAD00 | mfuPwdGen('E', uid, NULL) >> 24;
	case 'G': {
		u16 c1 = crc16(uid, 7, 0x49A3), c2 = crc16(mfg, 10, c1);
		w32 pwd = mfuPwdGen('G', uid, mfg);
		u8 pb[4] = { pwd >> 24, pwd >> 16, pwd >> 8, pwd };
		u16 c = crc16(pb, 4, c2);
		return c >> 8 | (c & 0xFF) << 8;
	}
	}
	return 0;
}

static const struct {
	char algo;
	const char *name;
} algos[] = { { 'A', "Transport EV1" }, { 'B', "Amiibo" }, { 'C', "Lego Dimensions" }, { 'D', "XYZ 3D printer" },
	{ 'E', "Xiaomi purifier" }, { 'F', "NTAG tools" }, { 'G', "Philips toothbrush" } };

// pm3 mfu_ident_table, the entries with a derived password: version, then bytes from page 0 on.
static const struct {
	const char *name;
	char algo;
	u8 version[8];
	u8 pos, len;
	const char *match;
} prints[] = {
	{ "Lego Dimensions", 'C', { 0, 4, 4, 2, 1, 0, 0x0F, 3 }, 12, 18, "E11012000103A00C340313D1010F5402656E" },
	{ "Amiibo", 'B', { 0, 4, 4, 2, 1, 0, 0x11, 3 }, 9, 9, "480FE0F110FFEEA500" },
	{ "Amiibo (Power Up band)", 'B', { 0, 4, 4, 5, 2, 2, 0x13, 3 }, 8, 10, "44000FE0F110FFEEA500" },
};

static bool fingerprint(const MfuDump *d, int i)
{
	if (!d || !d->info.hasVersion || memcmp(d->info.version, prints[i].version, 8)) return false;
	for (int k = 0; k < prints[i].len; k++) {
		int b = prints[i].pos + k, p = b / 4;
		unsigned v;
		if (p >= d->pages || !d->valid[p] || sscanf(prints[i].match + 2 * k, "%2x", &v) != 1) return false;
		if (d->data[p][b % 4] != v) return false;
	}
	return true;
}

// --- the list ---

static int parseHex(const char *s, u8 *out, int max, const char **end)
{
	int n = 0;
	while (*s == ' ' || *s == '\t') s++;
	for (; n < max; n++, s += 2) {
		unsigned v;
		if (!s[0] || !s[1] || !strchr("0123456789abcdefABCDEF", s[0]) || !strchr("0123456789abcdefABCDEF", s[1]))
			break;
		sscanf(s, "%2x", &v);
		out[n] = v;
	}
	if (end) *end = s;
	return n;
}

static void uidHexStr(const u8 *uid, u32 uidLen, char *out)
{
	for (w32 i = 0; i < uidLen; i++) sprintf(out + 2 * i, "%02X", uid[i]);
}

static int add(MfuKey *out, int n, int max, u8 len, const u8 *key, const char *label)
{
	if (n >= max) return n;
	for (int i = 0; i < n; i++)
		if (!memcmp(out[i].key, key, len)) return n;
	memset(&out[n], 0, sizeof(*out));
	memcpy(out[n].key, key, len);
	out[n].len = len;
	snprintf(out[n].label, sizeof(out[n].label), "%s", label);
	return n + 1;
}

int mfuKeyList(const u8 *uid, u32 uidLen, const MfuDump *d, u8 len, MfuKey *out, int max)
{
	int n = 0;
	char line[160], want[32];
	u8 key[16];
	const char *end;
	uidHexStr(uid, uidLen, want);
	FILE *f = fopen(MFU_KNOWN, "r");
	while (f && fgets(line, sizeof(line), f)) {
		if (strncasecmp(line, want, strlen(want)) || line[strlen(want)] != ' ') continue;
		if (parseHex(line + strlen(want), key, 16, NULL) != len) continue;
		n = add(out, n, max, len, key, "Opened this card before");
		out[n - 1].known = true;
	}
	if (f) fclose(f);

	u8 u7[7] = { 0 }, mfg[10] = { 0 };
	memcpy(u7, uid, uidLen < 7 ? uidLen : 7);
	bool hasMfg = d && 0x23 < d->pages && d->valid[0x21] && d->valid[0x22] && d->valid[0x23];
	if (hasMfg) memcpy(mfg, d->data[0x21] + 2, 2), memcpy(mfg + 2, d->data[0x22], 4), memcpy(mfg + 6, d->data[0x23], 4);
	if (len == 4) {
		for (w32 i = 0; i < sizeof(prints) / sizeof(prints[0]); i++) {
			if (!fingerprint(d, i)) continue;
			w32 p = mfuPwdGen(prints[i].algo, u7, NULL);
			u8 b[4] = { p >> 24, p >> 16, p >> 8, p };
			snprintf(line, sizeof(line), "%s (looks like one)", prints[i].name);
			int m = n;
			if ((n = add(out, n, max, 4, b, line)) > m) {
				u16 pk = packGen(prints[i].algo, u7, NULL);
				out[m].pack[0] = pk >> 8, out[m].pack[1] = pk, out[m].hasPack = out[m].match = true;
			}
		}
	}

	if ((f = fopen(MFU_KEYS, "r"))) {
		while (fgets(line, sizeof(line), f)) {
			if (parseHex(line, key, 16, &end) != len || (*end && !strchr(" \t#\r\n", *end))) continue;
			while (*end == ' ' || *end == '\t' || *end == '#') end++;
			char label[40];
			snprintf(label, sizeof(label), "%s", *end && *end != '\r' && *end != '\n' ? end : "mfu_keys.txt");
			label[strcspn(label, "\r\n")] = 0;
			n = add(out, n, max, len, key, label);
		}
		fclose(f);
	}

	if (len == 4) {
		for (w32 i = 0; i < sizeof(algos) / sizeof(algos[0]); i++) {
			if (algos[i].algo == 'G' && !hasMfg) continue;
			w32 p = mfuPwdGen(algos[i].algo, u7, mfg);
			u8 b[4] = { p >> 24, p >> 16, p >> 8, p };
			snprintf(line, sizeof(line), "%s (from the UID)", algos[i].name);
			int m = n;
			if ((n = add(out, n, max, 4, b, line)) > m && algos[i].algo != 'F') {
				u16 pk = packGen(algos[i].algo, u7, mfg);
				out[m].pack[0] = pk >> 8, out[m].pack[1] = pk, out[m].hasPack = true;
			}
		}
		static const u8 ff[4] = { 0xFF, 0xFF, 0xFF, 0xFF }, zero[4];
		n = add(out, n, max, 4, ff, "Factory default");
		n = add(out, n, max, 4, zero, "Zeros");
	} else {
		// pm3 mfulc_default_keys.dic, as the 3DES key (each half byte-reversed in pages 2C-2F)
		static const char *const ulc[][2] = {
			{ "49454D4B41455242214E4143554F5946", "Factory default (BREAKMEIFYOUCAN!)" },
			{ "425245414B4D454946594F5543414E21", "BREAKMEIFYOUCAN! unreversed" },
			{ "214E4143554F594649454D4B41455242", "Byte-reversed sample key" },
			{ "12E4143455F495649454D4B414542524", "Hex-reversed sample key" },
			{ "49454D4B41455242214E4143554F5900", "Semnox" },
			{ "921AAC1654B8D83A669A9012AE7C1222", "iKey UL-C magic tag" },
			{ "D2C8C2CEC8CCC420204E4042544E5846", "Kyiv NKS Vizit" },
			{ "00000000000000000000000000000000", "Zeros" },
			{ "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", "FF" },
		};
		for (w32 i = 0; i < sizeof(ulc) / sizeof(ulc[0]); i++) {
			parseHex(ulc[i][0], key, 16, NULL);
			n = add(out, n, max, 16, key, ulc[i][1]);
		}
	}
	return n;
}

bool mfuRememberKey(const u8 *uid, u32 uidLen, const u8 *key, u8 len)
{
	static char lines[256][80];
	char want[32], line[80];
	int n = 0;
	uidHexStr(uid, uidLen, want);
	FILE *f = fopen(MFU_KNOWN, "r");
	while (f && fgets(line, sizeof(line), f) && n < 255) {
		u8 k[16];
		bool same = !strncasecmp(line, want, strlen(want)) && line[strlen(want)] == ' ';
		if (same && parseHex(line + strlen(want), k, 16, NULL) == len) {
			if (!memcmp(k, key, len)) {
				fclose(f);
				return true;
			}
			continue; // the old key of this length goes
		}
		snprintf(lines[n++], sizeof(lines[0]), "%s", line);
	}
	if (f) fclose(f);
	char *p = lines[n] + sprintf(lines[n], "%s ", want);
	for (int i = 0; i < len; i++) p += sprintf(p, "%02X", key[i]);
	sprintf(p, "\n");
	n++;
	mkdir(MF_DIR, 0777);
	mkdir(MFU_DIR, 0777);
	if (!(f = fopen(MFU_KNOWN, "w"))) return false;
	for (int i = 0; i < n; i++) fputs(lines[i], f);
	return !fclose(f);
}
