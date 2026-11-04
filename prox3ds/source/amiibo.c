// Amiibo crypto with the console's keys, see amiibo.h.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "amiibo.h"
#include "amiibodb.h"
#include "dfcrypto.h"
#include "http.h"
#include "mfckeys.h"
#include "probe.h"

static char why[96];
#define FAIL(...) ({ snprintf(why, sizeof(why), __VA_ARGS__); return 0; })

const char *amiiboWhy(void)
{
	return why;
}

typedef struct {
	const char *type; // "unfixed infos" (data) / "locked secret" (tag), with the NUL in the seed
	u8 magicLen, magic[16], hmacKey[16], xorPad[32];
} MasterKey;

static MasterKey keys[2][2]; // [set][data, tag]
static int nsets, loaded;    // loaded: 0 not tried, 1 ok, -1 failed
static int goodSet = -1;     // the set the last figure read verified with

// 3DS ExeFS .code compression ("backward LZ"), in place in a buffer of the decompressed size.
static bool blzDecompress(u8 *buf, u32 inLen, u32 *outLen)
{
	if (inLen < 8) return false;
	u32 top = buf[inLen - 8] | buf[inLen - 7] << 8 | buf[inLen - 6] << 16 | (u32)buf[inLen - 5] << 24;
	u32 extra = buf[inLen - 4] | buf[inLen - 3] << 8 | buf[inLen - 2] << 16 | (u32)buf[inLen - 1] << 24;
	u32 hdr = top >> 24, enc = top & 0xFFFFFF, out = inLen + extra;
	if (hdr < 8 || enc > inLen || hdr > enc) return false;
	u32 src = inLen - hdr, dst = out, stop = inLen - enc;
	while (src > stop) {
		u8 flags = buf[--src];
		for (int i = 0; i < 8 && src > stop; i++, flags <<= 1) {
			if (flags & 0x80) {
				src -= 2;
				u32 v = buf[src] | buf[src + 1] << 8, disp = (v & 0xFFF) + 3, n = (v >> 12) + 3;
				while (n--) {
					dst--;
					buf[dst] = buf[dst + disp];
				}
			} else {
				buf[--dst] = buf[--src];
			}
		}
	}
	*outLen = out;
	return true;
}

// The NFC sysmodule's .code from NAND (New 3DS title first, then Old 3DS), decompressed (malloc'd).
static u8 *readNfcCode(u32 *len)
{
	static const u64 tids[2] = { 0x0004013020004002ULL, 0x0004013000004002ULL };
	static const u32 file[5] = { 0, 0, 2, 0x646F632E, 0x00000065 }; // ExeFS ".code"
	for (int t = 0; t < 2; t++) {
		u32 arch[4] = { (u32)tids[t], (u32)(tids[t] >> 32), MEDIATYPE_NAND, 0 };
		Handle f;
		Result r = FSUSER_OpenFileDirectly(&f, ARCHIVE_SAVEDATA_AND_CONTENT, (FS_Path){ PATH_BINARY, sizeof(arch), arch },
			(FS_Path){ PATH_BINARY, sizeof(file), file }, FS_OPEN_READ, 0);
		if (R_FAILED(r)) {
			snprintf(why, sizeof(why), "open NFC module %016llX .code: %08lX", tids[t], r);
			continue;
		}
		u64 size = 0;
		FSFILE_GetSize(f, &size);
		u8 *buf = malloc(size + 0x40000); // compressed code grows (the footer says by how much)
		u32 got = 0;
		if (buf && R_SUCCEEDED(FSFILE_Read(f, &got, 0, buf, size)) && got == size) {
			FSFILE_Close(f);
			u32 extra = size >= 8 ? (buf[size - 4] | buf[size - 3] << 8 | buf[size - 2] << 16 | (u32)buf[size - 1] << 24) : 0;
			if (extra && extra <= 0x40000 && blzDecompress(buf, size, len)) return buf;
			*len = size; // stored uncompressed
			return buf;
		}
		FSFILE_Close(f);
		free(buf);
		snprintf(why, sizeof(why), "read NFC module .code failed");
	}
	return NULL;
}

// One 106-byte set at p (see the module's FUN 0x114660): "unfixed infos" magic[14] hmac[16] "locked secret"
// magic[16] hmac[16] ctr[16].
static bool parseSet(const u8 *p, MasterKey mk[2], u8 ctr[16])
{
	if (memcmp(p, "unfixed infos", 14) || memcmp(p + 44, "locked secret", 14)) return false;
	mk[0].type = "unfixed infos";
	mk[0].magicLen = 14;
	memcpy(mk[0].magic, p + 14, 14);
	memcpy(mk[0].hmacKey, p + 28, 16);
	mk[1].type = "locked secret";
	mk[1].magicLen = 16;
	memcpy(mk[1].magic, p + 58, 16);
	memcpy(mk[1].hmacKey, p + 74, 16);
	memcpy(ctr, p + 90, 16);
	return true;
}

int amiiboKeysLoad(void)
{
	if (loaded) return loaded > 0;
	loaded = -1;
	u32 len = 0;
	u8 *code = readNfcCode(&len);
	if (!code) return 0;
	nsets = 0;
	for (u32 i = 0; i + 106 <= len && nsets < 2; i++) {
		u8 ctr[16];
		if (code[i] != 'u' || !parseSet(code + i, keys[nsets], ctr)) continue;
		logp("amiibo: key set %d at .code+%lX, crc %08lX\n", nsets, (unsigned long)i, (unsigned long)dfCrc32(code + i, 106));
		u8 zero[32] = { 0 };
		Result r = psInit();
		if (R_SUCCEEDED(r)) {
			r = PS_EncryptDecryptAes(32, zero, keys[nsets][0].xorPad, PS_ALGORITHM_CTR_ENC, PS_KEYSLOT_39_NFC, ctr);
			psExit();
		}
		if (R_FAILED(r)) {
			free(code);
			FAIL("ps:ps AES-CTR with keyslot 0x39: %08lX", r);
		}
		memcpy(keys[nsets][1].xorPad, keys[nsets][0].xorPad, 32); // one pad for both, as the module
		nsets++;
		i += 105;
	}
	free(code);
	if (!nsets) FAIL("no \"unfixed infos\" key table in the NFC module (%lu bytes)", (unsigned long)len);
	logp("amiibo: %d key set%s from the NFC module\n", nsets, nsets == 1 ? "" : "s");
	loaded = 1;
	return 1;
}

// --- amiitool ---

static void keygen(const MasterKey *mk, const u8 *internal, u8 out[48])
{
	u8 base[64], seed[96];
	memcpy(base, internal + 0x029, 2); // write counter
	memset(base + 2, 0, 14);
	memcpy(base + 0x10, internal + 0x1D4, 8); // UID (pages 0-1)
	memcpy(base + 0x18, internal + 0x1D4, 8);
	memcpy(base + 0x20, internal + 0x1E8, 32); // keygen salt
	u32 n = strlen(mk->type) + 1;
	memcpy(seed + 2, mk->type, n); // seed[0..1]: the DRBG's counter
	n += 2;
	memcpy(seed + n, base, 16 - mk->magicLen), n += 16 - mk->magicLen;
	memcpy(seed + n, mk->magic, mk->magicLen), n += mk->magicLen;
	memcpy(seed + n, base + 0x10, 16), n += 16;
	for (int i = 0; i < 32; i++) seed[n + i] = base[0x20 + i] ^ mk->xorPad[i];
	n += 32;
	u8 h[32];
	for (int it = 0; it < 2; it++) { // HMAC-SHA256 DRBG: 2 x 32 bytes, 48 used
		seed[0] = 0, seed[1] = it;
		hmacSha256(mk->hmacKey, 16, seed, n, NULL, 0, h);
		memcpy(out + 32 * it, h, it ? 16 : 32);
	}
}

static void ctrCrypt(const u8 key[16], const u8 iv[16], const u8 *in, u8 *out, u32 n)
{
	DfCipher c;
	dfCipherInit(&c, DF_AES, key);
	u8 ctr[16], ks[16];
	memcpy(ctr, iv, 16);
	for (u32 i = 0; i < n; i += 16) {
		memcpy(ks, ctr, 16);
		dfBlock(&c, ks, true);
		for (u32 k = 0; k < 16 && i + k < n; k++) out[i + k] = in[i + k] ^ ks[k];
		for (int k = 15; k >= 0 && !++ctr[k]; k--) {}
	}
}

static void tagToInternal(const u8 *tag, u8 *in)
{
	memcpy(in + 0x000, tag + 0x008, 0x008);
	memcpy(in + 0x008, tag + 0x080, 0x020);
	memcpy(in + 0x028, tag + 0x010, 0x024);
	memcpy(in + 0x04C, tag + 0x0A0, 0x168);
	memcpy(in + 0x1B4, tag + 0x034, 0x020);
	memcpy(in + 0x1D4, tag + 0x000, 0x008);
	memcpy(in + 0x1DC, tag + 0x054, 0x02C);
}

// Bit 0: the tag HMAC checks out, bit 1: the data HMAC.
static int unpackWith(const MasterKey mk[2], const u8 *internal, u8 *plain)
{
	u8 dk[48], tk[48], h[32]; // aesKey, aesIV, hmacKey
	keygen(&mk[0], internal, dk);
	keygen(&mk[1], internal, tk);
	memcpy(plain, internal, AMIIBO_PLAIN);
	ctrCrypt(dk, dk + 16, internal + 0x02C, plain + 0x02C, 0x188);
	hmacSha256(tk + 32, 16, plain + 0x1D4, 0x34, NULL, 0, h); // the data HMAC covers the tag HMAC
	int ok = !memcmp(h, internal + 0x1B4, 32);
	hmacSha256(dk + 32, 16, plain + 0x029, 0x1DF, NULL, 0, h);
	return ok | !memcmp(h, internal + 0x008, 32) << 1;
}

static void internalToTag(const u8 *in, u8 *tag)
{
	memcpy(tag + 0x008, in + 0x000, 0x008);
	memcpy(tag + 0x080, in + 0x008, 0x020);
	memcpy(tag + 0x010, in + 0x028, 0x024);
	memcpy(tag + 0x0A0, in + 0x04C, 0x168);
	memcpy(tag + 0x034, in + 0x1B4, 0x020);
	memcpy(tag + 0x000, in + 0x1D4, 0x008);
	memcpy(tag + 0x054, in + 0x1DC, 0x02C);
}

// amiitool's pack: the HMACs (tag first: the data HMAC covers it), then the encryption.
static void packWith(const MasterKey mk[2], const u8 *plain, u8 *tag)
{
	u8 dk[48], tk[48], cipher[AMIIBO_PLAIN], m[0x1DF];
	keygen(&mk[0], plain, dk);
	keygen(&mk[1], plain, tk);
	memcpy(cipher, plain, AMIIBO_PLAIN);
	hmacSha256(tk + 32, 16, plain + 0x1D4, 0x34, NULL, 0, cipher + 0x1B4);
	memcpy(m, plain + 0x029, 0x18B);
	memcpy(m + 0x18B, cipher + 0x1B4, 0x20);
	memcpy(m + 0x1AB, plain + 0x1D4, 0x34);
	hmacSha256(dk + 32, 16, m, sizeof(m), NULL, 0, cipher + 0x008);
	ctrCrypt(dk, dk + 16, plain + 0x02C, cipher + 0x02C, 0x188);
	internalToTag(cipher, tag);
}

int amiiboFresh(const u8 *tag, int set, u8 *out)
{
	if (!amiiboKeysLoad()) return 0;
	if (set < 0 || set >= nsets) FAIL("no key set %d", set);
	u8 plain[AMIIBO_PLAIN];
	tagToInternal(tag, plain); // the clear parts: UID, lock bytes, CC, write counter, model info, salt
	memset(plain + 0x02C, 0, 0x188); // settings + app data: zeros, a new figure
	memcpy(out, tag, AMIIBO_TAG);
	packWith(keys[set], plain, out);
	return 1;
}

int amiiboImage(const Amiibo *a, const u8 head[12], bool fresh, u8 *out)
{
	if (!a->ok) FAIL("the source does not verify");
	u8 plain[AMIIBO_PLAIN];
	memcpy(plain, a->plain, AMIIBO_PLAIN);
	if (fresh) memset(plain + 0x02C, 0, 0x188);
	memcpy(plain + 0x1D4, head, 8); // UID + BCC0 (the tag HMAC covers them)
	plain[0] = head[8], plain[1] = head[9]; // BCC1, internal
	static const u8 lockCc[6] = { 0x0F, 0xE0, 0xF1, 0x10, 0xFF, 0xEE };
	memcpy(plain + 2, lockCc, 6);
	memset(out, 0, AMIIBO_TAG);
	packWith(keys[a->set], plain, out);
	const u8 *u = head; // uid = u0 u1 u2 u4 u5 u6 u7 (u3 is BCC0); pm3 pwdgen B
	u8 cfg[20] = { 0x01, 0x00, 0x0F, 0xBD, 0x00, 0x00, 0x00, 0x04, 0x5F, 0x00, 0x00, 0x00,
		u[1] ^ u[4] ^ 0xAA, u[2] ^ u[5] ^ 0x55, u[4] ^ u[6] ^ 0xAA, u[5] ^ u[7] ^ 0x55, 0x80, 0x80, 0x00, 0x00 };
	memcpy(out + 4 * 0x82, cfg, sizeof(cfg));
	return 1;
}

int amiiboNew(const u8 id[8], Amiibo *a)
{
	memset(a, 0, sizeof(*a));
	if (!amiiboKeysLoad()) return 0;
	u8 *p = a->plain;
	p[0x028] = 0xA5; // page 4: A5, write counter 0
	memcpy(p + 0x1DC, id, 8);
	Result r = psInit(); // 4 bytes after the model info, then the keygen salt: random, as each figure's
	if (R_SUCCEEDED(r)) {
		r = PS_GenerateRandomBytes(p + 0x1E4, 0x24);
		psExit();
	}
	if (R_FAILED(r)) FAIL("ps:ps random bytes: %08lX", r);
	memcpy(a->charId, id, 8);
	a->set = goodSet >= 0 ? goodSet : nsets - 1; // retail consoles: set 1 (NOTES.md)
	a->ok = true;
	return 1;
}

int amiiboDbDownload(const char *path)
{
	mkdir(MF_DIR, 0777);
	// The worst a forged list does is name figures wrong (http.h: no certificate checks).
	if (!httpGetFile(AMIIBO_DB_URL, path, 8 << 20, why, sizeof(why))) return 0;
	struct stat st;
	logp("amiibo: figure list, %ld bytes\n", stat(path, &st) ? 0L : (long)st.st_size);
	return 1;
}

static void utf16(const u8 *p, int chars, bool le, char *out, u32 max)
{
	u32 o = 0;
	for (int i = 0; i < chars; i++) {
		u32 c = le ? p[2 * i + 1] << 8 | p[2 * i] : p[2 * i] << 8 | p[2 * i + 1];
		if (!c) break;
		if (c < 0x80 && o + 1 < max) out[o++] = c;
		else if (c < 0x800 && o + 2 < max) out[o++] = 0xC0 | c >> 6, out[o++] = 0x80 | (c & 0x3F);
		else if (c >= 0x800 && o + 3 < max) out[o++] = 0xE0 | c >> 12, out[o++] = 0x80 | (c >> 6 & 0x3F), out[o++] = 0x80 | (c & 0x3F);
	}
	out[o] = 0;
}

int amiiboUnpack(const u8 *tag, Amiibo *a)
{
	memset(a, 0, sizeof(*a));
	if (!amiiboKeysLoad()) return 0;
	u8 internal[AMIIBO_PLAIN];
	tagToInternal(tag, internal);
	for (int s = 0; s < nsets && !a->ok; s++) {
		int h = unpackWith(keys[s], internal, a->plain);
		a->hmacBits |= h << 2 * s;
		if (h == 3) a->ok = true, a->set = goodSet = s;
	}
	const u8 *p = a->plain;
	memcpy(a->charId, p + 0x1DC, 8);
	utf16(p + 0x38, 10, false, a->nickname, sizeof(a->nickname)); // shown when the HMACs fail too: a hint
	if (!a->ok) return 1;
	a->writes = p[0x29] << 8 | p[0x2A];
	a->registered = p[0x2C] & 0x10;
	a->hasAppData = p[0x2C] & 0x20;
	a->setupDate = p[0x30] << 8 | p[0x31];
	a->writeDate = p[0x32] << 8 | p[0x33];
	a->appId = (u32)p[0xB6] << 24 | p[0xB7] << 16 | p[0xB8] << 8 | p[0xB9];
	utf16(p + 0x38, 10, false, a->nickname, sizeof(a->nickname));
	if (a->registered) utf16(p + 0x4C + 0x1A, 10, true, a->owner, sizeof(a->owner)); // the owner Mii's name
	return 1;
}
