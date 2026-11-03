#pragma once
#include <3ds.h>

// SHA-1, HMAC-SHA1 and PBKDF2-HMAC-SHA1 (YubiKey OATH: the password's key, the challenge responses), SHA-256
// (filament spool keys, Java Card MessageDigest).

typedef struct {
	uint32_t h[5];
	u8 buf[64];
	u32 n;
	u64 total;
} Sha1;
void sha1Init(Sha1 *s);
void sha1Add(Sha1 *s, const u8 *m, u32 len);
void sha1Done(Sha1 *s, u8 out[20]);

typedef struct {
	uint32_t h[8];
	u8 buf[64];
	uint32_t n;   // bytes in buf
	uint64_t len; // total bytes
} Sha256;
void sha256Init(Sha256 *s);
void sha256Add(Sha256 *s, const u8 *m, uint32_t len);
void sha256Done(Sha256 *s, u8 out[32]);

void sha1(const u8 *m, u32 len, u8 out[20]);
void hmacSha1(const u8 *key, u32 klen, const u8 *m, u32 len, u8 out[20]);
void pbkdf2Sha1(const u8 *pw, u32 pwLen, const u8 *salt, u32 saltLen, u32 iter, u8 *out, u32 outLen);
