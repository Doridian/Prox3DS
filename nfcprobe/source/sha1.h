#pragma once
#include <3ds.h>

// SHA-1, HMAC-SHA1 and PBKDF2-HMAC-SHA1 (YubiKey OATH: the password's key, the challenge responses).

void sha1(const u8 *m, u32 len, u8 out[20]);
void hmacSha1(const u8 *key, u32 klen, const u8 *m, u32 len, u8 out[20]);
void pbkdf2Sha1(const u8 *pw, u32 pwLen, const u8 *salt, u32 saltLen, u32 iter, u8 *out, u32 outLen);
