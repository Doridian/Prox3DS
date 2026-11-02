#pragma once
#include <3ds.h>

// YubiKey OATH (the applet behind Yubico Authenticator, also ykneo-oath on any JavaCard): accounts, TOTP /
// HOTP codes, the password (PBKDF2 key, HMAC challenge-response), adding and deleting accounts. Over
// iso7816.h, with SEND REMAINING (A5) for long answers.

#define OATH_MAX 64
#define OATH_AID "A0000005272101"
enum { OATH_HOTP = 0x10, OATH_TOTP = 0x20 };
enum { OATH_SHA1 = 1, OATH_SHA256 = 2, OATH_SHA512 = 3 };

typedef struct {
	char name[65];  // as stored: [period/]issuer:account
	u8 type, alg;   // OATH_*
	u8 digits;
	u16 period;     // TOTP: from the name ("60/..."), else 30
	bool touch;     // CALCULATE ALL left it out: it wants a touch (over NFC the tap is one)
	bool hasCode;
	u32 code;
	u64 step;       // TOTP: the time step the code is for (unix time / period)
} OathCred;

typedef struct {
	u8 ver[3];
	u8 idLen, id[8]; // device ID, the password's salt (71)
	bool locked;     // a password is set: VALIDATE first
	u8 chal[8];      // its challenge
	u8 alg;
	int n;
	OathCred c[OATH_MAX];
} OathInfo;

const char *oathWhy(void);
// Card active: ISO-DEP, SELECT. 1 ok, 0 no OATH applet (oathWhy), -1 monitor error.
int oathSelect(OathInfo *o);
// The password's key: PBKDF2-HMAC-SHA1(password, device ID, 1000 rounds, 16 bytes).
void oathKey(const char *pw, const OathInfo *o, u8 key[16]);
// VALIDATE (a locked one, after oathSelect): 1 = the password is right, 0 = wrong (oathWhy), -1 = monitor.
int oathValidate(OathInfo *o, const u8 key[16]);
// LIST, then CALCULATE ALL for unix time t (TOTP with another period on their own). 1 / 0 / -1.
int oathList(OathInfo *o, u64 t);
// CALCULATE one (HOTP: its counter goes up). 1 / 0 / -1.
int oathCalc(OathInfo *o, int i, u64 t);
// PUT: a new account (an existing name is replaced). counter: HOTP's start. 1 / 0 / -1.
int oathPut(const char *name, u8 type, u8 alg, u8 digits, const u8 *secret, u32 len, bool touch, u32 counter);
int oathDelete(const char *name); // 1 / 0 / -1
// SET CODE: a new password's key (NULL: no password). 1 / 0 / -1.
int oathSetCode(const u8 *key);
void oathFormat(const OathCred *c, char *out); // the code with its leading zeros
const char *oathAlgName(u8 alg);
// Base32 (RFC 4648; case, spaces, '-' and '=' ignored) -> bytes. Length, -1 = not base32.
int base32Decode(const char *s, u8 *out, u32 max);
