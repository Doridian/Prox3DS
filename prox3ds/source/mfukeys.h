#pragma once
#include <3ds.h>

#include "mfu.h"

// Ultralight / NTAG passwords (PWD_AUTH, 4 bytes) and Ultralight C 3DES keys (16 bytes): what to offer
// for a card. The ones that worked on it before (MFU_KNOWN, by UID), MFU_KEYS (one hex key per line,
// 8 or 32 digits, '#' comments, the text after the key is its label), the passwords pm3 `hf mfu
// pwdgen` derives from the UID (common/generator.c) and the factory defaults.

#define MFU_KEYS  MF_DIR "/mfu_keys.txt"
#define MFU_KNOWN MFU_DIR "/known.txt" // "<UID hex> <key hex>" per line, written by mfuRememberKey
#define MFU_PM3_KEYS MFU_DIR "/mfulc_default_keys.dic" // pm3's UL-C keys, downloaded (pm3dict.h)

typedef struct {
	char label[40];
	u8 key[16];
	u8 len;      // 4 = password, 16 = 3DES key
	u8 pack[2];  // the PACK the algorithm gives (derived passwords), valid if hasPack
	bool hasPack, known, match; // known: worked on this UID; match: the card looks like this product
} MfuKey;

#define MFU_MAX_KEYS 64

// Candidates of length len (4 / 16) for the card with this UID. d (may be NULL) gives the version and
// pages 0-15 / 0x21-0x23 for pm3's fingerprints (Amiibo, Lego Dimensions, ...) and the Philips
// password. In order: known, fingerprint match, MFU_KEYS, derived, defaults; no duplicates.
int mfuKeyList(const u8 *uid, u32 uidLen, const MfuDump *d, u8 len, MfuKey *out, int max);
// Remembers that key opened the card with this UID (replaces what was remembered for it).
bool mfuRememberKey(const u8 *uid, u32 uidLen, const u8 *key, u8 len);

// pm3's algorithms (uid = 7 bytes), for tests: A transport, B Amiibo, C Lego Dimensions, D XYZ 3D
// printer, E Xiaomi, F NTAG tools (MD5), G Philips (mfg = 10 bytes from page 0x21 byte 2 on).
u32 mfuPwdGen(char algo, const u8 uid[7], const u8 *mfg);
