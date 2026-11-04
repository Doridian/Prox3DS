#pragma once
#include <3ds.h>

#include "mfc.h"

// What a Classic dump holds beyond its blocks: the MIFARE Application Directory (NXP AN10787, pm3
// `hf mf mad`), Saflok hotel key data (pm3 `hf saflok`) and the MFC EV1 / FM11RF08S originality
// signature; shown on the card info screen (editor actions) and summed up in the read result.

// MAD: sector 0 (MAD1, sectors 1-15) and on 4K sector 16 (MAD2, sectors 17-39). AIDs 0-5 are admin codes.
typedef struct {
	u8 gpb, version, info, info2;
	bool multi, crcOk, crc2Ok;
	int n;       // entries, sector = index + 1 (+ 1 more from 16 on: sector 16 is MAD2's own)
	u16 aid[38];
} Mad;
bool mfcMad(const MfDump *d, Mad *m); // false = no MAD (DA bit clear, or sector 0 not read)
const char *madAidName(u16 aid, const char **company); // madnames.c; NULL = unknown
const char *madAdminName(u16 aid);                       // AIDs 0-5, else NULL

// Saflok: 17 bytes (block 1 + block 2 byte 0), encrypted with a byte table and a bit rotation.
typedef struct {
	u16 year;
	u8 month, day, hour, minute;
} SafTime;
typedef struct {
	u8 raw[17]; // decrypted
	u8 level, type, cardId, openingKey, restricted; // restricted: weekday bits
	bool deadbolt, sumOk;
	u16 lockId, pass, seqComb, property;
	u8 iv[5]; // valid for: years, months, days, hours, minutes
	SafTime created, expires;
} Saflok;
void safDecrypt(const u8 enc[17], u8 out[17]);
void safDecode(const u8 raw[17], Saflok *s);
bool mfcSaflok(const MfDump *d, Saflok *s); // sector 1 key A is Saflok's, the data read, checksum ok
const char *safLevelName(int level);

// The signature (MfDump.sig), checked against the MFC keys: the key's name, NULL = none / doesn't verify.
const char *mfcSigCheck(const MfDump *d);

// One line for the read result ("" = nothing to say).
void mfcInfoSummary(const MfDump *d, char *out, u32 max);
void mfcInfoOpen(const MfDump *d); // the card info screen
