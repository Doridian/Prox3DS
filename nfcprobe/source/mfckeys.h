#pragma once
#include <3ds.h>

// Mifare Classic keys derived from the UID: pm3 `hf mf keygen` (common/generator.c KDFTable): Saflok /
// Maid, MIZIP, Disney Infinity (7-byte UID), Skylanders, Bambu Lab and Snapmaker filament spools,
// Vanderbilt ACT. The dump tries them per sector before the dictionary and the attacks.

#define MFC_KDF_MAX 8

// The keys the KDFs give for one sector / key type of the card with this UID, no duplicates; names
// (may be NULL) gets the KDF's name per key. Returns their number.
int mfcKdfKeys(const u8 *uid, int uidLen, int sector, bool keyB, u8 (*out)[6], const char **names);
// One KDF's key (index into the table, for tests): 1 = it applies to this UID length / sector.
int mfcKdfKey(int kdf, const u8 *uid, int uidLen, int sector, bool keyB, u8 out[6]);
const char *mfcKdfName(int kdf);
extern const int mfcNumKdfs;
