#pragma once
#include <3ds.h>

// Amiibo (NTAG215) decryption with this console's own keys, nothing shipped: the NFC sysmodule's .code
// is read from NAND and its key table ("unfixed infos" / "locked secret": magic bytes, HMAC keys, a
// counter) taken from it; the 32-byte XOR pad is AES-CTR under keyslot 0x39 (NFC) through ps:ps, as the
// module does it (FUN 0x114660). The algorithm is amiitool's (socram8888, MIT): HMAC-SHA256 DRBG keys,
// AES-128-CTR over 0x188 bytes, the tag and data HMACs to check. See docs/NOTES.md "Amiibo".
// amiitool (C) 2015-2017 Marcos Del Sol Vives and contributors, MIT license: see CREDITS.md for its notice.

#define AMIIBO_TAG   540 // 135 pages
#define AMIIBO_PLAIN 520 // amiitool's internal layout

// Loads the keys once (later calls return the first result). 1 = ok, 0 = failed (amiiboWhy).
int amiiboKeysLoad(void);
const char *amiiboWhy(void);

typedef struct {
	bool ok;            // both HMACs check out: the keys are right and the data intact
	u8 set;             // which of the module's key sets did it (0 / 1)
	u8 hmacBits;        // per set s: bit 2s the tag HMAC checks out, bit 2s+1 the data HMAC
	u8 plain[AMIIBO_PLAIN];
	char nickname[44];  // UTF-8
	char owner[44];     // the owner Mii's name (registered only)
	u8 charId[8];       // model info: character, variant, figure type, model number, series
	u16 writes;         // Amiibo write counter
	u16 setupDate, writeDate; // (year - 2000) << 9 | month << 5 | day
	u32 appId;
	bool hasAppData, registered;
} Amiibo;

// Decrypts a tag dump (pages 0-134, 540 bytes). 1 = done (a->ok says if it verified), 0 = no keys.
int amiiboUnpack(const u8 *tag, Amiibo *a);

// A fresh, unregistered copy of a tag (its UID, model info and salt kept, the encrypted settings and
// app data zeroed), signed and encrypted with key set `set`: out gets the 540 bytes (pages 0x82-0x86 as
// in tag). 1 = done, 0 = no keys / no such set.
int amiiboFresh(const u8 *tag, int set, u8 *out);

// The image for a blank NTAG215 whose pages 0-2 are head: a's figure (its settings and app data kept,
// or zeroed with fresh: a new, unregistered figure) re-signed for that UID with the key set that
// verified it, and an Amiibo's lock bytes, CC, config, PWD (from the UID) and PACK 8080. For
// mfuAmiiboWrite. 1 = done, 0 = a does not verify.
int amiiboImage(const Amiibo *a, const u8 head[12], bool fresh, u8 *out);

// A new figure of model id, as the factory would make it: nothing set up, a random keygen salt, signed
// with the key set that verified the last figure read (else set 1, the retail one). For amiiboImage
// (fresh). 1 = done, 0 = no keys.
int amiiboNew(const u8 id[8], Amiibo *a);

// Fetches AMIIBO_DB_URL (amiibodb.h) into path. 1 = done, 0 = failed (amiiboWhy).
int amiiboDbDownload(const char *path);
