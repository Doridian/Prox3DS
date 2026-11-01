#pragma once
#include <3ds.h>

#include "mfc.h"

// MIFARE Ultralight / NTAG (NFC Forum type 2): plaintext commands in data mode (HW parity + CRC), the
// C version of what pm3's hf mfu does. 4-byte pages, READ returns 4 pages at once. A NAK (4-bit answer)
// sends the card back to IDLE, so every failed command is followed by a reselect.

// What GET_VERSION (or, without it, the UL-C AUTH / an NTAG203 page) says the card is.
typedef struct {
	const char *name;
	u8 pages;     // total, including the ones that can't be read (UL-C key, PWD/PACK)
	u8 userEnd;   // user memory is pages 4 .. userEnd-1
	u8 cfg;       // first config page (CFG0, CFG1, PWD, PACK), 0 = none
	u8 dynLock;   // dynamic lock page, 0 = none
	u8 counters;  // bit mask of the READ_CNT counters (EV1: 0-2, NTAG21x: 2)
	bool tearing; // CHECK_TEARING_EVENT (EV1)
	bool pwd;     // PWD_AUTH (EV1, NTAG21x)
} MfuType;

typedef struct {
	const MfuType *type;
	bool hasVersion, hasSig;
	u8 version[8];
	u8 sig[32];
	u8 cnt[3][4];   // counter (3 bytes, LSB first) + tearing flag (BD = intact), pm3's layout
	u8 cntOk, tearOk; // bit masks
	const char *sigKey; // the NXP key the signature verifies with (nxpsig.h), NULL = none / not checked
} MfuInfo;

#define MFU_MAX_PAGES 256
#define MFU_DIR       MF_DIR "/mfu"
// pm3's mfu_dump_t: version[8], tbo[2], tbo1, max page number, signature[32], counters + tearing
// [3][4], then the pages. The same file, so pm3 can load ours (hf mfu restore / eload).
#define MFU_HDR       56

typedef struct {
	MfuInfo info;
	int pages;
	u8 data[MFU_MAX_PAGES][4];
	bool valid[MFU_MAX_PAGES];
	bool pwdOk;     // read with a password (it's in the PWD page)
} MfuDump;

const char *mfuWhy(void);
// 1 = ok, 0 = refused / no answer, -1 = monitor error. The card is selected (active) afterwards.
int mfuIdentify(MfuInfo *info);
int mfuRead(u8 page, u8 out[16]);               // 4 pages from `page` (wrapping at the end of memory)
int mfuPwdAuth(const u8 pwd[4], u8 pack[2]);
// Writes one user memory page (4 .. userEnd-1; anything else is refused unsent: lock bits and OTP
// are one-way, config pages can lock the card) and reads it back. 1 = verified. WRITES THE CARD.
int mfuWritePage(const MfuType *t, u8 page, const u8 data[4]);
// Identify + every page that reads, with the password first if given. 1 = done (pages read or not
// are in valid[]), 0 = no Ultralight / NTAG answer, -1 = monitor error.
int mfuDumpCard(MfuDump *d, const u8 *pwd);
// Writes the dump's user pages onto the card on the reader (same or bigger type), skipping pages
// that already match, every one read back. 1 = done, 0 = refused (mfuWhy), -1 = monitor error.
// WRITES THE CARD.
int mfuRestore(const MfuDump *d, int *written);

// Clones a dump onto a Gen4 GTU (password 00000000): switches it to Ultralight mode for the dump's
// type, writes every page through the backdoor (UID pages last; config pages the dump lacks get the
// factory defaults, a password never read FFFFFFFF), the version, signature and password,
// then reads it back as a reader would (with that password). A GTU that keeps the PACK in page 13
// (version 6666 / 06A0) answers with whatever that page holds, user memory on most types. 1 = verified, 0 = refused / mismatch
// (mfuWhy), -1 = monitor error. WRITES THE CARD AND ITS CONFIG.
int mfuCloneToGtu(const MfuDump *d);

bool mfuSaveDump(const MfuDump *d, char *path, u32 pathMax); // MFU_DIR/<UID>.bin, never overwrites
bool mfuWriteDump(const MfuDump *d, const char *path);       // + <name>.txt: unread pages
bool mfuLoadDump(MfuDump *d, const char *path);              // pm3 .bin (with or without the header)
bool mfuParseDump(MfuDump *d, const u8 *raw, int n);         // the same, from memory
const MfuType *mfuTypeFromVersion(const u8 version[8]);
const MfuType *mfuTypeForPages(int pages); // a dump without a version: guess from its size
extern const MfuType mfuTypeULC; // config in pages 0x28-0x2B, 3DES key in 0x2C-0x2F
