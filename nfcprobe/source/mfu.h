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
	bool zeroVersion; // answered GET_VERSION with zeros (a GTU in UL-C / UL mode): taken as no version
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
	bool pwdOk;     // authenticated: the password (it's in the PWD page) or the UL-C key (pages 2C-2F)
	u8 key[16];     // the password (4 bytes) or 3DES key it read with
} MfuDump;

const char *mfuWhy(void);
// 1 = ok, 0 = refused / no answer, -1 = monitor error. The card is selected (active) afterwards.
int mfuIdentify(MfuInfo *info);
int mfuRead(u8 page, u8 out[16]);               // 4 pages from `page` (wrapping at the end of memory)
int mfuPwdAuth(const u8 pwd[4], u8 pack[2]);
// Ultralight C 3DES mutual authentication (1A 00 / AF): 1 = done and the card's answer (RndA') checked,
// 0 = refused or a wrong key (the card is reselected), -1 = monitor error. No lockout counter on the
// UL-C, unlike PWD_AUTH. A Gen4 GTU answers any key, only the RndA' check tells.
int mfuUlcAuth(const u8 key[16]);
// The 3DES key as pages 2C-2F hold it (each 8-byte half byte-reversed), and back.
void mfuUlcKeyPages(const u8 key[16], u8 pages[4][4]);
void mfuUlcKeyFromPages(const u8 pages[4][4], u8 key[16]);
// UL-C: the dictionary (mfukeys.h: remembered for this UID, MFU_KEYS, defaults) until a key works.
// 1 = found (into key, the card is authenticated), 0 = none, -1 = monitor error.
int mfuUlcFindKey(u8 key[16]);
// UL-C key change: authenticates with cur, writes key into pages 2C-2F, then checks that the card
// takes it. 1 = done, 0 = refused (mfuWhy), -1 = monitor error. WRITES THE CARD: a key half written
// (the card pulled away) is a key nobody knows.
int mfuUlcSetKey(const u8 cur[16], const u8 key[16]);
// Writes one user memory page (4 .. userEnd-1; anything else is refused unsent: lock bits and OTP
// are one-way, config pages can lock the card) and reads it back. 1 = verified. WRITES THE CARD.
int mfuWritePage(const MfuType *t, u8 page, const u8 data[4]);
// Writes Type 2 NDEF bytes (ndefTlv: 03 len message FE) from page 4 on: an empty message into page 4
// first, then the rest, page 4 last, so a write cut short leaves an empty tag. Refused unsent without
// an NDEF CC (page 3: E1, write access 0) or when the bytes don't fit the CC's size. 1 = every page
// verified, 0 = refused / NAK (mfuWhy: locked, password), -1 = monitor error. WRITES THE CARD.
int mfuNdefWrite(const MfuType *t, const u8 cc[4], const u8 *data, u32 n);
// Identify + every page that reads, authenticated first with key if given: the password (4 bytes) on
// EV1 / NTAG21x, the 3DES key (16 bytes) on an Ultralight C, which without a key gets the dictionary
// (mfuUlcFindKey). 1 = done (pages read or not are in valid[]), 0 = no Ultralight / NTAG answer,
// -1 = monitor error.
int mfuDumpCard(MfuDump *d, const u8 *key);
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
