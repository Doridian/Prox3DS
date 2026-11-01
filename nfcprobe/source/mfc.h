#pragma once
#include <3ds.h>

#include "crypto1.h"
#include "mon.h"

// Raw ISO14443A and Mifare Classic through the debug monitor; the C version of tools/rawa.py
// and tools/mfc.py. The ROM does the first activation, then the framer is ours (capture on).
// 4-, 7- and 10-byte UIDs (cascade levels 1 to 3).

typedef struct {
	bool active;
	u8 atqa[2];
	u8 uid[10];
	u8 uidLen;
	u8 sak;
} Card;

extern Card card;
// Set from the UI to stop a long operation: card polling, the dump (keeps what it has), the clone
// (between sectors). Cleared by whoever starts the next one.
extern volatile bool mfCancel;

bool iso14aStart(void);  // load the monitor, poll NFC-A until a card is activated, capture on
bool iso14aParity(bool on); // off: we pack parity ourselves (0x5C560 = 8)
// Sends one frame (code = bytes << 4 | extra bits, 0 = len whole bytes) and collects the
// answers; returns their number or -1 on a monitor error.
int iso14aTx(const u8 *data, u32 len, u8 code, MonFrame *ans, int max);
int iso14aSelect(void); // HLTA + WUPA + SELECT; SAK, -1 = no card answer, -2 = monitor error
// Data mode (parity on: HW parity and CRC appended): stale frames dropped, then one frame of whole
// bytes; polls `polls` times (2 ms apart) for the answers. Their count, or -1 on a monitor error.
int iso14aDataTx(const u8 *data, u32 len, MonFrame *ans, int max, int polls);
void iso14aCrc(const u8 *data, u32 len, u8 out[2]); // CRC_A

// Gen1a "magic" backdoor (UID-0 cards): unlock, then plaintext writes with no auth.
bool mfGen1aUnlock(void);
// Writes 16 bytes to a block via the backdoor, then reads it back. 1 = verified, 0 = refused,
// -1 = monitor/no answer. The reason is in mfWhy(). WRITES THE CARD.
int mfGen1aWrite(u8 block, const u8 data[16]);

// Gen4 GTU "magic": plaintext CF <pwd> commands after SELECT, no auth (NOTES.md). 1 = ok (write:
// read back and verified), 0 = no / bad answer (wrong password, not a GTU), -1 = monitor error; the
// reason is in mfWhy(). The config read returns its length (30 or 32 bytes).
extern const u8 mfGen4DefaultPwd[4];
int mfGen4Read(const u8 pwd[4], u8 block, u8 out[16]);
int mfGen4Write(const u8 pwd[4], u8 block, const u8 data[16]); // WRITES THE CARD
int mfGen4Config(const u8 pwd[4], u8 *out, u32 max);
// Writes the 30-byte config (F0, never the fusing F1) and reads it back. Only the protocol (Classic /
// Ultralight), UID length (4, 7 or 10 bytes), shadow mode, ATS, ATQA/SAK and Ultralight mode may
// differ from the current config; anything else (password!) is refused unsent.
// WRITES THE CARD CONFIG.
#define MF_GEN4_CFG 30
int mfGen4SetConfig(const u8 pwd[4], const u8 cfg[MF_GEN4_CFG]);
int mfGen4Version(const u8 pwd[4], u8 *out, u32 max); // CC: 2 bytes (6666) or 5 (000000 06A0), 0 = none

// Magic card detection. Gen2 (CUID) only when asked (it takes longer), the pm3 way with nothing
// written: a known Gen2 ATS, else an ACK to an authenticated WRITE of block 0 (a default key for
// sector 0 must work), aborted before the data.
enum { MF_MAGIC_GEN1A = 1, MF_MAGIC_GEN2 = 2, MF_MAGIC_GEN4 = 4, MF_MAGIC_USCUID = 8 };
typedef struct {
	u8 flags;
	u8 cfgLen;
	u8 cfg[32]; // Gen4 config (C6)
	u8 usc[16]; // USCUID config (E000)
} MfMagic;
int mfMagicDetect(const u8 pwd[4], bool testGen2, MfMagic *m); // flags, -1 on a monitor error

// USCUID ("Gen4 GDM") behind the Gen1a wakeup: 16-byte config read (E000) and write (E100 + data,
// read back). A write may only change byte 6 (block key B if readable), 7 (CUID), 12 (static
// encrypted nonce), each 00 or 5A, and 15 (SAK); the rest (wakeup, shadow, magic auth, perso...)
// could cut off the backdoor. The wipe commands (F0 F1 F6 F8 F9 FE) are never sent. WRITES CONFIG.
#define MF_USC_CFG 16
int mfUscuidConfig(u8 out[MF_USC_CFG]); // 1 ok, 0 no Gen1a wakeup / no config, -1 monitor error
int mfUscuidSetConfig(const u8 cfg[MF_USC_CFG]);

// Parity-off framing: bytes + parity bits <-> raw bit stream (9 bits per byte, LSB first).
u32 mfPack(const u8 *data, u32 len, const u8 *par, u8 *out, u8 *code);
u32 mfUnpack(const u8 *raw, u32 rawLen, u32 off, u8 *out, u32 n);

// 1 = ok, 0 = refused / no valid answer, -1 = monitor error (reload with iso14aStart)
int mfAuth(u8 block, const u8 key[6], bool keyB, Crypto1 *c);
int mfReadBlock(Crypto1 *c, u8 block, u8 out[16]);
// Nested attack: recover a target sector's key from a known key in another sector (two nested
// nonces, crapto1). 1 = recovered (keyOut set), 0 = no answer / not recovered, -1 = monitor error.
int mfNestedRecover(u8 knownBlock, const u8 knownKey[6], bool knownKeyB, u8 targetBlock,
	bool targetKeyB, u8 keyOut[6]);
// FM11RF08S-family static encrypted nonce (NOTES.md). The nested nonce is static; the backdoor
// AUTH (0x64/0x65 with a vendor key) reveals it in clear, a normal nested AUTH gives it encrypted
// under the real key. A key fits a sector iff it decrypts ntEnc to nt -- checked offline.
typedef struct {
	u32 nt, ntEnc;
	u8 par; // raw encrypted parity bits of ntEnc, bit 3 = first byte
} MfStatic;
extern const u8 mfBackdoorKeys[][6];
extern const int mfNumBackdoorKeys;
int mfBackdoorKey(u8 keyOut[6]); // 1 = a backdoor key auths (keyOut set), 0 = none, -1 = monitor
int mfStaticNonce(u8 block, bool keyB, const u8 bdKey[6], MfStatic *st); // 1 ok, 0 no answer, -1 mon
bool mfStaticMatch(const MfStatic *st, const u8 key[6]);

// Encrypted WRITE in an authenticated session (mixed-parity data frame, NOTES.md). 1 = ACKed,
// 0 = NAK / no answer, -1 = monitor error, 2 = this keystream has no usable parity pair (nothing
// sent; re-auth and try again). WRITES THE CARD.
int mfWriteBlock(Crypto1 *c, u8 block, const u8 data[16]);
// Auth + write + encrypted read-back, re-authing until a parity pair fits. 1 = verified, else
// like mfAuth; the reason is in mfWhy(). WRITES THE CARD (trailers too: mind the access bits).
int mfWrite(u8 block, const u8 key[6], bool keyB, const u8 data[16]);
const char *mfWhy(void); // reason for the last mfAuth / write failure

#define MF_MAX_BLOCKS 256
typedef struct {
	int sectors;
	u8 data[MF_MAX_BLOCKS][16];
	bool valid[MF_MAX_BLOCKS];
	u8 keys[40][2][6];
	bool keyFound[40][2];
} MfDump;

// What the running mfDumpCard knows so far, for the UI (the worker writes it; display only).
enum { MF_KEY_OPEN, MF_KEY_TRYING, MF_KEY_FOUND, MF_KEY_FAILED };
typedef struct {
	int sectors;
	u8 key[40][2];  // MF_KEY_*; FAILED = every attack tried, none worked
	u8 blocks[40];  // blocks read
	bool pivot;     // a known key: nested can run for the open ones
	u32 nestedMs, nestedRuns; // time the nested attacks took (for estimates)
} MfDumpProgress;
extern MfDumpProgress mfProg;
#define MF_NESTED_MS 25000 // a typical nested recovery on the 3DS (crapto1 dominates), until measured

int mfFirstBlock(int sector);
int mfSectorBlocks(int sector);
// Finds a key per sector (A, then B) from the list and reads what it can; trailers get the found
// keys filled in. Returns the number of blocks read, -1 if the card is gone.
int mfDumpCard(MfDump *d, int sectors, const u8 (*keys)[6], int nkeys);
extern const u8 mfDefaultKeys[][6];
extern const int mfNumDefaultKeys;

#define MF_MAX_KEYS 256
#define MF_DIR      "sdmc:/nfcprobe"
#define MF_KEYS     MF_DIR "/keys.txt" // one hex key per line, '#' comments
int mfSectorsFromSak(u8 sak);
// extra keys, then MF_KEYS, then the defaults, without duplicates
int mfKeyList(u8 (*out)[6], int max, const u8 (*extra)[6], int nextra);
#define MF_DUMPS    MF_DIR "/dumps"
// Dump files: <name>.bin (raw blocks, unread = zeros) and <name>.keys.txt (per sector "NN A <key> B <key>",
// "--" = not found, then "# unread: <block>..."). mfSaveDump picks MF_DUMPS/<UID>.bin, or <UID>-2.bin and
// so on: it never overwrites. mfLoadDump takes foreign dumps (no key file) with the trailer keys.
bool mfSaveDump(const MfDump *d, char *path, u32 pathMax);
bool mfWriteDump(const MfDump *d, const char *path);
bool mfLoadDump(MfDump *d, const char *path);

// Trailer access bits. Group 0-2 = data blocks (small sectors) or 5-block groups (4K's big sectors),
// 3 = the trailer; the value is C1 C2 C3 as bits 2..0. mfAclSet keeps the inverted copy in step.
bool mfAclValid(const u8 *trailer);
int mfAclGet(const u8 *trailer, int group);
void mfAclSet(u8 *trailer, int group, int c);
bool mfTrailerRewritable(const u8 *trailer); // keys and access bits still writable afterwards

// Writes a dump onto a magic card: Gen4 GTU (default password) and Gen1a/USCUID through their
// backdoors, Gen2 with normal writes and the card's current keys (found like mfDumpCard); a GTU in
// Ultralight mode is switched to Classic first (4-byte UID, ATQA/SAK for the dump's size). Refuses
// unsent: a 4-byte block 0 with a bad BCC (not on the GTU: it computes its own), broken access
// bits, and on Gen2 (unless force) a trailer that would freeze its sector. Sector 0 goes last
// (block 0 changes the UID). Every block is read back (Gen2 trailers: the new key A must auth).
// 1 = done, 0 = refused (mfWhy), -1 = monitor error. WRITES THE CARD.
int mfCloneToMagic(const u8 (*data)[16], const bool *valid, int nblocks, bool force);
