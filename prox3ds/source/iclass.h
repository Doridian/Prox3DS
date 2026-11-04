#pragma once
#include <3ds.h>

#include "pm3dict.h"

// HID iClass / PicoPass: the card side's math (iclass.c, no hardware) and the reader (iclassrw.c) over
// the chip monitor. The BCM sends ISO15693 1-of-4 frames from a stalled V poll (I93_DATARATE 2, framer
// 0x5C558 = 5) and receives the card's answers with the V analog setup; see NOTES.md "NFC-V / iClass".
// The cipher, key diversification and elite key derivation follow pm3 (armsrc/optimized_cipher.c,
// optimized_ikeys.c, optimized_elite.c).

#define ICLASS_DIR       "sdmc:/prox3ds/iclass"
#define ICLASS_KEYS      ICLASS_DIR "/keys.txt"   // "<16 hex> [s|e|d] [label]": standard / elite master key, diversified
#define ICLASS_KNOWN     ICLASS_DIR "/known.txt"  // "<CSN> <Kd div> <Kc div>" (0 = unknown), written after a dump
#define ICLASS_TRANSPORT ICLASS_DIR "/iclass_decryptionkey.bin" // pm3's 16-byte credential (block 7-9) key
#define ICLASS_DICT_DEFAULT ICLASS_DIR "/iclass_default_keys.dic" // pm3's dictionaries, downloaded (iclassdict.c)
#define ICLASS_DICT_ELITE   ICLASS_DIR "/iclass_elite_keys.dic"
#define ICLASS_DICT_URL     PM3_CLIENT_URL

#define ICLASS_BLOCKS 256 // 2k cards use 32, 16k / 32k up to 256 per book / page

enum { IC_ACTALL = 0x0A, IC_IDENTIFY = 0x0C, IC_SELECT = 0x81, IC_READCHECK_KD = 0x88, IC_READCHECK_KC = 0x18,
	IC_CHECK = 0x05, IC_READ = 0x0C };

// The ISO15693-style CRC iClass uses (poly 1021 reflected, init E012, no final xor); out = LSB first.
void icCrc(const u8 *data, u32 len, u8 out[2]);
bool icCrcOk(const u8 *frame, u32 len); // the last 2 bytes are the CRC of the rest

// MACs with a diversified key: the reader's over CC (8) + NR (4), the card's (the same + 32 zero bits).
void icReaderMac(const u8 divKey[8], const u8 ccnr[12], u8 mac[4]);
void icTagMac(const u8 divKey[8], const u8 ccnr[12], u8 mac[4]);

enum { IC_KEY_STD, IC_KEY_ELITE, IC_KEY_DIV }; // how a key turns into the card's diversified key
void icDivKey(const u8 csn[8], const u8 key[8], int kind, u8 div[8]);

// Block 1 (configuration) decoded the pm3 way.
typedef struct {
	u8 appLimit;     // last block of AA1
	u8 kbits;        // 2 / 16 / 32
	u8 areas, books, pages;
	u8 lastBlock;    // last block on the first page (app2 limit)
	bool personalization, nonSecure, keysLocked, readAccess, keyAccessSplit;
	u8 pagemap;      // 0 auth disabled, 1 non-secure, 2 secured keys locked, 3 secured
	const char *coding;
} IcConfig;
void icConfig(const u8 cfg[8], IcConfig *out);

// The credential in blocks 6-9 (legacy cards, AIA all FF): block 6 byte 7 bits 0-1 say how blocks 7-9
// are encrypted (0 none, 2 DES, 3 2K3DES with the transport key). Wiegand formats like pm3's.
typedef struct {
	bool present;       // block 7 holds a credential
	bool encrypted;     // and it needs the transport key we don't have
	u8 bits;            // Wiegand length (sentinel stripped), 0 = not found
	u64 value;          // the Wiegand bits, right-aligned
	char format[24];    // e.g. "C1k35s"; "" = no known format matched
	char name[40];      // e.g. "HID Corporate 1000 35-bit"
	u32 fc, cn;
	bool hasFc, parityOk;
} IcCredential;
// blocks = blocks 0.. (at least 10); key = the transport key (16 bytes) or NULL.
void icCredential(const u8 *blocks, u32 nblocks, const u8 *key, IcCredential *out);
// Wiegand bits -> the best format (parity ok first), like pm3 `wiegand decode`; false = none.
bool icWiegand(u64 v, u8 bits, IcCredential *out);

// pm3's dictionaries (iclasskeys.c, tools/gen_iclasskeys.py): defaults (tried standard and elite) and
// the elite list (tried elite).
typedef struct {
	u8 key[8];
	const char *label;
} IcDictKey;
extern const IcDictKey icDefaultKeys[];
extern const int icNumDefaultKeys;
extern const u8 icEliteKeys[][8];
extern const int icNumEliteKeys;

// The dictionaries the key search walks (iclassdict.c): each downloaded one that has keys, else the
// built-in copy.
typedef struct {
	const IcDictKey *def;
	int ndef;
	const u8 (*elite)[8];
	int nelite;
	bool dlDef, dlElite; // downloaded
	bool transport;      // ICLASS_TRANSPORT is there
} IcDicts;
const IcDicts *icDicts(void); // loaded on first use
void icDictReload(void);      // after a download
// Fetches both of pm3's dictionaries and its transport key (ICLASS_TRANSPORT) from ICLASS_DICT_URL; a
// file is replaced only if the new one has keys / is 16 bytes. Over Wi-Fi, not in a card job. 1 = done, 0 = failed (icDictWhy).
int icDictDownload(void);
const char *icDictWhy(void);

// --- reader (iclassrw.c), in a card job (hwLock held) ---

typedef struct {
	u8 csn[8];
	u8 blocks[ICLASS_BLOCKS][8];
	bool have[ICLASS_BLOCKS]; // read (blocks 3 / 4: the diversified key that opened the card)
	int nblocks;              // the first page's blocks (lastBlock + 1)
	IcConfig cfg;
	bool kdKnown, kcKnown;
	u8 kd[8], kc[8];            // diversified
	u8 kdMaster[8], kcMaster[8]; // the dictionary / file key, when one was found
	int kdKind, kcKind;          // IC_KEY_*
	char kdLabel[48], kcLabel[48];
	u32 keysTried;
	IcCredential cred;
	bool transportKey; // the transport key file was there
} IcCard;
extern IcCard icCard; // the last card read

bool icStart(void);              // monitor, stalled V poll, the V coder / analog registers
void icStop(void);
int icXfer(const u8 *tx, u32 len, u8 *rx, u32 max); // -> answer length, 0 = none, -1 = monitor error
bool icSelect(u8 csn[8]);        // ACTALL, IDENTIFY, SELECT
bool icWait(u8 csn[8], u32 timeoutMs); // icStart, then select until a card answers (mfCancel, timeout; 0 = none)
bool icRead(u8 block, u8 out[8]);
int icAuth(const u8 div[8], bool kc); // READCHECK block 2 + CHECK: 1 ok, 0 wrong key, -1 lost / error
// The whole read: header, keys (remembered for the CSN, ICLASS_KEYS, the dictionaries; or only `key`
// if given), then every block the keys open, the credential. Card on the reader (icWait first).
// Returns 1 ok (maybe without keys), 0 lost, -1 chip error.
int icReadCard(IcCard *c, const u8 *key, int kind);
bool icSaveDump(const IcCard *c, char *path, u32 max); // pm3 .bin (blocks 0..), path out
