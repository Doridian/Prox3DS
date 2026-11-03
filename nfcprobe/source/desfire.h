#pragma once
#include <3ds.h>

#include "dfcrypto.h"
#include "mfc.h"

// MIFARE DESFire, the C version of pm3's hf mfdes info + lsapp (+ chk): native commands over ISO-DEP
// (isodep.h), EV1 or EV2 secure messaging (plain / MAC / full) once a key is known.

#define DF_MAX_APPS  32
#define DF_MAX_FILES 32
#define DF_MAX_DATA  256
#define DF_DIR       MF_DIR "/desfire"
#define DF_KEYS      DF_DIR "/keys.txt" // one hex key per line (8 / 16 / 24 bytes), '#' comments
#define DF_PM3_KEYS  DF_DIR "/mfdes_default_keys.dic" // pm3's dictionary, downloaded (pm3dict.h)
#define DF_ST_MAC    0xFE               // our status: the answer's MAC / CRC did not check

// File comm modes (file settings byte 1), and DF_ENC: encrypted without our CRC (ChangeKey builds its own);
// DF_FULL80: full with 80 after EV1's CRC, for variable-length data (SetConfiguration's ATS, pm3).
enum { DF_PLAIN = 0, DF_MACED = 1, DF_FULL = 3, DF_ENC = 4, DF_FULL80 = 5 };

typedef struct {
	bool known;
	u8 type;    // DF_2K3DES (a DES key is one with equal halves), DF_3K3DES, DF_AES
	u8 key[24];
} DfKey;

typedef struct {
	u8 fid;
	u8 st;      // GetFileSettings status (00 = ok, 9D = needs auth, ...)
	u8 len;
	u8 set[32]; // the settings, without the status
	// Free read access (key E): the contents (std / backup: up to DF_MAX_DATA bytes, value: 4 bytes,
	// records: all of them, cut at DF_MAX_DATA), in DfInfo.pool.
	bool hasData;
	u8 dataSt, dataKey; // dataKey: the key it was read with, 0xE = free
	u16 dataOff, dataLen;
} DfFile;

typedef struct {
	u32 aid;
	bool hasIso;
	u16 isoFid;
	u8 nameLen, name[16]; // ISO DF name
	u8 selSt, keySt, fileSt; // statuses: SelectApplication, GetKeySettings, GetFileIDs
	u8 keySet, maxKeys;   // GetKeySettings: settings, key count (low nibble) + key type (bits 6-7)
	u8 nKeyVer, keyVer[14]; // GetKeyVersion for keys 0..nKeyVer-1 (where it answered)
	DfKey keys[14];         // found by the dictionary check
	int nfiles;
	DfFile files[DF_MAX_FILES];
} DfApp;

typedef struct {
	u8 atsLen, ats[32];
	u8 verLen, ver[28]; // GetVersion, all 3 parts: hardware (7), software (7), UID, batch, week, year
	bool hasFree;
	u32 freeMem;
	u8 keySt, keySet, maxKeys, keyVerSt, keyVer; // PICC master key
	DfKey piccKey;
	bool keyed; // read with the dictionary
	bool ev2;   // AES keys used EV2 authentication / secure messaging
	int dictKeys;
	bool hasSig;
	u8 sig[56];
	const char *sigKey; // the NXP key the signature verifies with (nxpsig.h), NULL = none
	bool randomUid;     // random ID on (anticollision UID 08 xx xx xx); the real one only after
	bool hasRealUid;    // authentication: GetCardUID (51) with the PICC master key
	u8 realUid[7];
	u8 appSt;  // GetApplicationIDs status
	int napps; // listed (apps[] holds the first DF_MAX_APPS)
	DfApp apps[DF_MAX_APPS];
	u32 poolUsed;
	u8 pool[8192];
} DfInfo;

const char *dfWhy(void);
// In a job, card active: ISO-DEP, GetVersion, then everything else a DESFire tells without a key. With
// keys: the dictionary (built in + DF_KEYS) tried on the PICC master key and on every application key,
// then what they open: application lists, key settings, file lists and settings, file contents.
// 1 = read (refused parts carry their status), 0 = no ISO-DEP / not a DESFire (dfWhy, ATS may be set),
// -1 = monitor error.
int dfReadInfo(DfInfo *d, bool keys);

// Lower level, card active and ISO-DEP up (isoDepActivate). One native command c[0] + c[1..len) in comm
// mode comm (secure messaging once authenticated; hdr = the bytes after the command byte that stay plain
// in full mode). The answer's data into out, the last status in *st. Data length, -1 = no answer
// (dfWhy), -2 = monitor error.
int dfCmd(const u8 *c, u32 len, u32 hdr, u8 comm, u8 *out, u32 max, u8 *st);
// Authentication of key k of the selected application (or the PICC): EV1 (1A, AES: AA), or with ev2 an
// AES key AuthenticateEV2First (71) and EV2 secure messaging. 1 = ok, 0 = refused (*st), -1 = no answer /
// monitor error (dfWhy).
int dfAuth(u8 k, const DfKey *key, bool ev2, u8 *st);
// AuthenticateEV2NonFirst (77): another AES key in the running EV2 session (TI and counter go on).
int dfAuthEv2NonFirst(u8 k, const DfKey *key, u8 *st);
// ChangeKey (C4) of key k, authenticated: with the key being changed (old unused) or with the change key
// (old = k's current key). piccType: on the PICC, the new master key's type goes into the key number.
// AES keys get version ver. 1 = ok, 0 = refused (*st), -1 = no answer / monitor error.
int dfChangeKey(u8 k, const DfKey *key, u8 ver, const DfKey *old, bool picc, u8 *st);
// ISO 7816 over ISO-DEP, plain: one APDU, its data into out and its status word in *sw. Data length, -1
// = no answer (dfWhy), -2 = monitor error.
int dfApdu(const u8 *apdu, u32 len, u8 *out, u32 max, u16 *sw);
// An application's EFs the ISO 7816 way: native GetISOFileIDs, ISO SELECT of the application (by DF name,
// else by its ISO FID), then per EF SELECT and READ BINARY (up to DF_MAX_DATA), or READ RECORD 1.. for
// record files. Results in efs (data in d->pool after poolUsed, which stays). Count, -1 = monitor error,
// 0 with dfWhy = failed / none.
typedef struct {
	u16 fid, sw;   // sw of the read (or of the SELECT when that failed)
	bool records;
	u16 records_n; // records read
	u16 dataOff, dataLen;
} DfIsoEf;
int dfIsoRead(DfInfo *d, const DfApp *a, DfIsoEf *efs, int max);
void dfKeyHex(const DfKey *k, char *out); // hex, 16 digits for a DES key
bool dfUsesEv2(const DfInfo *d);          // EV2 or later (not Light): AES keys go over EV2
bool dfRandomUid(const Card *c);          // a random ID: 4 bytes, 08 first (not a card to match by UID)
// Appends a key to DF_KEYS unless the dictionary has it already (entered and newly set keys).
bool dfRememberKey(const DfKey *k);

// One operation, in a job with the card active: ISO-DEP up, select aid (0 = the PICC), authenticate
// key k with key (NULL: no authentication), then the command c in comm mode (hdr: dfCmd), and
// CommitTransaction after it with commit. 1 = done, 0 = refused / lost card (dfWhy), -1 = monitor error.
// flags: DF_COMMIT = CommitTransaction after the command; DF_READER_ID = CommitReaderID (16 bytes,
// "nfcprobe") before that, for a transaction MAC file that wants one; DF_TMAC = commit with option 01:
// the TMC and TMV come back into dfTmac (12 bytes, dfTmacLen).
enum { DF_COMMIT = 1, DF_READER_ID = 2, DF_TMAC = 4 };
extern u8 dfTmac[12], dfTmacLen;
int dfOp(const DfInfo *d, u32 aid, u8 k, const DfKey *key, const u8 *c, u32 len, u32 hdr, u8 comm, u8 flags);
// Just the authentication (checks an entered key).
int dfOpAuth(const DfInfo *d, u32 aid, u8 k, const DfKey *key);
// ChangeKey the same way: authenticated with key authK (authKey), key k becomes key (AES: version ver);
// old = k's current key when authK is another key. picc: the PICC master key (its type may change).
int dfOpChangeKey(const DfInfo *d, u32 aid, u8 authK, const DfKey *authKey, u8 k, const DfKey *key, u8 ver,
	const DfKey *old, bool picc);
const char *dfKeyName(const DfKey *k);    // "DES" / "2K3DES" / "3K3DES" / "AES"

const char *dfAidName(u32 aid, const char **vendor); // pm3's aid_desfire.json (aidnames.c), NULL = unknown
const char *dfVersionName(const DfInfo *d); // "DESFire EV2" etc., from the hardware version
u32 dfStorage(u8 code);                     // GetVersion storage size byte -> bytes (lower bound)
const char *dfStatusName(u8 st);
const char *dfKeyType(u8 maxKeys);
// A file in words: type, comm mode, size / value limits / records; and its access keys (empty if the
// settings did not read).
void dfFileDesc(const DfFile *f, char *out, u32 max);
void dfFileKeys(const DfFile *f, char *out, u32 max);
bool dfFreeRead(const DfFile *f); // read or read/write access is free (key E)
bool dfSaveInfo(const DfInfo *d, char *path, u32 pathMax); // DF_DIR/<UID>.txt, never overwrites
// Back from such a file (for emulation): what it shows; parts it shows refused carry that status. false = not
// an info file.
bool dfLoadInfo(DfInfo *d, const char *path);
