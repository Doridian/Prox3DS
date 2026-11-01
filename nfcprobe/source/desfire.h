#pragma once
#include <3ds.h>

#include "dfcrypto.h"
#include "mfc.h"

// MIFARE DESFire, the C version of pm3's hf mfdes info + lsapp (+ chk): native commands over ISO-DEP
// (isodep.h), EV1 secure messaging (ISO / AES authentication, plain / MAC / full) once a key is known.

#define DF_MAX_APPS  32
#define DF_MAX_FILES 32
#define DF_MAX_DATA  256
#define DF_DIR       MF_DIR "/desfire"
#define DF_KEYS      DF_DIR "/keys.txt" // one hex key per line (8 / 16 / 24 bytes), '#' comments
#define DF_ST_MAC    0xFE               // our status: the answer's MAC / CRC did not check

// File comm modes (file settings byte 1), and DF_ENC: encrypted without our CRC (ChangeKey builds its own)
enum { DF_PLAIN = 0, DF_MACED = 1, DF_FULL = 3, DF_ENC = 4 };

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
	int dictKeys;
	bool hasSig;
	u8 sig[56];
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
// EV1 authentication (1A, AES: AA) of key k of the selected application (or the PICC). 1 = ok, 0 =
// refused (*st), -1 = no answer / monitor error (dfWhy).
int dfAuth(u8 k, const DfKey *key, u8 *st);
// ChangeKey (C4) of key k, authenticated: with the key being changed (old unused) or with the change key
// (old = k's current key). piccType: on the PICC, the new master key's type goes into the key number.
// AES keys get version ver. 1 = ok, 0 = refused (*st), -1 = no answer / monitor error.
int dfChangeKey(u8 k, const DfKey *key, u8 ver, const DfKey *old, bool picc, u8 *st);
void dfKeyHex(const DfKey *k, char *out); // hex, 16 digits for a DES key
const char *dfKeyName(const DfKey *k);    // "DES" / "2K3DES" / "3K3DES" / "AES"

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
