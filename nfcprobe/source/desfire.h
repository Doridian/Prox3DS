#pragma once
#include <3ds.h>

#include "mfc.h"

// MIFARE DESFire without keys, the C version of pm3's hf mfdes info + lsapp --no-auth: native commands
// over ISO-DEP (isodep.h). Everything here reads; nothing authenticates or writes.

#define DF_MAX_APPS  32
#define DF_MAX_FILES 32
#define DF_MAX_DATA  256
#define DF_DIR       MF_DIR "/desfire"

typedef struct {
	u8 fid;
	u8 st;      // GetFileSettings status (00 = ok, 9D = needs auth, ...)
	u8 len;
	u8 set[32]; // the settings, without the status
	// Free read access (key E): the contents (std / backup: up to DF_MAX_DATA bytes, value: 4 bytes,
	// records: all of them, cut at DF_MAX_DATA), in DfInfo.pool.
	bool hasData;
	u8 dataSt;
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
	int nfiles;
	DfFile files[DF_MAX_FILES];
} DfApp;

typedef struct {
	u8 atsLen, ats[32];
	u8 verLen, ver[28]; // GetVersion, all 3 parts: hardware (7), software (7), UID, batch, week, year
	bool hasFree;
	u32 freeMem;
	u8 keySt, keySet, maxKeys, keyVerSt, keyVer; // PICC master key
	bool hasSig;
	u8 sig[56];
	u8 appSt;  // GetApplicationIDs status
	int napps; // listed (apps[] holds the first DF_MAX_APPS)
	DfApp apps[DF_MAX_APPS];
	u32 poolUsed;
	u8 pool[8192];
} DfInfo;

const char *dfWhy(void);
// In a job, card active: ISO-DEP, GetVersion, then everything else a DESFire tells without a key.
// 1 = read (refused parts carry their status), 0 = no ISO-DEP / not a DESFire (dfWhy, ATS may be set),
// -1 = monitor error.
int dfReadInfo(DfInfo *d);

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
