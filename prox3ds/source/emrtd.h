#pragma once
#include <3ds.h>

#include "eid.h"

// eMRTD (ICAO 9303 passports and ID cards), read only: access with PACE (MRZ or CAN) or BAC, then the LDS1
// application's files (EF.COM, EF.SOD, every DG the chip lets us have), DG1 (the MRZ) in fields, and passive
// authentication: the DG hashes in EF.SOD, its signed attributes and the document signer's signature (ECDSA
// on any prime curve the certificate gives, RSA PKCS#1 v1.5 / PSS). The document signer's own certificate
// chain (the country's CSCA) is not checked. pm3 `hf emrtd dump` does the same reading.

#define MRTD_FILES 18 // [0] EF.COM, [1..16] DG1..DG16, [17] EF.SOD
#define MRTD_COM 0
#define MRTD_SOD 17
#define MRTD_MAX_FILE 0x10000

typedef struct {
	u8 *data; // malloc'd, NULL = not read
	u32 len;
	u16 sw;   // the chip's answer when refused / missing (6982: needs EAC, 6A82: not there); 0 = not asked
} MrtdFile;

enum { PA_NONE, PA_OK, PA_BAD, PA_UNSUPPORTED };

typedef struct {
	char access[24]; // "PACE (MRZ)", "PACE (CAN)", "BAC"
	MrtdFile f[MRTD_FILES];
	// DG1
	char mrz[96];    // the lines, joined
	int mrzLines;    // 3 (TD1), 2 (TD2 / TD3), 0 = no DG1
	char docType[3], issuer[4], nationality[4], number[16], birth[7], expiry[7], sex;
	char surname[48], given[48];
	// passive authentication
	u8 hashLen;      // the LDS hashes' length (20 / 28 / 32 / 48 / 64), 0 = no EF.SOD parsed
	u32 listed, ok, bad; // DG bits (1 << n): in EF.SOD, read and matching, read and not matching
	int attrs;       // PA_*: the signed attributes' message digest over the LDS security object
	int sig;         // PA_*: the document signer's signature over the signed attributes
	char sigAlg[24]; // "ECDSA brainpoolP256r1", "RSA-PSS 2048"
	char dsSubject[64], dsIssuer[64];
	char dsFrom[11], dsTo[11]; // YYYY-MM-DD
	char paWhy[64];  // what could not be checked
	u32 photoOff, photoLen; // the face image in DG2 (JPEG / JPEG 2000), len 0 = none
	bool photoJp2;
} MrtdDoc;

const char *mrtdWhy(void);
// In a job, the card active (eidRead done on it: e). secret: eidMrzSecret's 20 bytes (how = EID_MRZ) or the
// CAN's digits (EID_CAN). PACE when the chip has it, else BAC (MRZ only). 1 = read (some files may be
// refused), 2 = wrong MRZ / CAN, 0 = failed (mrtdWhy), -1 = monitor error. d is freed first.
int mrtdRead(const EidCard *e, u8 how, const u8 *secret, u32 len, MrtdDoc *d);
void mrtdFree(MrtdDoc *d);
void mrtdVerify(MrtdDoc *d); // passive authentication again (mrtdRead does it)
void mrtdParseDg1(MrtdDoc *d);
// SC_DIR/emrtd-<number>[-N]/: EF_COM.bin, EF_SOD.bin, EF_DGn.bin as pm3 names them, plus EF_DG2.jp2 / .jpg.
bool mrtdSave(const MrtdDoc *d, char *path, u32 max);
const char *mrtdDgName(int dg); // "MRZ", "face", "fingerprints", ...
