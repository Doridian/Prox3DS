#pragma once
#include <3ds.h>

#include "dfcrypto.h"
#include "mfc.h"

// ID documents with a chip: ICAO 9303 passports and TR-03110 ID cards (the German eID card, "nPA"). What
// the chip tells anyone (EF.CardAccess: its PACE / chip / terminal authentication options; EF.DIR, EF.ATR/
// INFO), the eID PIN's state (MSE:Set AT, no try used), and PACE with a password (the CAN, printed on the
// card) followed by secure messaging. ECDH generic mapping only, AES-128 / 192 / 256, brainpoolP256r1 and
// NIST P-256. The German ID card gives no personal data (not even the MRZ or the photo) without terminal
// authentication, which takes a BSI-issued certificate: docs/NOTES.md "German eID card".

#define EID_MAX_INFO 12
#define EID_MAX_APPS 6

enum { EI_PACE = 1, EI_PACE_DP, EI_CA, EI_CA_DP, EI_TA, EI_RI, EI_CARDINFO, EI_EIDSEC, EI_OTHER };

typedef struct {
	u8 kind;            // EI_*
	bool privileged;    // from PrivilegedTerminalInfo (only for authenticated terminals)
	u8 oidLen, oid[16]; // as on the card (the DER contents)
	int version, param, keyId; // -1 = not given; param: standardized domain parameters
	char url[48];       // EI_CARDINFO
} EidInfo;

typedef struct {
	u8 atsLen, ats[32];
	u16 accessLen;      // 0 = no EF.CardAccess (a BAC-only passport)
	u8 access[512];
	int ninfo;
	EidInfo info[EID_MAX_INFO];
	int napps;          // EF.DIR
	struct {
		u8 aidLen, aid[16];
		char label[24]; // 50, "" = none
	} app[EID_MAX_APPS];
	u32 extIn, extOut;  // extended length from EF.ATR/INFO, 0 = not given
	u16 pinSw;          // MSE:Set AT with the PIN, 0 = not asked (no PACE)
	int pace;           // the PACE info used (info[]), -1 = none we can do
} EidCard;

typedef struct {
	DfCipher enc, mac;
	u8 ssc[16];
} EidSm;

const char *eidWhy(void);
// In a job, card active: ISO-DEP, then everything above. 1 = done, 0 = no ISO-DEP (eidWhy), -1 = monitor error.
int eidRead(EidCard *e);
// EF.CardAccess's contents into e (access, info, pace); false: not SecurityInfos.
bool eidParseAccess(EidCard *e, const u8 *p, u32 len);
// PACE with a password (EID_CAN: the digits), ISO-DEP activated again first. 1 = done (the card's token
// checked), sm set up; 2 = wrong password; 0 = failed (eidWhy); -1 = monitor error.
enum { EID_MRZ = 1, EID_CAN = 2, EID_PIN = 3, EID_PUK = 4 };
int eidPace(const EidCard *e, u8 ref, const char *pwd, EidSm *sm);
// One command under secure messaging (CLA's SM bits set here); le: Le 00 wanted. The plain answer's data
// length, -1 = no answer / bad MAC (eidWhy), -2 = monitor error.
int eidSmCmd(EidSm *sm, u8 ins, u8 p1, u8 p2, const u8 *data, u32 lc, bool le, u8 *out, u32 max, u16 *sw);

// In words, for the screen
const char *eidAppName(const u8 *aid, u32 len); // "eID", "ePass", ...; NULL = unknown
const char *eidParamName(int param);            // "brainpoolP256r1"; NULL = unknown
void eidInfoText(const EidInfo *i, char *out, u32 max);
const char *eidPinText(u16 sw, u32 *col); // NULL = no PIN state to show; col: a COL_*
bool eidIsGermanId(const EidCard *e);  // the CardInfoLocator names the nPA
