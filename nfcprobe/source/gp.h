#pragma once
#include <3ds.h>

#include "mfc.h"

// GlobalPlatform card management over ISO 7816 (iso7816.h), the C version of javacard/gpload.py: the
// issuer security domain's card data, SCP03 (AES-128, C-MAC), GET STATUS, DELETE, and installing CAP
// files (zip) from the SD card.
//
// The card counts failed EXTERNAL AUTHENTICATEs and locks itself after a few, so a key is only ever used
// after the card cryptogram from INITIALIZE UPDATE proves it right (gpCheck); a wrong key costs nothing.

#define GP_DIR  MF_DIR "/gp"
#define GP_KEYS GP_DIR "/keys.txt" // one key per line: 32 hex digits (ENC = MAC = DEK) or three; '#' comments
#define GP_CAPS MF_DIR "/cap"      // CAP files to install
#define GP_MAX_ENT 48

typedef struct {
	u8 enc[16], mac[16], dek[16];
} GpKeys;
extern const GpKeys gpDefaultKeys; // 404142..4F, what most JavaCards ship with

enum { GP_ISD, GP_APP, GP_PKG };

typedef struct {
	u8 kind;  // GP_*
	u8 aidLen, aid[16];
	u8 state; // life cycle
	u8 priv;  // first privileges byte (80 = security domain)
	u8 pkgLen, pkg[16]; // an application's load file (C4), a package's version (CE) in pkg[0..1] when pkgLen 0
	u8 nmods;
	u8 modLen[6], mods[6][16]; // a package's applet classes (84)
} GpEntry;

typedef struct {
	u8 isdLen, isd[16];  // the issuer security domain SELECT found
	u8 cplcLen, cplc[45];
	u8 crdLen, crd[128]; // card recognition data (66)
	u8 kinfoLen, kinfo[96]; // key information template (E0)
	bool hasSeq;
	u32 seq;             // sequence counter (C1)
	u8 kvn, scp, scpI;   // from INITIALIZE UPDATE
	u8 divLen, div[10];  // key diversification data
	bool listed;
	int nent;
	GpEntry ent[GP_MAX_ENT];
} GpCard;

typedef struct {
	u8 *lf;                // the load file: C4, its length, the components in load order (no Debug)
	u32 lfLen;
	u8 pkgLen, pkg[16];
	u8 pkgMajor, pkgMinor;
	int napplets;
	u8 appLen[8], apps[8][16];
	char name[64];         // the file's name
} GpCap;

const char *gpWhy(void);

// Card active: ISO-DEP up, SELECT the ISD (GP's, Visa's, else the default application), GET DATA: CPLC,
// card recognition data, key information, sequence counter. 1 = ok (whatever GET DATA refused stays
// empty), 0 = no ISO-DEP / no security domain (gpWhy), -1 = monitor error.
int gpOpen(GpCard *g);
int gpSelect(GpCard *g); // the same with ISO-DEP up already
// INITIALIZE UPDATE with keys (after gpOpen): 1 = the card cryptogram matches, 0 = it doesn't (or the
// card refused / isn't SCP03: gpWhy), -1 = monitor error. Nothing the card counts.
int gpCheck(GpCard *g, const GpKeys *k);
// gpCheck, then EXTERNAL AUTHENTICATE (C-MAC) only when it matched. Same results.
int gpAuth(GpCard *g, const GpKeys *k);
// A command in the authenticated session (C-MAC). Data length, -1 no answer (gpWhy), -2 monitor error.
int gpSend(u8 ins, u8 p1, u8 p2, const u8 *data, u32 len, u8 *out, u32 max, u16 *sw);
// GET STATUS: the ISD, applications / security domains, packages (with their applet classes). 1 / 0 / -1.
int gpList(GpCard *g);
// DELETE an application or a package (related: its applications with it). 1 = deleted, 0 = refused
// (*sw, gpWhy), -1 = monitor error.
int gpDelete(const u8 *aid, u32 len, bool related, u16 *sw);
// INSTALL [for load], LOAD in blocks (progress through prog), INSTALL [for install and make selectable]
// for each applet (instance AID = class AID, no install parameters). 1 / 0 / -1.
int gpInstall(const GpCap *c);
// A CAP file from the SD card: components, package and applet AIDs. false = not a CAP (gpWhy).
bool gpCapLoad(const char *path, GpCap *c);
void gpCapFree(GpCap *c);

// Keys to try, in order: the default, GP_KEYS. Count; fills up to max.
int gpKeyList(GpKeys *out, int max);
bool gpRememberKey(const GpKeys *k); // appends to GP_KEYS unless known

// In words.
const char *gpStateName(u8 kind, u8 state);
void gpCplcDesc(const GpCard *g, char *out, u32 max); // fabricator, IC type, OS, dates, serial
void gpCrdDesc(const GpCard *g, char *out, u32 max);  // GP version, SCP, JavaCard version
void gpAidHex(char *out, const u8 *aid, u32 len);
