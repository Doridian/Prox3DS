#pragma once
#include <3ds.h>

#include "scard.h"

// FIDO security keys over NFC (U2F / CTAP2), read only: the applet's SELECT answer (U2F_V2), CTAP2
// authenticatorGetInfo (versions, extensions, AAGUID, options, limits, algorithms) and, when a PIN is set,
// the PIN tries left (clientPIN getPINRetries). Nothing that makes or uses a credential.

#define FIDO_MAX_STR 10
#define FIDO_RAW 1024

typedef struct {
	char name[24];
	bool on;
} FidoOpt;

typedef struct {
	char u2f[16];         // SELECT's answer ("U2F_V2"), "" = none
	bool ctap2;           // getInfo answered
	u16 infoSw;           // getInfo's SW (6D00 on a U2F-only key)
	u8 infoStatus;        // CTAP status byte, 0 = ok
	int nver, next, ntrans;
	char ver[FIDO_MAX_STR][20], ext[FIDO_MAX_STR][24], trans[FIDO_MAX_STR][12];
	bool hasAaguid;
	u8 aaguid[16];
	int nopt;
	FidoOpt opt[16];
	int npin, nalg;
	int pinProto[4], alg[FIDO_MAX_STR]; // COSE algorithm numbers
	// -1 = not given
	int maxMsg, maxCredList, maxCredIdLen, minPin, firmware, remainingRk, pinRetries;
	bool forcePinChange;
	u16 rawLen;           // getInfo's CBOR as is, for the save file
	u8 raw[FIDO_RAW];
} FidoInfo;

const char *fidoWhy(void);
// In a job, card active: ISO-DEP, SELECT, getInfo. 1 = the applet answered, 0 = none / no ISO-DEP
// (fidoWhy), -1 = monitor error.
int fidoRead(FidoInfo *f);
// Decode a getInfo answer (CBOR map, no status byte) into f; false = not a CBOR map.
bool fidoParseInfo(FidoInfo *f, const u8 *p, u32 len);
// SC_DIR/fido-<first AAGUID bytes>.txt (numbered, never overwrites).
bool fidoSave(const FidoInfo *f, char *path, u32 max);

int fidoOpt(const FidoInfo *f, const char *name); // 1 on, 0 off, -1 not listed
const char *fidoModel(const u8 aaguid[16]);       // the key's name by AAGUID, NULL = unknown
const char *fidoAlgName(int cose);                // "ES256", ...; NULL = unknown
void fidoAaguidText(const u8 aaguid[16], char *out); // 8-4-4-4-12, out: 37 chars
