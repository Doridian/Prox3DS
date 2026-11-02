#pragma once
#include <3ds.h>

// ISO 7816-4 APDUs over ISO-DEP (isodep.h), for any ISO14443-4 smart card: 61xx answers fetched with GET
// RESPONSE (or the applet's own command, scMoreIns), 6Cxx resent with the Le the card asks for; BER-TLV;
// the ATS in words.

#define SC_MAX_ANS 8192 // the longest answer collected (YubiKey OATH: 64 accounts in one CALCULATE ALL)

const char *scWhy(void);
// S(DESELECT), reselect, RATS (isoDepActivate). The ATS (TL first) into ats. 1 ok, 0 no answer / not
// ISO14443-4 (scWhy), -1 monitor error.
int scActivate(u8 *ats, u32 max);
extern u8 scMoreIns; // what fetches the rest of a 61xx answer: C0 (GET RESPONSE); YubiKey OATH: A5
// One command APDU, whole (CLA INS P1 P2 [Lc data] [Le]); the answer's data into out (cut at max), the
// status word into *sw. Data length, -1 = no answer / lost card (scWhy), -2 = monitor error.
int scApdu(const u8 *apdu, u32 len, u8 *out, u32 max, u16 *sw);
// The same, built: Lc from lc (short, up to 255 bytes; 0 = none), Le 00 when le.
int scCmd(u8 cla, u8 ins, u8 p1, u8 p2, const u8 *data, u32 lc, bool le, u8 *out, u32 max, u16 *sw);
int scSelect(const u8 *aid, u32 len, u8 *out, u32 max, u16 *sw); // SELECT by DF name, first or only
const char *scSwName(u16 sw); // "ok", "file not found", ...; "error" when unknown

typedef struct {
	u32 tag; // as on the card, 1-3 bytes: 4F, 9F7F, ...
	bool constructed;
	const u8 *v;
	u32 len;
} Tlv;
// The TLV at *p (before end), *p moved past it; 00 / FF padding in front is skipped. false = end / broken.
bool tlvNext(const u8 **p, const u8 *end, Tlv *t);
// The first TLV with tag, depth first through the constructed ones.
bool tlvFind(const u8 *p, u32 len, u32 tag, Tlv *t);

// The ATS in words, a line each (\n): frame size, FWT / SFGT, bit rates, CID / NAD, historical bytes.
void scAtsDesc(const u8 *ats, u32 len, char *out, u32 max);
void scHex(char *out, const u8 *p, u32 n); // upper case, no separators
// Hex digits (spaces ignored) -> bytes; length, -1 = not hex / too long.
int scUnhex(const char *s, u8 *out, u32 max);
