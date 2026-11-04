#pragma once
#include <3ds.h>

// NFC Forum NDEF: records (NDEF 1.0), the well-known URI / Text / Smart Poster types, and the Type 2 tag
// TLVs around a message (NFC Forum T2T: 03 NDEF, FE terminator, 00 null, 01 / 02 lock / memory control,
// FD proprietary). Plain bytes in and out: the card code reads and writes them.

typedef struct {
	u8 tnf;            // 1 well-known, 2 MIME, 3 absolute URI, 4 external, 0 empty, 5 unknown, 6 unchanged
	bool mb, me, chunk;
	const u8 *type, *id, *payload; // into the message
	u32 typeLen, idLen, payloadLen;
} NdefRec;

#define NDEF_MAX_RECS 16

// T2T: the NDEF TLV in user memory (from page 4). 1 = found (*off, *len: the message), 0 = none (an
// empty message counts: len 0), -1 = broken TLVs.
int ndefFindTlv(const u8 *mem, u32 n, u32 *off, u32 *len);
// Records of a message; their number, -1 = malformed.
int ndefParse(const u8 *msg, u32 len, NdefRec *recs, int max);
// One line for a record: "URI https://...", "Text (en) ...", "MIME text/vcard, 120 bytes", ...
void ndefDescribe(const NdefRec *r, char *out, u32 max);

// Builders: one record (MB ME, SR when the payload is under 256 bytes) into out; their length, 0 = doesn't fit.
u32 ndefUri(const char *uri, u8 *out, u32 max);   // with the URI prefix code (0x04 https://, ...)
u32 ndefText(const char *lang, const char *text, u8 *out, u32 max); // UTF-8
// The T2T bytes for a message: 03 len (or FF len16) msg FE. Their length, 0 = doesn't fit.
u32 ndefTlv(const u8 *msg, u32 len, u8 *out, u32 max);
