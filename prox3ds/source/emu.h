#pragma once
#include <3ds.h>

#include "mfc.h"
#include "mfu.h"

// Card emulation: the 3DS as an ISO14443-A card (NCI listen A through the ROM), see docs/NOTES.md "Card mode".
// The ROM does anticollision, RATS / ATS and the ISO-DEP blocks; every APDU comes to us as NCI DATA and
// the answer goes back the same way, well inside the reader's frame waiting time. Phones read it with a
// tap; a strong reader (pm3) wants the 3DS lying on it. Frames of other protocols (Ultralight READ, ...)
// do reach us, but the ROM never sends our answers to them: those cards need chip code.

// An APDU in, the answer (with its status word) out; its length.
typedef u32 (*EmuApdu)(const u8 *cmd, u32 len, u8 *resp, u32 max);

// What the reader sees in anticollision. atqa[0] is the first byte on the air (04, 44, ...); a SAK
// with bit 0x20 (ISO-DEP) gets RATS / ATS and APDUs, any other SAK is a UID-only card.
typedef struct {
	u8 uid[10];
	u8 uidLen; // 4, 7 or 10
	u8 atqa[2];
	u8 sak;
} EmuId;
void emuUidHex(const EmuId *id, char *out); // out: up to 21 chars

#define EMU_LOG_N 6
typedef struct {
	EmuId id;
	bool field, active;    // a reader field / an ISO-DEP session right now
	u32 fields, sessions, apdus;
	char log[EMU_LOG_N][48]; // the last APDUs, "> 00A40400 07 .. < 9000", newest last (chip: frames)
	u32 nlog;
	// Answered on the chip (emuRunMfu): pages, frames in the active state, pages written, dump pages
	// that differ afterwards
	u32 chipPages, frames, writes, changed;
} EmuState;
extern EmuState emu; // the worker writes it, the UI only shows it

// In a job: listen as a card until mfCancel; id NULL: a random UID (08 xx xx xx), ATQA 0004, SAK 20.
// false = the chip failed.
bool emuRun(const EmuId *id, EmuApdu fn);

// An Ultralight / NTAG from a dump, answered by our chip image (chip/emu.c, the ROM can't: docs/NOTES.md): its
// UID (ATQA 0044, SAK 00), READ, FAST_READ, GET_VERSION, READ_SIG, READ_CNT, PWD_AUTH (the dump's
// password if known, else any; PACK from the dump), WRITE, COMPATIBILITY WRITE, Ultralight C 3DES AUTH (the
// dump's key, mfuUlcDumpKey). No AUTH0 protection. Pages readers wrote end up in *d (emu.changed).
bool emuRunMfu(MfuDump *d);
// MIFARE Classic Mini / 1K / 2K / 4K from a dump, the same way (Crypto1 on the chip, its own image): its
// UID / ATQA / SAK from block 0, AUTH (first and nested) with the keys the dump found, READ (key A reads as
// zeros, key B where the access bits let it), WRITE (not block 0 or trailers into the dump), HALT. Access
// bits otherwise not enforced, no value blocks. Encrypted answers carry their encrypted parity.
int emuMfcBlocks(const MfDump *d); // 20 / 64 / 128 / 256, 0 = can't
bool emuRunMfc(MfDump *d);

// NFC Forum Type 4 tag (T4T 2.0): the NDEF application, CC file E103 and NDEF file E104, readable
// and writable (UPDATE BINARY), up to EMU_NDEF_MAX bytes of message.
#define EMU_NDEF_MAX 1022
void emuNdefSet(const u8 *msg, u32 len);
const u8 *emuNdefGet(u32 *len); // the message now (a reader may have written another)
u32 emuNdefWrites(void);       // UPDATE BINARY commands since emuNdefSet
u32 emuNdefApdu(const u8 *cmd, u32 len, u8 *resp, u32 max);

// APDU log: an ISO-DEP card that answers from EMU_RULES ("<command prefix hex> <response hex>" per line,
// '#' comments, the first matching prefix wins; else 6A82 for a SELECT, 6D00 for anything else) and
// appends every APDU to EMU_APDU_LOG.
#define EMU_DIR      "sdmc:/prox3ds/emu"
#define EMU_RULES    EMU_DIR "/apdu.txt"
#define EMU_APDU_LOG EMU_DIR "/apdu.log"
int emuLogLoad(void); // the rules; their number
u32 emuLogApdu(const u8 *cmd, u32 len, u8 *resp, u32 max);
void emuLogClose(void);
