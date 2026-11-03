#pragma once
#include <3ds.h>

// Card emulation: the 3DS as an ISO14443-4A card (NCI listen A, ISO-DEP through the ROM), see NOTES.md
// "Card mode". The ROM does anticollision, RATS / ATS and the ISO-DEP blocks; every APDU comes to us as
// NCI DATA and the answer goes back the same way, well inside the reader's frame waiting time. The
// reader has to sit under the 3DS (the antenna is weak as a card).

// An APDU in, the answer (with its status word) out; its length.
typedef u32 (*EmuApdu)(const u8 *cmd, u32 len, u8 *resp, u32 max);

#define EMU_LOG_N 6
typedef struct {
	u8 uid[4];
	bool field, active;    // a reader field / an ISO-DEP session right now
	u32 fields, sessions, apdus;
	char log[EMU_LOG_N][48]; // the last APDUs, "> 00A40400 07 .. < 9000", newest last
	u32 nlog;
} EmuState;
extern EmuState emu; // the worker writes it, the UI only shows it

// In a job: listen as a card with a random UID (08 xx xx xx) until mfCancel. false = the chip failed.
bool emuRun(EmuApdu fn);

// NFC Forum Type 4 tag (T4T 2.0): the NDEF application, CC file E103 and NDEF file E104, readable
// and writable (UPDATE BINARY), up to EMU_NDEF_MAX bytes of message.
#define EMU_NDEF_MAX 1022
void emuNdefSet(const u8 *msg, u32 len);
const u8 *emuNdefGet(u32 *len); // the message now (a reader may have written another)
u32 emuNdefWrites(void);       // UPDATE BINARY commands since emuNdefSet
u32 emuNdefApdu(const u8 *cmd, u32 len, u8 *resp, u32 max);
