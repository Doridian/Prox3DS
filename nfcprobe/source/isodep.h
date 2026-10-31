#pragma once
#include <3ds.h>

// ISO14443-4 (ISO-DEP) over the raw framer (mfc.h data mode: HW parity and CRC). Our own RATS asks for
// FSD 32, so every card frame fits a capture ring slot (MonFrame.data, 36 bytes); longer answers come
// chained (R(ACK) per block). S(WTX) is answered. No CID, no NAD, no TX chaining: a command's INF fits one
// frame (ISO_DEP_MAX_INF).

#define ISO_DEP_MAX_INF 29 // FSD 32 - PCB - CRC

const char *isoDepWhy(void);
// S(DESELECT) (the ROM activates layer 4 itself when it maps ISO-DEP), reselect, RATS. The ATS (TL
// first) goes to ats. 1 = ok, 0 = no answer, -1 = monitor error.
int isoDepActivate(u8 *ats, u32 atsMax);
// One command (INF only) and its answer, chained blocks joined. Answer length (> 0), 0 = no / broken
// answer (isoDepWhy), -1 = monitor error.
int isoDepTx(const u8 *inf, u32 len, u8 *out, u32 max);
