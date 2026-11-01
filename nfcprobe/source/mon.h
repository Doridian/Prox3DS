#pragma once
#include <3ds.h>

// Chip-side debug monitor (chip/memrw.c, vendor command 2F 2C), see tools/chipmon.py.

enum { MON_READ8, MON_WRITE8, MON_CALL, MON_READ32, MON_WRITE32, MON_CAPTURE, MON_TXRAW, MON_AUTH, MON_TXSCHED, MON_NESTED,
	MON_SNAP, MON_CHKKEYS };

#define MON_CHUNK      0xF0
#define MON_NO_ANSWER  (-1)
#define MON_STATUS(s)  (-0x100 - (s)) // monitor answered with an error status

// One captured RX frame (memrw struct frame).
typedef struct {
	u32 regs[5]; // TX/RX status, 0x5C588, 0x5C58C, 0x5C598, 0x5C5A0
	u8 len;
	u8 data[36];
} MonFrame;

bool monLoad(void); // power cycle, download memrw, CORE_RESET / GET_PATCH_VERSION / CORE_INIT
// One request; returns the answer payload length or MON_NO_ANSWER / MON_STATUS(s).
int monDo(u8 op, u32 addr, const void *data, u32 len, u8 *out, u32 outMax);
bool monRead(u32 addr, void *buf, u32 len);
bool monWrite32(u32 addr, u32 value);
bool monCapture(bool on);                 // also resets the frames() position
int monFrames(MonFrame *out, int max);    // new frames since the last call, -1 on error
bool monTxraw(const u8 *data, u32 len, u8 code, u8 r570, u8 r574, u8 r55c);
// A register store during a TX (OP_TXSCHED): `delay` timer ticks (1 MHz) after the last FIFO write.
typedef struct {
	u16 delay;
	u32 reg, val;
} MonStore;
#define MON_MAX_STORES 8
// Bit-mode TX (r570 0, r574 1, r55c 0x88) with timed stores; waits for the TX to end.
bool monTxsched(const u8 *data, u32 len, u8 code, const MonStore *st, u32 n);
// Mifare Classic first auth on the chip (OP_AUTH). Returns 1 (nt answered with {nr}{ar}),
// 0 (no nt), -1 (monitor error).
int monAuth(const u8 key[6], u32 uid, u32 nr, const u8 *frame, u32 flen, u8 code, u32 nrarTx,
	u32 *nt, u32 *odd, u32 *even);
// On-chip nested auth (OP_NESTED): auth1 with the known key, then the nested AUTH command (nestedCmd,
// 4 plaintext bytes) at fixed timing. Returns 1 with nt0 set (read the encrypted nested nonce from
// the ring), 0 if auth1 got no nt, -1 on a monitor error.
// On-chip key check (OP_CHKKEYS, chip/memrw.c: arg layout there): out = key index that worked (0xFF =
// none), keys tried, keys the card didn't select for. 0 = ok, -1 = monitor error.
int monChkKeys(const u8 *arg, u32 len, u32 nrarTx, u8 out[3]);
int monNested(const u8 key[6], u32 uid, u32 nr, const u8 *frame, u32 flen, u8 code,
	const u8 nestedCmd[4], u32 nrarTx, u32 *nt0);
