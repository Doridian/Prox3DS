// ISO14443-4 (ISO-DEP) over the chip monitor, see isodep.h.

#include <stdio.h>
#include <string.h>

#include "isodep.h"
#include "mfc.h"
#include "mon.h"

static char why[64];
static u8 bn; // our block number
static int fwtPolls = 40; // 2 ms polls for an answer: the card's FWT from its ATS (TB1), at least 80 ms

const char *isoDepWhy(void)
{
	return why;
}

#define FAIL(ret, ...) ({ snprintf(why, sizeof(why), __VA_ARGS__); return (ret); })

// One frame out, one block back (CRC checked and cut), polled `polls` times 2 ms apart: the last frame
// with a good CRC (a Mastercard debit card's answers come with stray 1-byte frames, before or after).
// Its length, 0 = none / broken, -1 = monitor.
static int block(const u8 *f, u32 len, u8 *out, u32 max, int polls)
{
	MonFrame a[4];
	u8 crc[2];
	int n = iso14aDataTx(f, len, a, 4, polls), left = polls;
	while (n > 0) {
		for (int i = n; i-- > 0; ) {
			const MonFrame *m = &a[i];
			if (m->len < 3 || m->len < m->regs[4]) continue;
			iso14aCrc(m->data, m->len - 2, crc);
			if (memcmp(crc, m->data + m->len - 2, 2)) continue;
			u32 k = m->len - 2 < max ? m->len - 2 : max;
			memcpy(out, m->data, k);
			return k;
		}
		// only stray frames so far: the answer may still be on its way
		for (n = 0; !n && left > 0; left--) {
			svcSleepThread(2000000);
			if ((n = monFrames(a, 4)) < 0) return -1;
		}
	}
	return n;
}

int isoDepActivate(u8 *ats, u32 atsMax)
{
	u8 desel = 0xC2, rats[2] = { 0xE0, 0x20 }, a[34]; // RATS: FSDI 2 (32 bytes), CID 0
	for (int t = 0; t < 3; t++) {
		// the next times from a new discovery: a card left alone a while after a session (a Mastercard
		// debit card) answers nothing, DESELECT included, until the chip starts over
		if (t && !iso14aStart()) FAIL(0, "no card on a new discovery");
		if (!iso14aParity(true)) FAIL(-1, "parity on");
		if (block(&desel, 1, a, sizeof(a), 40) < 0) FAIL(-1, "deselect: monitor");
		svcSleepThread(5000000); // that card ignores a WUPA right after its DESELECT answer
		int sak = iso14aSelect();
		if (sak == -2) FAIL(-1, "select: monitor");
		if (sak < 0) {
			snprintf(why, sizeof(why), "select: no answer");
			continue;
		}
		if (!(sak & 0x20)) FAIL(0, "SAK %02X: not ISO14443-4", sak);
		int r = block(rats, 2, a, sizeof(a), 40);
		if (r < 0) FAIL(-1, "RATS: monitor");
		if (!r || a[0] != r) {
			snprintf(why, sizeof(why), "RATS: no ATS");
			continue;
		}
		memcpy(ats, a, (u32)r < atsMax ? (u32)r : atsMax);
		bn = 0;
		// FWT = 256 * 16 / fc * 2^FWI (FWI from TB1, default 4): a German ID card says FWI 13 (2.5 s) and
		// takes over a second for a PACE step without sending WTX
		int fwi = 4;
		if (r >= 2 && (a[1] & 0x20)) {
			int i = 2 + !!(a[1] & 0x10);
			if (i < r && a[i] >> 4 != 15) fwi = a[i] >> 4;
		}
		fwtPolls = (302 << fwi) / 2000 + 2;
		if (fwtPolls < 40) fwtPolls = 40;
		return 1;
	}
	return 0;
}

int isoDepTx(const u8 *inf, u32 len, u8 *out, u32 max)
{
	u8 cmd[ISO_DEP_MAX_INF + 1], r[2], a[34];
	u32 n = 0, off = 0, chunk = 0;
	int fails = 0, wtx = 0, polls = fwtPolls;
	const u8 *tx = cmd;
	u32 txLen = 0;
	// the next piece of the command: chained (PCB bit 4) while more follows
	#define LOAD_CHUNK() do { \
		chunk = len - off > ISO_DEP_MAX_INF ? ISO_DEP_MAX_INF : len - off; \
		cmd[0] = 0x02 | bn | (off + chunk < len ? 0x10 : 0); \
		memcpy(cmd + 1, inf + off, chunk); \
		tx = cmd, txLen = chunk + 1; \
	} while (0)
	LOAD_CHUNK();
	for (;;) {
		int k = block(tx, txLen, a, sizeof(a), polls);
		polls = fwtPolls;
		if (k < 0) FAIL(-1, "monitor");
		if (!k) {
			// R(NAK): the card repeats its last block, or ACKs if our I-block never got there
			if (++fails > 4) FAIL(0, "no answer"); // stray frames around a slow card's answer cost a few
			r[0] = 0xB2 | bn;
			tx = r, txLen = 1;
			continue;
		}
		u8 pcb = a[0];
		if ((pcb & 0xE2) == 0x02) { // I-block
			if (cmd[0] & 0x10) FAIL(0, "answer while chaining");
			if ((pcb & 1) != bn) {
				// a repeat of the block we ACKed already: ACK it again
				if (++fails > 2) FAIL(0, "block number");
				r[0] = 0xA2 | bn;
				tx = r, txLen = 1;
				continue;
			}
			bn ^= 1;
			if (n + k - 1 > max) FAIL(0, "answer too long");
			memcpy(out + n, a + 1, k - 1);
			n += k - 1;
			if (!(pcb & 0x10)) {
				if (!n) FAIL(0, "empty answer");
				return n;
			}
			r[0] = 0xA2 | bn; // chaining: R(ACK) for the next block
			tx = r, txLen = 1, fails = 0;
		} else if ((pcb & 0xF7) == 0xF2 && k >= 2) { // S(WTX): echo the multiplier, wait that much longer
			if (++wtx > 2000) FAIL(0, "endless WTX"); // a minute or more at the shortest FWT
			r[0] = 0xF2, r[1] = a[1] & 0x3F;
			tx = r, txLen = 2, fails = 0;
			polls = fwtPolls * (r[1] ? r[1] : 1);
		} else if ((pcb & 0xF6) == 0xA2 && (pcb & 1) == bn && (cmd[0] & 0x10)) {
			// R(ACK) for our chained block: on to the next piece
			bn ^= 1, off += chunk, fails = 0;
			LOAD_CHUNK();
		} else if ((pcb & 0xE6) == 0xA2) { // R(ACK) for the previous number: our last block got lost
			if (++fails > 2) FAIL(0, "R-block %02X", pcb);
			if (!n) tx = cmd, txLen = chunk + 1;
			else r[0] = 0xA2 | bn, tx = r, txLen = 1;
		} else {
			FAIL(0, "PCB %02X", pcb);
		}
	}
	#undef LOAD_CHUNK
}
