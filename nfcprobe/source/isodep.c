// ISO14443-4 (ISO-DEP) over the chip monitor, see isodep.h.

#include <stdio.h>
#include <string.h>

#include "isodep.h"
#include "mfc.h"

static char why[64];
static u8 bn; // our block number

const char *isoDepWhy(void)
{
	return why;
}

#define FAIL(ret, ...) ({ snprintf(why, sizeof(why), __VA_ARGS__); return (ret); })

// One frame out, one block back (CRC checked and cut). Its length, 0 = none / broken, -1 = monitor.
static int block(const u8 *f, u32 len, u8 *out, u32 max)
{
	MonFrame a[2];
	u8 crc[2];
	int n = iso14aDataTx(f, len, a, 2, 40);
	if (n <= 0) return n;
	const MonFrame *m = &a[n - 1];
	if (m->len < 3 || m->len < m->regs[4]) return 0;
	iso14aCrc(m->data, m->len - 2, crc);
	if (memcmp(crc, m->data + m->len - 2, 2)) return 0;
	u32 k = m->len - 2 < max ? m->len - 2 : max;
	memcpy(out, m->data, k);
	return k;
}

int isoDepActivate(u8 *ats, u32 atsMax)
{
	u8 desel = 0xC2, rats[2] = { 0xE0, 0x20 }, a[34]; // RATS: FSDI 2 (32 bytes), CID 0
	if (!iso14aParity(true)) FAIL(-1, "parity on");
	if (block(&desel, 1, a, sizeof(a)) < 0) FAIL(-1, "deselect: monitor");
	int sak = iso14aSelect();
	if (sak == -2) FAIL(-1, "select: monitor");
	if (sak < 0) FAIL(0, "select: no answer");
	if (!(sak & 0x20)) FAIL(0, "SAK %02X: not ISO14443-4", sak);
	int r = block(rats, 2, a, sizeof(a));
	if (r < 0) FAIL(-1, "RATS: monitor");
	if (!r || a[0] != r) FAIL(0, "RATS: no ATS");
	memcpy(ats, a, (u32)r < atsMax ? (u32)r : atsMax);
	bn = 0;
	return 1;
}

int isoDepTx(const u8 *inf, u32 len, u8 *out, u32 max)
{
	u8 cmd[ISO_DEP_MAX_INF + 1], r[2], a[34];
	if (len > ISO_DEP_MAX_INF) FAIL(0, "command too long");
	cmd[0] = 0x02 | bn;
	memcpy(cmd + 1, inf, len);
	const u8 *tx = cmd;
	u32 txLen = len + 1, n = 0;
	int fails = 0, wtx = 0;
	for (;;) {
		int k = block(tx, txLen, a, sizeof(a));
		if (k < 0) FAIL(-1, "monitor");
		if (!k) {
			// R(NAK): the card repeats its last block, or ACKs if our I-block never got there
			if (++fails > 2) FAIL(0, "no answer");
			r[0] = 0xB2 | bn;
			tx = r, txLen = 1;
			continue;
		}
		u8 pcb = a[0];
		if ((pcb & 0xE2) == 0x02) { // I-block
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
		} else if ((pcb & 0xF7) == 0xF2 && k >= 2) { // S(WTX): echo the multiplier
			if (++wtx > 50) FAIL(0, "endless WTX");
			r[0] = 0xF2, r[1] = a[1] & 0x3F;
			tx = r, txLen = 2;
		} else if ((pcb & 0xE6) == 0xA2) { // R(ACK) for the previous number: our last block got lost
			if (++fails > 2) FAIL(0, "R-block %02X", pcb);
			if (!n) tx = cmd, txLen = len + 1;
			else r[0] = 0xA2 | bn, tx = r, txLen = 1;
		} else {
			FAIL(0, "PCB %02X", pcb);
		}
	}
}
