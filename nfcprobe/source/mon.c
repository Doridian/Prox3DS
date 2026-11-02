// Host side of the chip debug monitor (chip/memrw.c), the C version of tools/chipmon.py.

#include <string.h>

#include "mon.h"
#include "nfchw.h"
#include "probe.h"
#include "memrw_ncd_bin.h"

#define N_FRAMES   8
#define FRAME_SIZE 64 // seq, regs[5], len, data[36], pad[3]

static u32 ringAddr, seen;

static u32 get32(const u8 *p)
{
	return p[0] | (p[1] << 8) | (p[2] << 16) | ((u32)p[3] << 24);
}

static void put32(u8 *p, u32 v)
{
	for (int i = 0; i < 4; i++) p[i] = v >> (8 * i);
}

// Sends an NCI command and waits for the packet starting with b1 b2 (response or notification).
static bool nciExpect(const u8 *cmd, u32 len, u8 b1, u8 b2, u32 timeoutMs)
{
	u8 pkt[4 + 0x100];
	if (R_FAILED(i2cNfcWrite(cmd, len))) return false;
	for (int n = 0; n < 8; n++) {
		u32 rlen = nciRecv(pkt, sizeof(pkt), timeoutMs / 20 + 1, false);
		if (!rlen) return false;
		if (rlen >= 4 && pkt[1] == b1 && pkt[2] == b2) return true;
	}
	return false;
}

static void drainQuiet(void)
{
	u8 pkt[4 + 0x100];
	while (nciRecv(pkt, sizeof(pkt), 3, false));
}

bool monLoad(void)
{
	static const u8 coreReset[] = { NCI_HCIT, 0x20, 0x00, 0x01, 0x01 };
	static const u8 coreInit[]  = { NCI_HCIT, 0x20, 0x01, 0x00 };
	static const u8 patchVer[]  = { NCI_HCIT, 0x2F, 0x2D, 0x00 };
	// Loads occasionally fail (download rejected, or no answer afterwards); retry those.
	for (int t = 0; t < 3; t++) {
		chipPowerUp();
		drainQuiet();
		if (!spdDownload(memrw_ncd_bin, memrw_ncd_bin_size, false)) continue;
		nciExpect(coreReset, sizeof(coreReset), 0x40, 0x00, 500);
		drainQuiet();
		if (!nciExpect(patchVer, sizeof(patchVer), 0x4F, 0x2D, 500)) continue;
		nciExpect(coreInit, sizeof(coreInit), 0x40, 0x01, 500);
		drainQuiet();
		ringAddr = 0;
		return true;
	}
	return false;
}

int monDo(u8 op, u32 addr, const void *data, u32 len, u8 *out, u32 outMax)
{
	return monDoWait(op, addr, data, len, out, outMax, 4000);
}

int monDoWait(u8 op, u32 addr, const void *data, u32 len, u8 *out, u32 outMax, u32 waitMs)
{
	u8 pkt[4 + 0x100];
	if (len > 0xFF - 5) return MON_STATUS(0xFF);
	pkt[0] = NCI_HCIT;
	pkt[1] = 0x2F;
	pkt[2] = 0x2C;
	pkt[3] = 5 + len;
	pkt[4] = op;
	put32(pkt + 5, addr);
	memcpy(pkt + 9, data, len);
	if (R_FAILED(i2cNfcWrite(pkt, 9 + len))) return MON_NO_ANSWER;
	// While the chip is busy with RF the answer can come late: 1 s, then up to waitMs more.
	// Other packets (RF notifications) are skipped.
	u32 rlen = 0;
	for (int n = 0; n < 16; n++) {
		rlen = nciRecv(pkt, sizeof(pkt), 1000 / 20, false);
		if (!rlen && !n) rlen = nciRecv(pkt, sizeof(pkt), waitMs / 20, false);
		if (!rlen || (rlen >= 5 && pkt[1] == 0x4F && pkt[2] == 0x2C)) break;
	}
	if (rlen < 5 || pkt[1] != 0x4F || pkt[2] != 0x2C) return MON_NO_ANSWER;
	if (pkt[4]) return MON_STATUS(pkt[4]);
	u32 n = rlen - 5;
	if (n > outMax) n = outMax;
	if (out) memcpy(out, pkt + 5, n);
	return n;
}

bool monRead(u32 addr, void *buf, u32 len)
{
	u8 *p = buf;
	for (u32 o = 0; o < len; o += MON_CHUNK) {
		u8 n = len - o < MON_CHUNK ? len - o : MON_CHUNK;
		if (monDo(MON_READ8, addr + o, &n, 1, p + o, n) != n) return false;
	}
	return true;
}

bool monWrite32(u32 addr, u32 value)
{
	u8 w[4];
	put32(w, value);
	return monDo(MON_WRITE32, addr, w, 4, NULL, 0) == 0;
}

bool monCapture(bool on)
{
	u8 arg = on, out[8], cnt[4];
	if (monDo(MON_CAPTURE, 0, &arg, 1, out, 4) != 4) return false;
	ringAddr = get32(out);
	if (!monRead(ringAddr, cnt, 4)) return false;
	seen = get32(cnt);
	return true;
}

int monFrames(MonFrame *out, int max)
{
	u8 cnt[4];
	if (!ringAddr || !monRead(ringAddr, cnt, 4)) return -1;
	u32 count = get32(cnt), first = seen + 1;
	if (count + 1 > first + N_FRAMES) first = count + 1 - N_FRAMES; // overwritten ones are lost
	if (count + 1 > first + max) first = count + 1 - max;           // keep the newest
	int n = 0;
	for (u32 seq = first; seq <= count; seq++) {
		u8 f[FRAME_SIZE];
		if (!monRead(ringAddr + 4 + ((seq - 1) % N_FRAMES) * FRAME_SIZE, f, sizeof(f))) return -1;
		if (get32(f) != seq) continue;
		for (int i = 0; i < 5; i++) out[n].regs[i] = get32(f + 4 + 4 * i);
		out[n].len = f[24] > sizeof(out[n].data) ? sizeof(out[n].data) : f[24];
		memcpy(out[n].data, f + 25, out[n].len);
		n++;
	}
	seen = count;
	return n;
}

bool monTxraw(const u8 *data, u32 len, u8 code, u8 r570, u8 r574, u8 r55c)
{
	u8 arg[4 + 0x40];
	if (len > sizeof(arg) - 4) return false;
	arg[0] = r570;
	arg[1] = r574;
	arg[2] = code;
	arg[3] = r55c;
	memcpy(arg + 4, data, len);
	return monDo(MON_TXRAW, 0, arg, 4 + len, NULL, 0) == 0;
}

bool monTxsched(const u8 *data, u32 len, u8 code, const MonStore *st, u32 n)
{
	return monTxschedRegs(data, len, code, 0, 1, 0x88, st, n);
}

bool monTxschedRegs(const u8 *data, u32 len, u8 code, u8 r570, u8 r574, u8 r55c, const MonStore *st, u32 n)
{
	u8 arg[5 + 10 * MON_MAX_STORES + 0x40], out[4];
	if (n > MON_MAX_STORES || len > 0x40) return false;
	arg[0] = r570;
	arg[1] = r574;
	arg[2] = code;
	arg[3] = r55c;
	arg[4] = n;
	u8 *p = arg + 5;
	for (u32 i = 0; i < n; i++, p += 10) {
		p[0] = st[i].delay;
		p[1] = st[i].delay >> 8;
		put32(p + 2, st[i].reg);
		put32(p + 6, st[i].val);
	}
	memcpy(p, data, len);
	return monDo(MON_TXSCHED, 0, arg, p - arg + len, out, sizeof(out)) == 4;
}

int monAuth(const u8 key[6], u32 uid, u32 nr, const u8 *frame, u32 flen, u8 code, u32 nrarTx,
	u32 *nt, u32 *odd, u32 *even)
{
	u8 arg[15 + 16], out[12];
	if (flen > 16) return -1;
	memcpy(arg, key, 6);
	for (int i = 0; i < 4; i++) {
		arg[6 + i] = uid >> (24 - 8 * i);
		arg[10 + i] = nr >> (24 - 8 * i);
	}
	arg[14] = code;
	memcpy(arg + 15, frame, flen);
	int r = monDo(MON_AUTH, nrarTx, arg, 15 + flen, out, sizeof(out));
	if (r == MON_STATUS(2)) return 0;
	if (r != 12) return -1;
	*nt = get32(out);
	*odd = get32(out + 4);
	*even = get32(out + 8);
	return 1;
}

int monNested(const u8 key[6], u32 uid, u32 nr, const u8 *frame, u32 flen, u8 code,
	const u8 nestedCmd[4], u32 nrarTx, u32 *nt0)
{
	u8 arg[19 + 16], out[4];
	if (flen > 16) return -1;
	memcpy(arg, key, 6);
	for (int i = 0; i < 4; i++) {
		arg[6 + i] = uid >> (24 - 8 * i);
		arg[10 + i] = nr >> (24 - 8 * i);
	}
	arg[14] = code;
	memcpy(arg + 15, nestedCmd, 4);
	memcpy(arg + 19, frame, flen);
	int r = monDo(MON_NESTED, nrarTx, arg, 19 + flen, out, sizeof(out));
	if (r == MON_STATUS(2) || r == MON_STATUS(3)) return 0;
	if (r != 4) return -1;
	*nt0 = get32(out);
	return 1;
}

int monChkKeys(const u8 *arg, u32 len, u32 nrarTx, u8 out[3])
{
	return monDo(MON_CHKKEYS, nrarTx, arg, len, out, 3) == 3 ? 0 : -1;
}

int monDarkside(const u8 *arg, u32 len, u32 nrarTx, int nslot, u8 *out)
{
	// up to maxiter AUTHs, nslot per PRNG period (~79 ms)
	int n = MON_DARKSIDE_SLOT * nslot, r = monDoWait(MON_DARKSIDE, nrarTx, arg, len, out, n, 30000);
	return r == n ? 0 : -1;
}
