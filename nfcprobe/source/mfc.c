// Raw ISO14443A and Mifare Classic over the chip monitor, see mfc.h and NOTES.md.

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include "mfc.h"
#include "crapto1.h"
#include "nfchw.h"
#include "probe.h"

#define MS(x)       ((s64)(x) * 1000000LL)
#define PARITY_REG  0x5C560
#define PARITY_OFF  0x08
#define NRAR_TX     0x178 // r574 = 1, length code 0x78 for the 72-bit {nr}{ar} (NOTES.md)

Card card;
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

// The UID Crypto1 uses: the last cascade level's 4 bytes.
static u32 cardUid(void)
{
	const u8 *u = card.uid + card.uidLen - 4;
	return u[0] << 24 | u[1] << 16 | u[2] << 8 | u[3];
}

int iso14aSelect(void)
{
	MonFrame f[4];
	u8 hlta[4] = { 0x50, 0x00 }, wupa = 0x52, cl[3][4];
	if (card.uidLen != 4 && card.uidLen != 7 && card.uidLen != 10) return -1;
	crcA(hlta, 2, hlta + 2);
	if (iso14aTx(hlta, 4, 0, f, 4) < 0) return -2;
	int n = iso14aTx(&wupa, 1, 0x07, f, 4);
	if (n < 0) return -2;
	if (!n || f[n - 1].len != 2) return -1;
	memcpy(card.atqa, f[n - 1].data, 2);
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
		if (!n || !f[n - 1].len) return -1;
		sak = f[n - 1].data[0];
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

// Config bytes a write may change: 1 UID length (4, 7 or 10 bytes: what our SELECT does), 6 shadow mode,
// 7 ATS length, 8-23 ATS, 24-25 ATQA (swapped), 26 SAK. The rest (protocol, password, UL mode, max
// sectors) must stay, so a write can't lock us out: a lost password is a lost card.
static bool gen4CfgChangeable(int i)
{
	return i == 1 || (i >= 6 && i <= 26);
}

int mfGen4SetConfig(const u8 pwd[4], const u8 cfg[MF_GEN4_CFG])
{
	u8 cur[32], cmd[1 + MF_GEN4_CFG] = { 0xF0 }, ans[4];
	int n = mfGen4Config(pwd, cur, sizeof(cur));
	if (n <= 0) return n;
	if (n != MF_GEN4_CFG) FAIL(0, "config is %d bytes, not %d", n, MF_GEN4_CFG);
	for (int i = 0; i < MF_GEN4_CFG; i++)
		if (cfg[i] != cur[i] && !gen4CfgChangeable(i)) FAIL(0, "config byte %d may not change", i);
	if (cfg[1] > 2) FAIL(0, "UID length %02X (only 4, 7 or 10 bytes)", cfg[1]);
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

// Distance that last gave a key on this card (a calibrated one sticks for the card's other keys).
static u32 nestedDist = NESTED_DIST, nestedDistUid;

int mfNestedRecover(u8 kb, const u8 key[6], bool knownB, u8 tb, bool tgtB, u8 keyOut[6])
{
	u32 nt0, nt0b, enc1, enc, uid = cardUid();
	if (uid != nestedDistUid) {
		nestedDist = NESTED_DIST;
		nestedDistUid = uid;
	}
	int r = nestedNonce(kb, key, knownB, tb, tgtB, &nt0, &enc1);
	if (r <= 0) return r;
	u32 ntTa = prngSuccessor(nt0, nestedDist), ks1 = enc1 ^ ntTa;
	r = nestedNonce(kb, key, knownB, tb, tgtB, &nt0b, &enc);
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
	u64 k = crapto1_nested(uid, ntTa, ks1, ntTb, ks2);
	// A wrong distance can still leave a (wrong) key in both candidate sets: only an auth proves it.
	if ((r = keyAuths(k, tb, tgtB)) < 0) return -1;
	if (!r && nt0b != nt0) { // a PRNG that steps differently: measure the distance, like pm3
		u32 d;
		if ((r = calibrate(kb, key, knownB, false, &d)) <= 0) return r;
		logp("  nested: no key at distance %lu, calibrated %lu\n", nestedDist, d);
		ntTa = prngSuccessor(nt0, d);
		ntTb = prngSuccessor(nt0b, d);
		k = crapto1_nested(uid, ntTa, enc1 ^ ntTa, ntTb, enc ^ ntTb);
		if ((r = keyAuths(k, tb, tgtB)) < 0) return -1;
		if (!r) FAIL(0, "no key (calibrated distance %lu)", d);
		nestedDist = d;
	}
	if (!r) FAIL(0, "no key (wrong distance?)");
	keyBytes(k, keyOut);
	return 1;
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

	c1Encrypt(c, cmd, 4, cenc, cpar);
	u32 off;
	int n = ptx(cenc, 4, cpar, f, &off);
	if (n < 0) FAIL(-1, "A0 tx");
	int a = ack4(c, f, n, off);
	if (a != 0xA) FAIL(0, a < 0 ? "A0: no answer" : "A0 nak %X", a);

	c1Encrypt(c, plain, WR_BYTES, enc, par);
	u8 fifo[20];
	MonStore st[4];
	u32 ns = mixedFrame(enc, par, wrPairs[pair], fifo, st);
	monFrames(f, 2);
	if (!monTxsched(fifo, sizeof(fifo), 0x70, st, ns)) FAIL(-1, "data tx");
	n = waitFrames(f, 2);
	if (n < 0) FAIL(-1, "data frames");
	if (wrPairs[pair][1] == WR_BYTES - 1 && !iso14aParity(false)) FAIL(-1, "parity off"); // left on
	a = ack4(c, f, n, 0); // whole-byte frame: the answer starts at bit 0
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

const u8 mfDefaultKeys[][6] = {
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }, { 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5 },
	{ 0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7 }, { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5 }, { 0x4D, 0x3A, 0x99, 0xC3, 0x51, 0xDD },
	{ 0x1A, 0x98, 0x2C, 0x7E, 0x45, 0x9A }, { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF },
	{ 0x71, 0x4C, 0x5C, 0x88, 0x6E, 0x97 }, { 0x58, 0x7E, 0xE5, 0xF9, 0x35, 0x0F },
};
const int mfNumDefaultKeys = sizeof(mfDefaultKeys) / 6;

// Gen2 (CUID): block 0 takes a normal WRITE. Rewrites it with what it holds, so nothing changes.
static int gen2Test(void)
{
	for (int k = 0; k < mfNumDefaultKeys; k++)
		for (int kb = 0; kb < 2; kb++) {
			Crypto1 c;
			u8 b0[16];
			int r = mfAuth(0, mfDefaultKeys[k], kb, &c);
			if (r < 0) return -1;
			if (!r) continue;
			if ((r = mfReadBlock(&c, 0, b0)) <= 0) return r;
			if ((r = mfWrite(0, mfDefaultKeys[k], kb, b0)) < 0) return -1;
			logp("gen2 test (block 0 rewrite, key %c): %s\n", kb ? 'B' : 'A', r ? "ok" : mfWhy());
			return r;
		}
	logp("gen2 test: no default key for sector 0\n");
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
	if (mfGen1aUnlock()) {
		m->flags |= MF_MAGIC_GEN1A;
		if ((r = mfUscuidConfig(m->usc)) < 0) return -1;
		if (r) m->flags |= MF_MAGIC_USCUID;
	}
	if (testGen2) {
		if ((r = gen2Test()) < 0) return -1;
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

// FM11RF08S family (NOTES.md): with a backdoor key, collect every sector's static nonce and solve
// keys offline -- dictionary keys and reuse are checked against the nonces with no RF traffic, and
// only matches cost an auth. A candidate of one cell that fits another cell is a reused key. Keys used
// by a single cell stay open (tens of thousands of candidates: too many to try over RF). Returns -1
// on a monitor error.
static int staticPass(MfDump *d, int sectors, u8 (*dict)[6], int *ndict)
{
	u8 bd[6];
	int r = mfBackdoorKey(bd);
	if (r <= 0) return r;
	logp("backdoor key %02X%02X%02X%02X%02X%02X: static nonce attack\n",
		bd[0], bd[1], bd[2], bd[3], bd[4], bd[5]);
	static MfStatic st[40][2];
	static u64 cand[1 << 18];
	bool done[40][2] = { 0 }, expanded[40][2] = { 0 };
	u32 uid = cardUid();
	for (int sec = 0; sec < sectors; sec++)
		for (int kb = 0; kb < 2; kb++) {
			if ((r = mfStaticNonce(mfFirstBlock(sec), kb, bd, &st[sec][kb])) < 0) return -1;
			done[sec][kb] = r == 1;
		}
#define OPEN(s, k) (done[s][k] && !d->keyFound[s][k])
	bool progress = true;
	while (progress) {
		progress = false;
		for (int sec = 0; sec < sectors; sec++)
			for (int kb = 0; kb < 2; kb++)
				for (int k = 0; k < *ndict && OPEN(sec, kb); k++)
					if (mfStaticMatch(&st[sec][kb], dict[k]) && readSectorRetry(d, sec, dict[k], kb) < 0)
						return -1;
		for (int sec = 0; sec < sectors && !progress; sec++)
			for (int kb = 0; kb < 2 && !progress; kb++) {
				if (!OPEN(sec, kb) || expanded[sec][kb]) continue;
				expanded[sec][kb] = true;
				MfStatic *s = &st[sec][kb];
				int n = crapto1_static(uid, s->nt, s->ntEnc, s->par, cand, 1 << 18);
				logp("sector %2d %c: %d candidates\n", sec, kb ? 'B' : 'A', n);
				for (int i = 0; i < n && !progress; i++)
					for (int os = 0; os < sectors && !progress; os++)
						for (int ok = 0; ok < 2; ok++) {
							if ((os == sec && ok == kb) || !OPEN(os, ok)) continue;
							if (crapto1_nt_decrypt(cand[i], uid, st[os][ok].ntEnc) != st[os][ok].nt)
								continue;
							u8 key[6];
							keyBytes(cand[i], key);
							logp("  reused key %02X%02X%02X%02X%02X%02X (sector %d %c)\n", key[0], key[1],
								key[2], key[3], key[4], key[5], os, ok ? 'B' : 'A');
							*ndict = addKey(dict, *ndict, MF_MAX_KEYS, key);
							progress = true; // back to the dictionary step, which applies it everywhere
							break;
						}
			}
	}
	for (int sec = 0; sec < sectors; sec++)
		for (int kb = 0; kb < 2; kb++)
			if (OPEN(sec, kb)) logp("sector %2d %c: key used only here, not recovered\n", sec, kb ? 'B' : 'A');
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
	}
	return 1;
}

// Magic cards read without keys: Gen4 GTU (default password), then the Gen1a backdoor. The trailers
// hold the real keys; they go into the dictionary, which the sweep then confirms by auth.
static int magicPass(MfDump *d, int sectors, u8 (*dict)[6], int *ndict)
{
	int nb = mfFirstBlock(sectors), r = mfGen4Read(mfGen4DefaultPwd, 0, d->data[0]);
	if (r < 0) return -1;
	bool gen4 = r;
	if (!gen4 && !mfGen1aUnlock()) return 0;
	logp("%s magic: reading without keys\n", gen4 ? "gen4 GTU" : "gen1a");
	for (int b = 0; b < nb; b++) {
		for (int t = 0; t < 3; t++) {
			if (gen4) {
				if ((r = mfGen4Read(mfGen4DefaultPwd, b, d->data[b])) < 0) return -1;
			} else {
				r = gen1aRead(b, d->data[b]); // -1 is no answer here, not a monitor error
				if (r != 1) mfGen1aUnlock();
			}
			if (r == 1) break;
		}
		d->valid[b] = r == 1;
	}
	// The trailer keys are known to be right: confirm them with retries, so one flaky auth doesn't
	// send a sector to the nested attack.
	for (int sec = 0; sec < sectors; sec++) {
		int t = mfFirstBlock(sec) + mfSectorBlocks(sec) - 1;
		if (!d->valid[t]) continue;
		u8 keys[2][6];
		memcpy(keys[0], d->data[t], 6);
		memcpy(keys[1], d->data[t] + 10, 6);
		for (int kb = 0; kb < 2; kb++) {
			*ndict = addKey(dict, *ndict, MF_MAX_KEYS, keys[kb]);
			if (readSectorRetry(d, sec, keys[kb], kb) < 0) return -1;
		}
	}
	return 1;
}

int mfDumpCard(MfDump *d, int sectors, const u8 (*keys)[6], int nkeys)
{
	memset(d, 0, sizeof(*d));
	d->sectors = sectors;
	// Running dictionary: the supplied keys plus every key we recover (a key reused by
	// another sector is far cheaper to auth than to recover again). Magic cards' trailer keys go first.
	static u8 dict[MF_MAX_KEYS][6];
	int ndict = 0;
	if (magicPass(d, sectors, dict, &ndict) < 0) return -1;
	for (int k = 0; k < nkeys; k++) ndict = addKey(dict, ndict, MF_MAX_KEYS, keys[k]);
	bool nestedTried[40][2] = { 0 };
	int tried[40][2] = { 0 }; // dict entries already attempted per cell (so each is tried once)
	int pivotSec = -1; bool pivotB = false; // first confirmed key, used as the nested known key

	// FM11RF08S family: the backdoor solves what it can before the sweep.
	if (staticPass(d, sectors, dict, &ndict) < 0) return -1;

	// Sweep until a full pass turns up nothing new: recover EVERY missing A/B key, folding each
	// one back into the dictionary so later sectors can reuse it before falling back to nested.
	bool progress = true;
	while (progress) {
		progress = false;
		for (int sec = 0; sec < sectors; sec++)
			for (int kb = 0; kb < 2; kb++) {
				if (d->keyFound[sec][kb]) continue;
				for (int k = tried[sec][kb]; k < ndict && !d->keyFound[sec][kb]; k++)
					if (readSector(d, sec, dict[k], kb) < 0) return -1;
				tried[sec][kb] = ndict;
				if (!d->keyFound[sec][kb]) {
					if (pivotSec < 0 || nestedTried[sec][kb]) continue; // nested needs a known key
					nestedTried[sec][kb] = true;
					u8 rk[6];
					logp("sector %2d %c: nested...\n", sec, kb ? 'B' : 'A');
					int r = mfNestedRecover(mfFirstBlock(pivotSec), d->keys[pivotSec][pivotB],
						pivotB, mfFirstBlock(sec), kb, rk);
					if (r < 0) return -1;
					if (!r) { logp("  nested: %s\n", mfWhy()); continue; }
					logp("  recovered %02X%02X%02X%02X%02X%02X\n",
						rk[0], rk[1], rk[2], rk[3], rk[4], rk[5]);
					if (readSector(d, sec, rk, kb) < 0) return -1;
				}
				if (d->keyFound[sec][kb]) {
					if (pivotSec < 0) { pivotSec = sec; pivotB = kb; }
					ndict = addKey(dict, ndict, MF_MAX_KEYS, d->keys[sec][kb]);
					progress = true;
				}
			}
	}
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
				int v = (*p >= '0' && *p <= '9') ? *p - '0' : ((*p | 0x20) >= 'a' && (*p | 0x20) <= 'f') ? (*p | 0x20) - 'a' + 10 : -1;
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

bool mfSaveDump(const MfDump *d, char *path, u32 pathMax)
{
	char uid[21] = "";
	for (int i = 0; i < card.uidLen; i++) sprintf(uid + 2 * i, "%02X", card.uid[i]);
	mkdir(MF_DIR, 0777);
	mkdir(MF_DIR "/dumps", 0777);
	snprintf(path, pathMax, MF_DIR "/dumps/%s.bin", uid);
	FILE *f = fopen(path, "wb");
	if (!f) return false;
	static const u8 zero[16];
	int nb = mfFirstBlock(d->sectors);
	for (int b = 0; b < nb; b++) fwrite(d->valid[b] ? d->data[b] : zero, 1, 16, f); // unread = zeros
	fclose(f);
	char kpath[64];
	snprintf(kpath, sizeof(kpath), MF_DIR "/dumps/%s.keys.txt", uid);
	if ((f = fopen(kpath, "w"))) {
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
		fclose(f);
	}
	return true;
}

// Access bits are stored twice (inverted); a broken copy locks a real sector for good.
static bool aclValid(const u8 *t)
{
	return (t[7] >> 4) == (~t[6] & 0xF) && (t[8] & 0xF) == (~t[6] >> 4 & 0xF) && (t[8] >> 4) == (~t[7] & 0xF);
}

// C1 C2 C3 of the trailer itself: 001 and 011 leave keys and access bits writable (key A / key B).
static bool trailerRewritable(const u8 *t)
{
	u8 c = (t[7] >> 7 & 1) << 2 | (t[8] >> 3 & 1) << 1 | (t[8] >> 7 & 1);
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
	if (type == CLONE_GEN4) return mfGen4Write(mfGen4DefaultPwd, b, data);
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
	if (sectors > mfSectorsFromSak(card.sak)) FAIL(0, "dump has %d sectors, the card %d", sectors, mfSectorsFromSak(card.sak));
	for (int sec = 0; sec < sectors; sec++) {
		int t = mfFirstBlock(sec) + mfSectorBlocks(sec) - 1;
		if (valid[t] && !aclValid(data[t])) FAIL(0, "sector %d: broken access bits", sec);
	}

	MfMagic m;
	if (mfMagicDetect(mfGen4DefaultPwd, false, &m) < 0) return -1;
	int type = m.flags & MF_MAGIC_GEN4 ? CLONE_GEN4 : m.flags & MF_MAGIC_GEN1A ? CLONE_GEN1A : CLONE_GEN2;
	// The GTU computes its BCC; the others send block 0's as it is, and a wrong one breaks anticollision.
	if (type != CLONE_GEN4 && valid[0] && card.uidLen == 4
	    && (data[0][0] ^ data[0][1] ^ data[0][2] ^ data[0][3]) != data[0][4])
		FAIL(0, "block 0: bad BCC");
	static MfDump tgt;
	if (type == CLONE_GEN2) {
		int r = gen2Test();
		if (r < 0) return -1;
		if (!r) FAIL(0, "not a magic card");
		for (int sec = 0; sec < sectors && !force; sec++) {
			int t = mfFirstBlock(sec) + mfSectorBlocks(sec) - 1;
			if (valid[t] && !trailerRewritable(data[t]))
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
