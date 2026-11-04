// MIFARE DESFire over ISO-DEP, with EV1 secure messaging once a key is known; see desfire.h.

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include "desfire.h"
#include "isodep.h"
#include "nxpsig.h"
#include "probe.h"

static char why[64];

const char *dfWhy(void)
{
	return why;
}

#define FAIL(ret, ...) ({ snprintf(why, sizeof(why), __VA_ARGS__); return (ret); })

const char *dfStatusName(u8 st)
{
	switch (st) {
	case 0x00: return "ok";
	case 0x0C: return "no changes";
	case 0x0E: return "out of EEPROM";
	case 0x1C: return "illegal command";
	case 0x1E: return "integrity error";
	case 0x40: return "no such key";
	case 0x7E: return "length error";
	case 0x9D: return "permission denied";
	case 0x9E: return "parameter error";
	case 0xA0: return "application not found";
	case 0xAE: return "authentication error";
	case 0xAF: return "additional frame";
	case 0xBE: return "boundary error";
	case 0xCA: return "command aborted";
	case 0xEE: return "memory error";
	case 0xF0: return "file not found";
	case DF_ST_MAC: return "bad MAC / CRC";
	}
	return "unknown status";
}

// --- EV1 secure messaging ---

static struct {
	bool on, ev2, d40;
	u8 keyNo;
	DfCipher c;   // EV1: the session key; EV2: SesAuthENCKey
	u8 iv[16];    // EV1 only
	DfCipher mac; // EV2: SesAuthMACKey
	u8 ti[4];     // EV2: transaction identifier, command counter
	u16 ctr;
} ses;

static u32 rng;

static void rnd(u8 *p, u32 n)
{
	if (!rng) rng = (u32)osGetTime() * 2654435761u | 1;
	while (n--) {
		rng ^= rng << 13, rng ^= rng >> 17, rng ^= rng << 5;
		*p++ = rng >> 24;
	}
}

static void put32(u8 *p, u32 v)
{
	p[0] = v, p[1] = v >> 8, p[2] = v >> 16, p[3] = v >> 24;
}

// Commands that carry our MAC in MAC mode (pm3 EV1D40TransmitMAC): the writes.
static bool txMac(u8 c)
{
	return c == 0x3D || c == 0x3B || c == 0xDB || c == 0x0C || c == 0xDC || c == 0x1C || c == 0xC8;
}

// A decrypted full-mode answer: data, CRC32 over data + status (00; Read_Sig's 90), padding (zeros, or 80 and zeros).
// The data length, -1 = no CRC fits.
static int crcPos(const u8 *p, u32 n, u8 bs, u8 st)
{
	u8 t[320];
	for (int l = (int)n - 4; l >= 0 && l > (int)n - 4 - bs; l--) {
		bool pad = true;
		for (u32 i = l + 4; i < n; i++) pad &= !p[i] || (i == (u32)l + 4 && p[i] == 0x80);
		if (!pad) continue;
		memcpy(t, p, l);
		t[l] = st;
		u32 crc = dfCrc32(t, l + 1);
		if (p[l] == (u8)crc && p[l + 1] == (u8)(crc >> 8) && p[l + 2] == (u8)(crc >> 16) && p[l + 3] == (u8)(crc >> 24))
			return l;
	}
	return -1;
}

// EV2 (AES only, no running IV): MACt = the odd bytes of CMAC(SesAuthMACKey, code || CmdCtr || TI || data)
static void ev2Mac(u8 code, const u8 *p, u32 len, u8 *mac)
{
	u8 m[340], iv[16] = { 0 }, full[16];
	m[0] = code, m[1] = ses.ctr, m[2] = ses.ctr >> 8;
	memcpy(m + 3, ses.ti, 4);
	memcpy(m + 7, p, len);
	dfCmac(&ses.mac, iv, m, 7 + len, full);
	for (int i = 0; i < 8; i++) mac[i] = full[2 * i + 1];
}

// The IV for full mode: E(SesAuthENCKey, A55A (command) / 5AA5 (answer) || TI || CmdCtr || 0..)
static void ev2Iv(bool cmd, u8 *iv)
{
	memset(iv, 0, 16);
	iv[0] = cmd ? 0xA5 : 0x5A, iv[1] = cmd ? 0x5A : 0xA5;
	memcpy(iv + 2, ses.ti, 4);
	iv[6] = ses.ctr, iv[7] = ses.ctr >> 8;
	dfBlock(&ses.c, iv, true);
}

// EV2 wants a MAC on every command but the data ones (file comm mode) once authenticated.
static bool dataCmd(u8 c)
{
	return c == 0xBD || c == 0xBB || c == 0x6C || c == 0x3D || c == 0x3B || c == 0xDB || c == 0x0C || c == 0xDC ||
		c == 0x1C || c == 0x51 || c == 0xC4;
}

// D40 (MF3ICD40 secure messaging, pm3 DACd40): the card only enciphers, so what we send is deciphered in
// CBC send mode (y_i = D(x_i ^ y_i-1)), what we get back deciphered in the usual CBC; IV 0 each time.
static void d40Send(const DfCipher *c, u8 *p, u32 len)
{
	u8 iv[8] = { 0 };
	for (u32 o = 0; o < len; o += 8) {
		for (int i = 0; i < 8; i++) p[o + i] ^= iv[i];
		dfBlock(c, p + o, false);
		memcpy(iv, p + o, 8);
	}
}

// D40 MAC: the first 4 bytes of the last block of the zero-padded data CBC-enciphered from IV 0
static void d40Mac(const u8 *p, u32 len, u8 *mac)
{
	u8 t[320], iv[8] = { 0 };
	u32 pl = (len + 7) / 8 * 8;
	memcpy(t, p, len);
	memset(t + len, 0, pl - len);
	dfCbc(&ses.c, iv, t, pl, true);
	memcpy(mac, t + pl - 8, 4);
}

// A deciphered D40 full-mode answer: data, CRC16-A over the data, zero padding. The data length, -1 = none fits.
static int crc16Pos(const u8 *p, u32 n)
{
	for (int l = (int)n - 2; l >= 0 && l > (int)n - 10; l--) {
		bool pad = true;
		for (u32 i = l + 2; i < n; i++) pad &= !p[i];
		u8 crc[2];
		iso14aCrc(p, l, crc);
		if (pad && p[l] == crc[0] && p[l + 1] == crc[1]) return l;
	}
	return -1;
}

static bool readCmd(u8 c)
{
	return c == 0xBD || c == 0xBB || c == 0x6C;
}

#define DF_FRAME 54 // command bytes per native frame (pm3 DESFIRE_TX_FRAME_MAX_LEN)

int dfCmd(const u8 *c, u32 len, u32 hdr, u8 comm, u8 *out, u32 max, u8 *st)
{
	u8 tx[320], rx[320], a[128], af[1 + DF_FRAME] = { 0xAF }, mac[16], bs = ses.c.bs;
	if (len + 4 + 16 + 8 > sizeof(tx)) FAIL(-1, "command too long");
	// SelectApplication ends the session, so does any error; a good answer keeps it
	bool on = ses.on && c[0] != 0x5A, encRx = false;
	ses.on = false;
	memcpy(tx, c, len);
	u32 n = len;
	bool pad80 = comm == DF_FULL80;
	if (pad80) comm = DF_FULL; // EV2 pads with 80 anyway
	if (on && ses.ev2) {
		if (comm == DF_PLAIN && !dataCmd(c[0])) comm = DF_MACED;
		if (comm == DF_ENC || (comm == DF_FULL && len > 1 + hdr)) { // data + 80 00.., encrypted
			u32 d = len - 1 - hdr, p = (d + 16) / 16 * 16;
			tx[len] = 0x80;
			memset(tx + len + 1, 0, p - d - 1);
			u8 iv[16];
			ev2Iv(true, iv);
			dfCbc(&ses.c, iv, tx + 1 + hdr, p, true);
			n = 1 + hdr + p;
		} else {
			encRx = comm == DF_FULL;
		}
		if (comm != DF_PLAIN) ev2Mac(c[0], tx + 1, n - 1, tx + n), n += 8;
	} else if (on && ses.d40) { // CRC16 over the data only, MAC over the data only, writes only
		if (comm == DF_ENC || (comm == DF_FULL && len > 1 + hdr)) {
			u32 d = len - 1 - hdr;
			if (comm == DF_FULL) iso14aCrc(c + 1 + hdr, d, tx + len), d += 2;
			if (pad80) tx[1 + hdr + d++] = 0x80;
			u32 p = (d + 7) / 8 * 8;
			memset(tx + 1 + hdr + d, 0, p - d);
			d40Send(&ses.c, tx + 1 + hdr, p);
			n = 1 + hdr + p;
		} else {
			if (comm == DF_MACED && txMac(c[0]) && len > 1 + hdr) d40Mac(c + 1 + hdr, len - 1 - hdr, tx + len), n += 4;
			encRx = comm == DF_FULL;
		}
	} else if (on) {
		if (comm == DF_ENC || (comm == DF_FULL && len > 1 + hdr)) {
			u32 d = len - 1 - hdr;
			if (comm == DF_FULL) put32(tx + len, dfCrc32(c, len)), d += 4;
			if (pad80) tx[1 + hdr + d++] = 0x80;
			u32 p = (d + bs - 1) / bs * bs;
			memset(tx + 1 + hdr + d, 0, p - d);
			dfCbc(&ses.c, ses.iv, tx + 1 + hdr, p, true);
			n = 1 + hdr + p;
		} else {
			dfCmac(&ses.c, ses.iv, c, len, mac);
			if (comm == DF_MACED && txMac(c[0])) memcpy(tx + len, mac, 8), n += 8;
			encRx = comm == DF_FULL; // a read: the answer comes encrypted
		}
	}
	// native frames of DF_FRAME bytes out (AF between them), AF frames in, joined
	u32 o = n < 1 + DF_FRAME ? n : 1 + DF_FRAME, got = 0;
	int k = isoDepTx(tx, o, a, sizeof(a));
	for (int i = 0;; i++) {
		if (k < 0) return -2;
		if (!k) FAIL(-1, "lost the card: %s", isoDepWhy());
		*st = a[0];
		if (o < n) {
			if (a[0] != 0xAF) break;
			u32 m = n - o < DF_FRAME ? n - o : DF_FRAME;
			memcpy(af + 1, tx + o, m);
			o += m;
			k = isoDepTx(af, 1 + m, a, sizeof(a));
			continue;
		}
		u32 m = (u32)k - 1 < sizeof(rx) - got ? (u32)k - 1 : sizeof(rx) - got;
		memcpy(rx + got, a + 1, m);
		got += m;
		if (a[0] != 0xAF || i == 40) break;
		k = isoDepTx(af, 1, a, sizeof(a));
	}
	// ChangeKey of the session's own key ends it without a MAC
	// Read_Sig (3C) answers 90 when it worked
	bool ok = !*st || (c[0] == 0x3C && *st == 0x90);
	if (on && ok && !(c[0] == 0xC4 && (c[1] & 0x3F) == ses.keyNo) && ses.ev2) {
		ses.ctr++;
		if (comm != DF_PLAIN) {
			u8 rm[8];
			if (got < 8) goto bad;
			got -= 8;
			ev2Mac(*st, rx, got, rm);
			if (memcmp(rm, rx + got, 8)) goto bad;
		}
		if (encRx && got) {
			u8 iv[16];
			if (got % 16) goto bad;
			ev2Iv(false, iv);
			dfCbc(&ses.c, iv, rx, got, false);
			while (got && !rx[got - 1]) got--;
			if (!got || rx[got - 1] != 0x80) goto bad;
			got--;
		}
		ses.on = true;
	} else if (on && ok && !(c[0] == 0xC4 && (c[1] & 0x3F) == ses.keyNo) && ses.d40) {
		if (encRx && got) {
			u8 iv[8] = { 0 };
			if (got % 8) goto bad;
			dfCbc(&ses.c, iv, rx, got, false);
			int l = crc16Pos(rx, got);
			if (l < 0) goto bad;
			got = l;
		} else if (comm == DF_MACED && readCmd(c[0]) && got > 4) {
			u8 rm[4];
			got -= 4;
			d40Mac(rx, got, rm);
			if (memcmp(rm, rx + got, 4)) goto bad;
		}
		ses.on = true;
	} else if (on && ok && !(c[0] == 0xC4 && (c[1] & 0x3F) == ses.keyNo)) {
		if (encRx) {
			int l = got >= bs && !(got % bs) ? (dfCbc(&ses.c, ses.iv, rx, got, false), crcPos(rx, got, bs, *st)) : -1;
			if (l < 0) goto bad;
			got = l;
		} else {
			u8 rm[8];
			if (got < 8) goto bad;
			got -= 8;
			memcpy(rm, rx + got, 8);
			rx[got] = *st;
			dfCmac(&ses.c, ses.iv, rx, got + 1, mac);
			if (memcmp(mac, rm, 8)) goto bad;
		}
		ses.on = true;
	}
	u32 m = got < max ? got : max;
	memcpy(out, rx, m);
	return m;
bad:
	*st = DF_ST_MAC;
	return 0;
}

#define RUNC(c, len, hdr, comm, out, max) ({ \
	int r_ = dfCmd(c, len, hdr, comm, out, max, &st); \
	if (r_ == -2) FAIL(-1, "monitor"); \
	if (r_ == -1) return 0; \
	r_; })
#define RUN(c, len, out, max) RUNC(c, len, 0, DF_PLAIN, out, max)

static bool halvesEqual(const u8 *k)
{
	for (int i = 0; i < 8; i++)
		if ((k[i] ^ k[i + 8]) & 0xFE) return false;
	return true;
}

// AuthenticateEV2First (71): RndB and RndA||rol(RndB) both with IV 0, the answer TI || rol(RndA) ||
// PDcap2 || PCDcap2; session keys CMAC(K, A55A / 5AA5 0001 0080 || RndA/RndB mix), pm3 DesfireGenSessionKeyEV2.
// NonFirst (77, in a running EV2 session): the answer is rol(RndA) alone, TI and CmdCtr carry on.
static int authEv2(u8 k, const DfKey *key, bool first, u8 *st)
{
	DfCipher c;
	dfCipherInit(&c, DF_AES, key->key);
	u8 cmd[3] = { first ? 0x71 : 0x77, k, 0x00 }, a[64], iv[16] = { 0 }, ra[16], rb[16], buf[33];
	int n = isoDepTx(cmd, first ? 3 : 2, a, sizeof(a));
	if (n < 0) FAIL(-1, "monitor");
	if (!n) FAIL(-1, "lost the card: %s", isoDepWhy());
	*st = a[0];
	if (a[0] != 0xAF || n != 17) return 0;
	memcpy(rb, a + 1, 16);
	dfCbc(&c, iv, rb, 16, false);
	rnd(ra, 16);
	buf[0] = 0xAF;
	memcpy(buf + 1, ra, 16);
	memcpy(buf + 17, rb + 1, 15);
	buf[32] = rb[0];
	memset(iv, 0, 16);
	dfCbc(&c, iv, buf + 1, 32, true);
	n = isoDepTx(buf, 33, a, sizeof(a));
	if (n < 0) FAIL(-1, "monitor");
	if (!n) FAIL(-1, "lost the card: %s", isoDepWhy());
	*st = a[0];
	if (a[0] || n != (first ? 33 : 17)) return 0;
	memset(iv, 0, 16);
	dfCbc(&c, iv, a + 1, n - 1, false);
	const u8 *rot = first ? a + 5 : a + 1; // rol(RndA)
	if (memcmp(rot, ra + 1, 15) || rot[15] != ra[0]) {
		*st = DF_ST_MAC;
		return 0;
	}
	u8 sv[32] = { 0xA5, 0x5A, 0x00, 0x01, 0x00, 0x80 }, ke[16], km[16];
	memcpy(sv + 6, ra, 8);
	for (int i = 0; i < 6; i++) sv[8 + i] ^= rb[i];
	memcpy(sv + 14, rb + 6, 10);
	memcpy(sv + 24, ra + 8, 8);
	memset(iv, 0, 16);
	dfCmac(&c, iv, sv, 32, ke);
	sv[0] = 0x5A, sv[1] = 0xA5;
	memset(iv, 0, 16);
	dfCmac(&c, iv, sv, 32, km);
	dfCipherInit(&ses.c, DF_AES, ke);
	dfCipherInit(&ses.mac, DF_AES, km);
	if (first) memcpy(ses.ti, a + 1, 4), ses.ctr = 0;
	ses.keyNo = k, ses.ev2 = ses.on = true;
	return 1;
}

// After a refused one the card still takes another NonFirst (same TI): only ev2 (a TI) is needed.
int dfAuthEv2NonFirst(u8 k, const DfKey *key, u8 *st)
{
	if (!ses.ev2 || key->type != DF_AES) FAIL(0, "no EV2 session to continue");
	ses.on = false;
	int r = authEv2(k, key, false, st);
	if (r <= 0) ses.on = false;
	return r;
}

int dfAuth(u8 k, const DfKey *key, u8 how, u8 *st)
{
	ses.on = ses.ev2 = ses.d40 = false;
	if (how == DF_AUTH_EV2 && key->type == DF_AES) return authEv2(k, key, true, st);
	bool d40 = how == DF_AUTH_D40 && key->type == DF_2K3DES;
	DfCipher c;
	dfCipherInit(&c, key->type, key->key);
	u8 rl = key->type == DF_2K3DES ? 8 : 16, cmd[2] = { d40 ? 0x0A : key->type == DF_AES ? 0xAA : 0x1A, k };
	u8 a[64], iv[16] = { 0 }, ra[16], rb[16], buf[33];
	int n = isoDepTx(cmd, 2, a, sizeof(a));
	if (n < 0) FAIL(-1, "monitor");
	if (!n) FAIL(-1, "lost the card: %s", isoDepWhy());
	*st = a[0];
	if (a[0] != 0xAF || n != 1 + rl) return 0;
	memcpy(rb, a + 1, rl);
	dfCbc(&c, iv, rb, rl, false);
	rnd(ra, rl);
	buf[0] = 0xAF;
	memcpy(buf + 1, ra, rl);
	memcpy(buf + 1 + rl, rb + 1, rl - 1);
	buf[2 * rl] = rb[0];
	if (d40) d40Send(&c, buf + 1, 2 * rl), memset(iv, 0, 8); // the answer from IV 0 too
	else dfCbc(&c, iv, buf + 1, 2 * rl, true);
	n = isoDepTx(buf, 1 + 2 * rl, a, sizeof(a));
	if (n < 0) FAIL(-1, "monitor");
	if (!n) FAIL(-1, "lost the card: %s", isoDepWhy());
	*st = a[0];
	if (a[0] || n != 1 + rl) return 0;
	dfCbc(&c, iv, a + 1, rl, false);
	if (memcmp(a + 1, ra + 1, rl - 1) || a[rl] != ra[0]) {
		*st = DF_ST_MAC;
		return 0;
	}
	// session key (pm3 DesfireGenSessionKeyEV1)
	u8 sk[24];
	memcpy(sk, ra, 4), memcpy(sk + 4, rb, 4);
	if (key->type == DF_2K3DES) {
		if (halvesEqual(key->key)) memcpy(sk + 8, sk, 8);
		else memcpy(sk + 8, ra + 4, 4), memcpy(sk + 12, rb + 4, 4);
	} else if (key->type == DF_3K3DES) {
		memcpy(sk + 8, ra + 6, 4), memcpy(sk + 12, rb + 6, 4);
		memcpy(sk + 16, ra + 12, 4), memcpy(sk + 20, rb + 12, 4);
	} else {
		memcpy(sk + 8, ra + 12, 4), memcpy(sk + 12, rb + 12, 4);
	}
	dfCipherInit(&ses.c, key->type, sk);
	memset(ses.iv, 0, sizeof(ses.iv));
	ses.keyNo = k, ses.on = true, ses.d40 = d40;
	return 1;
}

int dfChangeKey(u8 k, const DfKey *key, u8 ver, const DfKey *old, bool picc, u8 *st)
{
	if (!ses.on) FAIL(0, "not authenticated");
	u8 c[64] = { 0xC4, k }, *cd = c + 2;
	u32 kl = dfKeyLen(key->type), n = kl;
	if (picc) c[1] |= (key->type == DF_AES ? 2 : key->type == DF_3K3DES ? 1 : 0) << 6;
	memcpy(cd, key->key, kl);
	bool other = k != ses.keyNo;
	if (other)
		for (u32 i = 0; i < kl; i++) cd[i] ^= old->key[i];
	if (key->type == DF_AES) cd[n++] = ver;
	if (ses.d40) { // pm3 DesfireChangeKey: CRC16 over the cryptogram so far, CRC16 of the new key
		iso14aCrc(cd, n, cd + n), n += 2;
		if (other) iso14aCrc(key->key, kl, cd + n), n += 2;
	} else {
		if (!ses.ev2) put32(cd + n, dfCrc32(c, 2 + n)), n += 4;
		if (other) put32(cd + n, dfCrc32(key->key, kl)), n += 4;
	}
	u8 out[8];
	int r = dfCmd(c, 2 + n, 1, DF_ENC, out, sizeof(out), st);
	if (r == -2) FAIL(-1, "monitor");
	if (r == -1) return -1;
	return !*st;
}

void dfKeyHex(const DfKey *k, char *out)
{
	int n = k->type == DF_2K3DES && halvesEqual(k->key) && !memcmp(k->key, k->key + 8, 8) ? 8 : dfKeyLen(k->type);
	for (int i = 0; i < n; i++) sprintf(out + 2 * i, "%02X", k->key[i]);
	if (!n) *out = 0;
}

const char *dfKeyName(const DfKey *k)
{
	return k->type == DF_2K3DES && halvesEqual(k->key) ? "DES" : dfKeyTypeName(k->type);
}

// --- key dictionary ---

typedef struct {
	u8 len, key[24];
} DictKey;

static DictKey dict[256];
static int ndict;
static u8 authHow; // dfReadInfo: DF_AUTH_* for this card (dfAuthHow)

static const char *const defaultKeys[] = {
	"00000000000000000000000000000000", "000000000000000000000000000000000000000000000000",
	"FFFFFFFFFFFFFFFF", "0011223344556677", "1122334455667788", "A0A1A2A3A4A5A6A7", "D3F7D3F7D3F7D3F7",
	"7544D1652BC9BD43", "00112233445566778899AABBCCDDEEFF", "000102030405060708090A0B0C0D0E0F",
	"404142434445464748494A4B4C4D4E4F", "A0A1A2A3A4A5A6A7A8A9AAABACADAEAF", "B0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF",
	"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", "425245414B4D454946594F5543414E21",
	"00112233445566778899AABBCCDDEEFF0102030405060708", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
};

static int hexVal(char c)
{
	return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
}

// A key from hex (8 bytes = DES, stored as 2K3DES with equal halves); duplicates skipped.
static void addDict(const char *s)
{
	DictKey k = { 0 };
	int d = 0;
	for (; *s && *s != '#' && d < 49; s++) {
		int v = hexVal(*s);
		if (v < 0) continue;
		if (d < 48) k.key[d / 2] = d & 1 ? k.key[d / 2] | v : v << 4;
		d++;
	}
	if (d != 16 && d != 32 && d != 48) return;
	k.len = d / 2;
	if (k.len == 8) memcpy(k.key + 8, k.key, 8), k.len = 16;
	for (int i = 0; i < ndict; i++)
		if (dict[i].len == k.len && !memcmp(dict[i].key, k.key, k.len)) return;
	if (ndict < (int)(sizeof(dict) / sizeof(dict[0]))) dict[ndict++] = k;
}

static void loadDict(void)
{
	ndict = 0;
	for (u32 i = 0; i < sizeof(defaultKeys) / sizeof(defaultKeys[0]); i++) addDict(defaultKeys[i]);
	static const char *const files[] = { DF_KEYS, DF_PM3_KEYS };
	for (int i = 0; i < 2; i++) {
		FILE *f = fopen(files[i], "r");
		if (!f) continue;
		char line[160];
		while (fgets(line, sizeof(line), f)) addDict(line);
		fclose(f);
	}
}

// The dictionary on key k of the selected application (PICC), of type kt (GetKeySettings bits 6-7,
// -1 = unknown: all). 1 = found (into *out, the session runs on it), 0 = not, -1 = lost card / monitor.
static int findKey(u8 k, int kt, DfKey *out)
{
	static const u8 order[] = { DF_AES, DF_2K3DES, DF_3K3DES };
	for (int t = 0; t < 3; t++) {
		u8 type = order[t];
		if (kt >= 0 && type != (kt == 2 ? DF_AES : kt == 1 ? DF_3K3DES : DF_2K3DES)) continue;
		for (int i = 0; i < ndict; i++) {
			if (mfCancel) return 0;
			if (dict[i].len != dfKeyLen(type)) continue;
			DfKey c = { true, type };
			memcpy(c.key, dict[i].key, dict[i].len);
			u8 st;
			int r = dfAuth(k, &c, authHow, &st);
			if (r < 0) return -1;
			if (r) {
				*out = c;
				return 1;
			}
			if (st == 0x40 || st == 0x9D) return 0; // no such key / not allowed: no key will do
		}
	}
	return 0;
}

static void loadDict(void);
static int selectApp(u32 aid, u8 *st);

// --- operations ---

bool dfRandomUid(const Card *c)
{
	return c->uidLen == 4 && c->uid[0] == 0x08;
}

bool dfUsesEv2(const DfInfo *d)
{
	return d->ver[1] == 0x01 && d->ver[3] >= 0x12 && d->ver[3] != 0x30;
}

u8 dfAuthHow(const DfInfo *d)
{
	if (d->ver[1] == 0x01 && d->ver[3] == 0x00) return DF_AUTH_D40;
	return dfUsesEv2(d) ? DF_AUTH_EV2 : DF_AUTH_EV1;
}

bool dfRememberKey(const DfKey *k)
{
	loadDict();
	u8 len = dfKeyLen(k->type);
	for (int i = 0; i < ndict; i++)
		if (dict[i].len == len && !memcmp(dict[i].key, k->key, len)) return true;
	mkdir(MF_DIR, 0777);
	mkdir(DF_DIR, 0777);
	FILE *f = fopen(DF_KEYS, "a");
	if (!f) return false;
	char hex[49];
	for (int i = 0; i < len; i++) sprintf(hex + 2 * i, "%02X", k->key[i]);
	fprintf(f, "%s # %s\n", hex, dfKeyTypeName(k->type));
	return !fclose(f);
}

// ISO-DEP, select, authenticate: the common start of an operation.
static int opStart(const DfInfo *d, u32 aid, u8 k, const DfKey *key)
{
	u8 ats[32], st;
	ses.on = false;
	int r = isoDepActivate(ats, sizeof(ats));
	if (r <= 0) FAIL(r, "%s", isoDepWhy());
	if ((r = selectApp(aid, &st)) <= 0) return r;
	if (st) FAIL(0, "select %06lX: %s", aid, dfStatusName(st));
	if (!key) return 1;
	if ((r = dfAuth(k, key, dfAuthHow(d), &st)) < 0) return r;
	if (!r) FAIL(0, "key %d: %s", k, dfStatusName(st));
	return 1;
}

int dfOpAuth(const DfInfo *d, u32 aid, u8 k, const DfKey *key)
{
	return opStart(d, aid, k, key);
}

u8 dfTmac[12], dfTmacLen;

int dfOp(const DfInfo *d, u32 aid, u8 k, const DfKey *key, const u8 *c, u32 len, u32 hdr, u8 comm, u8 flags)
{
	u8 out[64], st;
	dfTmacLen = 0;
	int r = opStart(d, aid, k, key);
	if (r <= 0) return r;
	if ((r = dfCmd(c, len, hdr, comm, out, sizeof(out), &st)) == -2) FAIL(-1, "monitor");
	if (r < 0) return 0;
	if (st) FAIL(0, "%s", dfStatusName(st));
	if (!(flags & DF_COMMIT)) return 1;
	if (flags & DF_READER_ID) { // answers the previous reader ID, encrypted with a TM session key
		u8 rid[17] = { 0xC8, 'P', 'r', 'o', 'x', '3', 'D', 'S' };
		if ((r = dfCmd(rid, 17, 0, DF_MACED, out, sizeof(out), &st)) == -2) FAIL(-1, "monitor");
		if (r < 0) return 0;
		if (st) FAIL(0, "CommitReaderID: %s", dfStatusName(st));
	}
	u8 cc[2] = { 0xC7, 0x01 };
	u32 cl = flags & DF_TMAC ? 2 : 1;
	if ((r = dfCmd(cc, cl, cl - 1, DF_PLAIN, out, sizeof(out), &st)) == -2) FAIL(-1, "monitor");
	if (r < 0) return 0;
	if (st) FAIL(0, "commit: %s", dfStatusName(st));
	if ((flags & DF_TMAC) && r >= 12) memcpy(dfTmac, out, 12), dfTmacLen = 12;
	return 1;
}

int dfApdu(const u8 *apdu, u32 len, u8 *out, u32 max, u16 *sw)
{
	u8 a[300];
	int n = isoDepTx(apdu, len, a, sizeof(a));
	if (n < 0) return -2;
	if (n < 2) FAIL(-1, "lost the card: %s", isoDepWhy());
	*sw = a[n - 2] << 8 | a[n - 1];
	u32 m = (u32)n - 2 < max ? (u32)n - 2 : max;
	memcpy(out, a, m);
	return m;
}

#define APDU(c, len, out, max) ({ \
	int r_ = dfApdu(c, len, out, max, &sw); \
	if (r_ == -2) FAIL(-1, "monitor"); \
	if (r_ < 0) return 0; \
	r_; })

int dfIsoRead(DfInfo *d, const DfApp *a, DfIsoEf *efs, int max)
{
	u8 ats[32], st, buf[64], c[24];
	u16 sw;
	ses.on = false;
	int r = isoDepActivate(ats, sizeof(ats));
	if (r <= 0) FAIL(r, "%s", isoDepWhy());
	if ((r = selectApp(a->aid, &st)) <= 0) return r;
	if (st) FAIL(0, "select %06lX: %s", a->aid, dfStatusName(st));
	c[0] = 0x61; // GetISOFileIDs: 2 bytes each, LSB first
	int n = RUN(c, 1, buf, sizeof(buf));
	if (st) FAIL(0, "GetISOFileIDs: %s", dfStatusName(st));
	if (!n) FAIL(0, "no file has an ISO FID");
	// SELECT the application: by DF name, else by its ISO FID
	u32 l;
	if (a->nameLen) {
		u8 s[5] = { 0x00, 0xA4, 0x04, 0x0C, a->nameLen };
		memcpy(c, s, 5), memcpy(c + 5, a->name, a->nameLen), l = 5 + a->nameLen;
	} else {
		u8 s[7] = { 0x00, 0xA4, 0x00, 0x0C, 0x02, a->isoFid >> 8, a->isoFid };
		memcpy(c, s, 7), l = 7;
	}
	APDU(c, l, buf + 32, 32);
	if (sw != 0x9000) FAIL(0, "ISO SELECT of the application: SW %04X", sw);
	int count = 0;
	for (int i = 0; i + 1 < n && count < max; i += 2) {
		DfIsoEf *e = &efs[count++];
		memset(e, 0, sizeof(*e));
		e->fid = buf[i] | buf[i + 1] << 8;
		u8 sel[7] = { 0x00, 0xA4, 0x02, 0x0C, 0x02, e->fid >> 8, e->fid };
		APDU(sel, 7, c, sizeof(c));
		if ((e->sw = sw) != 0x9000) continue;
		u32 room = sizeof(d->pool) - d->poolUsed;
		u8 *p = d->pool + d->poolUsed;
		u8 rb[5] = { 0x00, 0xB0, 0x00, 0x00, 0x00 };
		int k = APDU(rb, 5, p, room < DF_MAX_DATA ? room : DF_MAX_DATA);
		e->sw = sw;
		if (sw == 0x6981 || sw == 0x6985) { // not a binary file (DESFire says 6985): its records, 1 on
			e->records = true;
			u32 got = 0;
			for (int rec = 1; rec < 256 && got < DF_MAX_DATA && got < room; rec++) {
				u8 rr[5] = { 0x00, 0xB2, rec, 0x04, 0x00 };
				k = APDU(rr, 5, p + got, room - got < DF_MAX_DATA - got ? room - got : DF_MAX_DATA - got);
				if (sw != 0x9000) break;
				got += k, e->records_n++;
			}
			if (!e->records_n) e->records = false; // keep READ BINARY's answer
			else e->sw = 0x9000;
			k = got;
		}
		if (e->sw != 0x9000) continue;
		e->dataOff = d->poolUsed, e->dataLen = k;
		d->poolUsed += k;
	}
	return count;
}

int dfOpChangeKey(const DfInfo *d, u32 aid, u8 authK, const DfKey *authKey, u8 k, const DfKey *key, u8 ver,
	const DfKey *old, bool picc)
{
	u8 st;
	int r = opStart(d, aid, authK, authKey);
	if (r <= 0) return r;
	if ((r = dfChangeKey(k, key, ver, old, picc, &st)) < 0) return r;
	if (!r) FAIL(0, "ChangeKey: %s", dfStatusName(st));
	dfRememberKey(key);
	return 1;
}

// --- reading ---

static DfApp *findApp(DfInfo *d, u32 aid)
{
	for (int i = 0; i < d->napps && i < DF_MAX_APPS; i++)
		if (d->apps[i].aid == aid) return &d->apps[i];
	return NULL;
}

static u32 le24(const u8 *p)
{
	return p[0] | p[1] << 8 | p[2] << 16;
}

// A transaction MAC file's read/write right is its CommitReaderID key: only read counts there.
bool dfFreeRead(const DfFile *f)
{
	return !f->st && f->len >= 4 && ((f->set[3] >> 4) == 0xE || (f->set[0] != 5 && (f->set[2] >> 4) == 0xE));
}

// ReadData / GetValue / ReadRecords into the pool, in comm mode comm.
static int readFile(DfInfo *d, DfFile *f, u8 comm)
{
	u8 c[8] = { 0xBD, f->fid }, st, t = f->set[0];
	u32 len = 2, room = sizeof(d->pool) - d->poolUsed, want = DF_MAX_DATA;
	if (t <= 1) { // offset 0, length (24 bit)
		u32 size = f->len >= 7 ? le24(f->set + 4) : 0;
		want = size < DF_MAX_DATA ? size : DF_MAX_DATA;
		c[5] = want, c[6] = want >> 8, len = 8;
	} else if (t == 2) {
		c[0] = 0x6C, want = 4;
	} else if (t == 5) { // transaction MAC: TMC (4) || TMV (8)
		c[5] = 12, len = 8, want = 12;
	} else if ((t == 3 || t == 4) && f->len >= 13) { // offset 0, as many records as fit
		u32 rs = le24(f->set + 4), cnt = le24(f->set + 10);
		if (rs && cnt > DF_MAX_DATA / rs) cnt = DF_MAX_DATA / rs;
		c[0] = 0xBB, c[5] = cnt, len = 8, want = cnt * rs;
	} else {
		return 1;
	}
	if (!want || room < want) return 1;
	int n = RUNC(c, len, len - 1, comm, d->pool + d->poolUsed, want);
	f->hasData = true, f->dataSt = st;
	if (st) return 1;
	f->dataOff = d->poolUsed, f->dataLen = n;
	d->poolUsed += n;
	return 1;
}

static int selectApp(u32 aid, u8 *st)
{
	u8 c[4] = { 0x5A, aid, aid >> 8, aid >> 16 }, buf[16];
	int r = dfCmd(c, 4, 0, DF_PLAIN, buf, sizeof(buf), st);
	if (r == -2) FAIL(-1, "monitor");
	return r < 0 ? 0 : 1;
}

// Key settings, key versions, file IDs and file settings, in the current state (session or not).
static int appBasics(DfApp *a)
{
	u8 c[2] = { 0x45 }, buf[96], st;
	int n = RUN(c, 1, buf, sizeof(buf));
	a->keySt = st ? st : n < 2 ? 0x7E : 0;
	a->nKeyVer = 0;
	if (!a->keySt) {
		a->keySet = buf[0], a->maxKeys = buf[1];
		for (int k = 0; k < (a->maxKeys & 0xF) && k < 14; k++) {
			c[0] = 0x64, c[1] = k;
			if (RUN(c, 2, buf, sizeof(buf)) < 1 || st) break;
			a->keyVer[a->nKeyVer++] = buf[0];
		}
	}
	c[0] = 0x6F;
	n = RUN(c, 1, buf, sizeof(buf));
	if ((a->fileSt = st)) return 1;
	a->nfiles = n < DF_MAX_FILES ? n : DF_MAX_FILES;
	for (int i = 0; i < a->nfiles; i++) {
		DfFile *f = &a->files[i];
		memset(f, 0, sizeof(*f));
		f->fid = buf[i];
		u8 fc[2] = { 0xF5, f->fid };
		n = RUNC(fc, 2, 1, DF_PLAIN, f->set, sizeof(f->set));
		f->st = st, f->len = n;
	}
	return 1;
}

// The key that reads f (read, then read/write; value files also write), -1 = none known.
static int readKey(const DfApp *a, const DfFile *f)
{
	if (f->st || f->len < 4) return -1;
	u8 ks[3] = { f->set[3] >> 4, f->set[2] >> 4, f->set[3] & 0xF };
	for (int i = 0; i < (f->set[0] == 2 ? 3 : f->set[0] == 5 ? 1 : 2); i++)
		if (ks[i] < 14 && a->keys[ks[i]].known) return ks[i];
	return -1;
}

static int readApp(DfInfo *d, DfApp *a, bool keys)
{
	u8 st;
	int r;
	if ((r = selectApp(a->aid, &st)) <= 0) return r;
	if ((a->selSt = st)) return 1;
	if ((r = appBasics(a)) <= 0) return r;
	if (keys) {
		// key 0 first: it may open the key settings (key count, type) and the file list
		if ((r = findKey(0, a->keySt ? -1 : a->maxKeys >> 6, &a->keys[0])) < 0) return r;
		bool denied = a->keySt || a->fileSt;
		for (int i = 0; i < a->nfiles; i++) denied |= a->files[i].st != 0;
		if (r && denied && (r = appBasics(a)) <= 0) return r;
		for (int k = 1; !a->keySt && k < (a->maxKeys & 0xF) && k < 14; k++)
			if ((r = findKey(k, a->maxKeys >> 6, &a->keys[k])) < 0) return r;
	}
	for (int i = 0; i < a->nfiles && !a->fileSt; i++) {
		DfFile *f = &a->files[i];
		int k = dfFreeRead(f) ? 0xE : keys ? readKey(a, f) : -1;
		if (k < 0) continue;
		// a fresh select: free files without a session, keyed ones with their key's
		if ((r = selectApp(a->aid, &st)) <= 0) return r;
		if (k != 0xE) {
			if ((r = dfAuth(k, &a->keys[k], authHow, &st)) < 0) return r;
			if (!r) {
				f->hasData = true, f->dataSt = st, f->dataKey = k;
				continue;
			}
		}
		if ((r = readFile(d, f, k == 0xE || (f->set[1] & 3) == 2 ? DF_PLAIN : f->set[1] & 3)) <= 0) return r;
		f->dataKey = k;
	}
	return 1;
}

int dfReadInfo(DfInfo *d, bool keys)
{
	memset(d, 0, sizeof(*d));
	ses.on = false;
	int r = isoDepActivate(d->ats, sizeof(d->ats));
	if (r <= 0) FAIL(r, "%s", isoDepWhy());
	d->atsLen = d->ats[0] < sizeof(d->ats) ? d->ats[0] : sizeof(d->ats);
	u8 c[4] = { 0x60 }, buf[128], st;
	int n = RUN(c, 1, d->ver, sizeof(d->ver));
	if (st || n < 14) FAIL(0, "GetVersion: %s %02X (not a DESFire)", n < 14 && !st ? "short answer, status" : dfStatusName(st), st);
	d->verLen = n;
	logp("DESFire: %s, %lu bytes\n", dfVersionName(d), dfStorage(d->ver[5]));
	if (keys) {
		loadDict();
		d->keyed = true, d->dictKeys = ndict;
		// EV2 or later DESFire (not Light): EV2 secure messaging for AES keys; MF3ICD40: D40 only
		authHow = dfAuthHow(d);
		d->ev2 = authHow == DF_AUTH_EV2, d->d40 = authHow == DF_AUTH_D40;
	}

	c[0] = 0x6E;
	n = RUN(c, 1, buf, sizeof(buf));
	if (!st && n >= 3) d->hasFree = true, d->freeMem = le24(buf);
	c[0] = 0x45;
	n = RUN(c, 1, buf, sizeof(buf));
	d->keySt = st ? st : n < 2 ? 0x7E : 0;
	if (!d->keySt) d->keySet = buf[0], d->maxKeys = buf[1];
	c[0] = 0x64, c[1] = 0;
	n = RUN(c, 2, buf, sizeof(buf));
	d->keyVerSt = st ? st : n < 1 ? 0x7E : 0;
	if (!d->keyVerSt) d->keyVer = buf[0];
	c[0] = 0x3C, c[1] = 0;
	n = RUN(c, 2, buf, sizeof(buf));
	if ((st == 0x90 || !st) && n >= 56) {
		d->hasSig = true;
		memcpy(d->sig, buf, 56);
	}
	d->randomUid = dfRandomUid(&card);

	if (keys) {
		progOp("PICC master key: dictionary");
		if ((r = findKey(0, d->keySt ? -1 : d->maxKeys >> 6, &d->piccKey)) < 0) return r;
		if (r) logp("PICC master key: %s\n", dfKeyName(&d->piccKey));
		if (r && d->randomUid) { // the session runs on the PICC key: GetCardUID (full)
			c[0] = 0x51;
			n = RUNC(c, 1, 0, DF_FULL, buf, sizeof(buf));
			if (!st && n >= 7) d->hasRealUid = true, memcpy(d->realUid, buf, 7);
			if (!d->hasSig) { // random ID hides the signature too: Read_Sig in the session, encrypted
				c[0] = 0x3C, c[1] = 0;
				n = RUNC(c, 2, 1, DF_FULL, buf, sizeof(buf));
				if (st == 0x90 && n >= 56) d->hasSig = true, memcpy(d->sig, buf, 56);
			}
		}
	}
	// the signature is over the real UID: GetVersion's, unless random ID zeroes it there
	if (d->hasSig) {
		bool zero = true;
		for (int i = 0; i < 7 && d->verLen >= 21; i++) zero &= !d->ver[14 + i];
		const u8 *uid = !zero && d->verLen >= 21 ? d->ver + 14 : d->hasRealUid ? d->realUid : NULL;
		d->sigKey = uid ? nxpSigCheck(SIG_DESFIRE, uid, 7, d->sig, 56) : NULL;
		logp("signature: %s\n", d->sigKey ? d->sigKey : uid ? "NOT verified by an NXP key" : "real UID unknown (random ID)");
	}
	c[0] = 0x6A;
	n = RUN(c, 1, buf, sizeof(buf));
	if ((d->appSt = st)) {
		logp("app list: %s\n", dfStatusName(st));
		return 1;
	}
	d->napps = n / 3;
	for (int i = 0; i < d->napps && i < DF_MAX_APPS; i++) d->apps[i].aid = le24(buf + 3 * i);
	// GetDFNames: one app per frame (AID, ISO FID, DF name), so without a session
	if (ses.on && (r = selectApp(0, &st)) <= 0) return r;
	c[0] = 0x6D;
	for (int i = 0; i < 64; i++) {
		int k = isoDepTx(c, 1, buf, sizeof(buf));
		if (k < 0) FAIL(-1, "monitor");
		if (!k) FAIL(0, "lost the card: %s", isoDepWhy());
		DfApp *a = k >= 6 && (!buf[0] || buf[0] == 0xAF) ? findApp(d, le24(buf + 1)) : NULL;
		if (a) {
			a->hasIso = true;
			a->isoFid = buf[4] | buf[5] << 8;
			a->nameLen = k - 6 < 16 ? k - 6 : 16;
			memcpy(a->name, buf + 6, a->nameLen);
		}
		if (buf[0] != 0xAF) break;
		c[0] = 0xAF;
	}
	for (int i = 0; i < d->napps && i < DF_MAX_APPS; i++) {
		if (mfCancel) break;
		progOp("Application %06lX%s", d->apps[i].aid, keys ? ": keys, files" : "");
		progStep(i, d->napps < DF_MAX_APPS ? d->napps : DF_MAX_APPS);
		if ((r = readApp(d, &d->apps[i], keys)) <= 0) return r;
		logp("app %06lX: %d files\n", d->apps[i].aid, d->apps[i].nfiles);
	}
	return selectApp(0, &st);
}

const char *dfVersionName(const DfInfo *d)
{
	u8 type = d->ver[1], major = d->ver[3], minor = d->ver[4];
	// pm3 mifare_prime_get_version_str
	if (type == 0x01 && major == 0x00) return "DESFire MF3ICD40";
	if (major == 0x10 && minor == 0x00) return "NTAG413DNA";
	if (type == 0x01 && major == 0x01 && minor == 0x00) return "DESFire EV1";
	if (type == 0x01 && (major == 0x12 || major == 0x42) && minor == 0x00) return "DESFire EV2";
	if (type == 0x01 && major == 0x22 && minor == 0x00) return "DESFire EV2 XL";
	if (type == 0x01 && major == 0x33 && minor == 0x00) return "DESFire EV3";
	if (type == 0x81 && major == 0x43 && minor == 0x01) return "DESFire EV3C (P71D600)";
	if (type == 0x01 && major == 0x30 && minor == 0x00) return "DESFire Light";
	if (type == 0x02 && major == 0x11 && minor == 0x00) return "MIFARE Plus EV1";
	if (type == 0x02 && major == 0x22 && minor == 0x00) return "MIFARE Plus EV2";
	if (type == 0x01 && major == 0xA0 && minor == 0x00) return "DESFire DUOX";
	if (type == 0xA1) return "DESFire HCE";
	if (type & 0x08) return "DESFire Light";
	return type == 0x01 ? "DESFire (unknown version)" : type == 0x02 ? "MIFARE Plus" : "unknown NXP type";
}

u32 dfStorage(u8 code)
{
	return 1u << (code >> 1);
}

const char *dfKeyType(u8 maxKeys)
{
	switch (maxKeys >> 6) {
	case 0: return "DES/2K3DES";
	case 1: return "3K3DES";
	case 2: return "AES";
	}
	return "?";
}

void dfFileDesc(const DfFile *f, char *out, u32 max)
{
	static const char *types[] = { "standard", "backup", "value", "linear record", "cyclic record", "transaction MAC" };
	static const char *comm[] = { "plain", "MAC", "plain", "full" };
	const u8 *s = f->set;
	if (f->st || f->len < 4) {
		snprintf(out, max, "settings: %s", f->st ? dfStatusName(f->st) : "short answer");
		return;
	}
	char size[48] = "";
	if (s[0] <= 1 && f->len >= 7) {
		snprintf(size, sizeof(size), ", %lu bytes", le24(s + 4));
	} else if (s[0] == 2 && f->len >= 17) {
		s32 lo, hi;
		memcpy(&lo, s + 4, 4), memcpy(&hi, s + 8, 4);
		snprintf(size, sizeof(size), ", %ld..%ld", lo, hi);
	} else if ((s[0] == 3 || s[0] == 4) && f->len >= 13) {
		snprintf(size, sizeof(size), ", %lu/%lu records x %lu bytes", le24(s + 10), le24(s + 7), le24(s + 4));
	}
	else if (s[0] == 5 && f->len >= 6) {
		snprintf(size, sizeof(size), ", %s key version %02X", s[4] == 2 ? "AES" : "key", s[5]);
	}
	snprintf(out, max, "%s, %s%s%s", s[0] < 6 ? types[s[0]] : "type ?", comm[s[1] & 3],
		s[1] & 0x80 ? " + more access rights" : "", size);
}

static void keyName(u8 k, char *out)
{
	if (k == 0xE) strcpy(out, "free");
	else if (k == 0xF) strcpy(out, "never");
	else sprintf(out, "key %X", k);
}

void dfFileKeys(const DfFile *f, char *out, u32 max)
{
	*out = 0;
	if (f->st || f->len < 4) return;
	u16 ar = f->set[2] | f->set[3] << 8;
	char r[8], w[8], rw[8], ch[8];
	keyName(ar >> 12, r), keyName(ar >> 8 & 0xF, w), keyName(ar >> 4 & 0xF, rw), keyName(ar & 0xF, ch);
	if (f->set[0] == 5) snprintf(out, max, "read %s, CommitReaderID %s, change %s", r, rw, ch);
	else snprintf(out, max, "read %s, write %s, read/write %s, change %s", r, w, rw, ch);
}

static void keySetDesc(FILE *fp, u8 ks, bool picc)
{
	const char *m = picc ? "PICC master key" : "app master key";
	fprintf(fp, "    %s changeable: %s\n", m, ks & 1 ? "yes" : "no");
	fprintf(fp, "    %s list / key settings %s\n", picc ? "AID" : "file", ks & 2 ? "free" : "need the master key");
	fprintf(fp, "    create / delete %s\n", ks & 4 ? "free" : "needs the master key");
	fprintf(fp, "    configuration changeable: %s\n", ks & 8 ? "yes" : "no");
	if (!picc) {
		u8 ck = ks >> 4;
		if (ck == 0xE) fprintf(fp, "    changing a key needs that same key\n");
		else if (ck == 0xF) fprintf(fp, "    keys are frozen (only the master key changes itself)\n");
		else fprintf(fp, "    changing a key needs key %X\n", ck);
	}
}

static void hexLine(FILE *fp, const char *label, const u8 *p, int n)
{
	fprintf(fp, "%s", label);
	for (int i = 0; i < n; i++) fprintf(fp, "%02X", p[i]);
	fprintf(fp, "\n");
}

static void keyLine(FILE *fp, int k, const DfKey *key)
{
	char hex[49];
	dfKeyHex(key, hex);
	if (key->known) fprintf(fp, "  key %d: %s %s\n", k, dfKeyName(key), hex);
	else fprintf(fp, "  key %d: not in the dictionary\n", k);
}

// Hex digits (spaces allowed between bytes) into out; the byte count.
static int unhexLine(const char *s, u8 *out, int max)
{
	int n = 0;
	unsigned v;
	while (n < max) {
		while (*s == ' ') s++;
		if (sscanf(s, "%2x", &v) != 1 || !s[1] || s[1] == ' ' || s[1] == '\n' || s[1] == '\r') break;
		out[n++] = v;
		s += 2;
	}
	return n;
}

// "ok", "permission denied", ... back to the status (dfStatusName); unknown text: AE.
static u8 statusFromName(const char *s)
{
	char t[48];
	snprintf(t, sizeof(t), "%s", s);
	t[strcspn(t, "\r\n")] = 0;
	for (int st = 0; st < 256; st++)
		if (!strcmp(dfStatusName(st), t)) return st;
	return 0xAE;
}

static bool keyFromLine(const char *s, DfKey *k)
{
	char name[16];
	int off;
	if (sscanf(s, "%15s %n", name, &off) != 1) return false;
	int n = unhexLine(s + off, k->key, 24);
	if (!strcmp(name, "AES") && n == 16) k->type = DF_AES;
	else if (!strcmp(name, "3K3DES") && n == 24) k->type = DF_3K3DES;
	else if ((!strcmp(name, "DES") || !strcmp(name, "2K3DES")) && (n == 8 || n == 16)) k->type = DF_2K3DES;
	else return false;
	if (n == 8) memcpy(k->key + 8, k->key, 8);
	return k->known = true;
}

bool dfLoadInfo(DfInfo *d, const char *path)
{
	FILE *fp = fopen(path, "r");
	if (!fp) return false;
	memset(d, 0, sizeof(*d));
	d->keySt = d->keyVerSt = d->appSt = 0xAE; // until the file says otherwise
	char line[512];
	u8 uid[10];
	int uidLen = 0;
	bool ok = false;
	DfApp *a = NULL;
	DfFile *f = NULL;
	unsigned x, y;
	while (fgets(line, sizeof(line), fp)) {
		const char *l = line;
		int k;
		if (sscanf(l, "# Prox3DS DESFire info (key dictionary: %u keys", &x) == 1) { // so a save keeps the keys
			d->keyed = true, d->dictKeys = x;
			d->ev2 = strstr(l, "EV2") != NULL, d->d40 = strstr(l, "D40") != NULL;
		} else if (!strncmp(l, "UID ", 4)) {
			uidLen = unhexLine(l + 4, uid, 10);
			ok = true;
		} else if (!strncmp(l, "random ID on", 12)) {
			d->randomUid = true;
			if (strstr(l, "real UID by GetCardUID")) d->hasRealUid = true;
		} else if (!strncmp(l, "ATS ", 4)) {
			d->atsLen = unhexLine(l + 4, d->ats, sizeof(d->ats));
		} else if (!strncmp(l, "hardware ", 9)) {
			if (unhexLine(l + 9, d->ver, 7) == 7 && d->verLen < 7) d->verLen = 7;
		} else if (!strncmp(l, "software ", 9)) {
			if (unhexLine(l + 9, d->ver + 7, 7) == 7) d->verLen = 21;
		} else if (!strncmp(l, "batch ", 6)) {
			if (unhexLine(l + 6, d->ver + 21, 5) == 5) d->verLen = 28;
		} else if (sscanf(l, "production week %x / 20%x", &x, &y) == 2) {
			d->ver[26] = x, d->ver[27] = y;
		} else if (!strncmp(l, "signature ", 10)) {
			d->hasSig = unhexLine(l + 10, d->sig, 56) == 56;
		} else if (sscanf(l, "free memory %u bytes", &x) == 1) {
			d->hasFree = true, d->freeMem = x;
		} else if (sscanf(l, "Application %x", &x) == 1) {
			a = d->napps < DF_MAX_APPS ? &d->apps[d->napps] : NULL;
			if (a) {
				memset(a, 0, sizeof(*a));
				a->aid = x;
				a->keySt = a->fileSt = 0xAE;
			}
			d->napps++;
			f = NULL;
		} else if (!a) { // the PICC
			if (!strncmp(l, "  key settings: ", 16)) d->keySt = statusFromName(l + 16);
			else if (sscanf(l, "  key settings %x, %d", &x, &k) == 2) {
				d->keySt = 0, d->keySet = x;
				d->maxKeys = k | (strstr(l, "AES") ? 0x80 : strstr(l, "3K3DES") ? 0x40 : 0);
			} else if (sscanf(l, "  key 0 version %x", &x) == 1) d->keyVerSt = 0, d->keyVer = x;
			else if (!strncmp(l, "  key 0: ", 9)) keyFromLine(l + 9, &d->piccKey);
			else if (!strncmp(l, "  applications: ", 16)) d->appSt = statusFromName(l + 16);
			else if (sscanf(l, "  %d application", &k) == 1) d->appSt = 0;
		} else if (a && a - d->apps < DF_MAX_APPS) {
			int n = 0;
			if (sscanf(l, "  ISO FID %x", &x) == 1) {
				a->hasIso = true, a->isoFid = x;
				const char *nm = strstr(l, "DF name ");
				if (nm) a->nameLen = unhexLine(nm + 8, a->name, 16);
			} else if (!strncmp(l, "  select: ", 10)) a->selSt = statusFromName(l + 10);
			else if (!strncmp(l, "  key settings: ", 16)) a->keySt = statusFromName(l + 16);
			else if (sscanf(l, "  key settings %x, %d", &x, &k) == 2) {
				a->keySt = 0, a->keySet = x;
				a->maxKeys = k | (strstr(l, "AES") ? 0x80 : strstr(l, "3K3DES") ? 0x40 : 0);
			} else if (!strncmp(l, "  key versions ", 15)) a->nKeyVer = unhexLine(l + 15, a->keyVer, 14);
			else if (sscanf(l, "  key %d: %n", &k, &n) == 1 && k >= 0 && k < 14) keyFromLine(l + n, &a->keys[k]);
			else if (!strncmp(l, "  files: ", 9)) a->fileSt = statusFromName(l + 9);
			else if (sscanf(l, "  file %x:", &x) == 1) {
				a->fileSt = 0;
				f = a->nfiles < DF_MAX_FILES ? &a->files[a->nfiles++] : NULL;
				if (f) {
					memset(f, 0, sizeof(*f));
					f->fid = x;
					f->dataKey = 0xE;
					const char *st = strstr(l, ": settings: ");
					if (st) f->st = statusFromName(st + 12);
				}
			} else if (f && sscanf(l, "    read with key %x", &x) == 1) {
				f->dataKey = x;
			} else if (f && !strncmp(l, "    contents: ", 14)) {
				f->hasData = true, f->dataSt = statusFromName(l + 14);
			} else if (f && !strncmp(l, "    raw ", 8)) {
				f->len = unhexLine(l + 8, f->set, sizeof(f->set));
			} else if (f && sscanf(l, "    %x:%n", &x, &n) == 1 && n == 9) { // contents, 16 bytes a line
				if (!f->hasData) f->hasData = true, f->dataOff = d->poolUsed;
				u32 room = sizeof(d->pool) - d->poolUsed;
				int got = unhexLine(l + n, d->pool + d->poolUsed, room < 16 ? room : 16);
				d->poolUsed += got, f->dataLen += got;
			}
		}
	}
	fclose(fp);
	if (d->verLen >= 21) memcpy(d->ver + 14, uid, uidLen < 7 ? uidLen : 7);
	if (d->hasRealUid || !d->randomUid) memcpy(d->realUid, uid, 7);
	return ok && d->verLen >= 7;
}

bool dfSaveInfo(const DfInfo *d, char *path, u32 pathMax)
{
	char uid[21] = "";
	bool verZero = true;
	for (int i = 0; i < 7 && d->verLen >= 21; i++) verZero &= !d->ver[14 + i];
	if (d->hasRealUid)
		for (int i = 0; i < 7; i++) sprintf(uid + 2 * i, "%02X", d->realUid[i]);
	else if (d->verLen >= 21 && !verZero)
		for (int i = 0; i < 7; i++) sprintf(uid + 2 * i, "%02X", d->ver[14 + i]);
	else
		for (int i = 0; i < card.uidLen; i++) sprintf(uid + 2 * i, "%02X", card.uid[i]);
	mkdir(MF_DIR, 0777);
	mkdir(DF_DIR, 0777);
	struct stat st;
	snprintf(path, pathMax, DF_DIR "/%s.txt", uid);
	for (int i = 2; !stat(path, &st) && i < 1000; i++) snprintf(path, pathMax, DF_DIR "/%s-%d.txt", uid, i);
	FILE *fp = fopen(path, "w");
	if (!fp) return false;
	const u8 *v = d->ver;
	if (d->keyed) fprintf(fp, "# Prox3DS DESFire info (key dictionary: %d keys, %s secure messaging)\nUID %s\n",
		d->dictKeys, d->d40 ? "D40" : d->ev2 ? "EV2" : "EV1", uid);
	else fprintf(fp, "# Prox3DS DESFire info (no keys)\nUID %s\n", uid);
	if (d->randomUid) fprintf(fp, "random ID on%s\n", d->hasRealUid ? " (real UID by GetCardUID)" : ": real UID unknown (needs the PICC master key)");
	hexLine(fp, "ATS ", d->ats, d->atsLen);
	fprintf(fp, "%s\n", dfVersionName(d));
	hexLine(fp, "hardware ", v, 7);
	fprintf(fp, "  vendor %02X type %02X subtype %02X version %X.%X storage %lu%s bytes protocol %02X\n", v[0], v[1], v[2],
		v[3], v[4], dfStorage(v[5]), v[5] & 1 ? "+" : "", v[6]);
	hexLine(fp, "software ", v + 7, 7);
	fprintf(fp, "  vendor %02X type %02X subtype %02X version %X.%X storage %lu%s bytes protocol %02X\n", v[7], v[8], v[9],
		v[10], v[11], dfStorage(v[12]), v[12] & 1 ? "+" : "", v[13]);
	if (d->verLen >= 28) {
		hexLine(fp, "batch ", v + 21, 5);
		fprintf(fp, "production week %X / 20%02X\n", v[26], v[27]);
	}
	if (d->hasSig) {
		hexLine(fp, "signature ", d->sig, 56);
		fprintf(fp, "  %s%s\n", d->sigKey ? "verified: NXP key " : "NOT verified by any NXP key", d->sigKey ? d->sigKey : "");
	}
	else fprintf(fp, "signature: none\n");
	if (d->hasFree) fprintf(fp, "free memory %lu bytes\n", d->freeMem);
	fprintf(fp, "\nPICC\n");
	if (d->keySt) {
		fprintf(fp, "  key settings: %s\n", dfStatusName(d->keySt));
	} else {
		fprintf(fp, "  key settings %02X, %d %s key%s\n", d->keySet, d->maxKeys & 0xF, dfKeyType(d->maxKeys),
			(d->maxKeys & 0xF) == 1 ? "" : "s");
		keySetDesc(fp, d->keySet, true);
	}
	if (!d->keyVerSt) fprintf(fp, "  key 0 version %02X\n", d->keyVer);
	if (d->keyed) keyLine(fp, 0, &d->piccKey);
	if (d->appSt) fprintf(fp, "  applications: %s\n", dfStatusName(d->appSt));
	else fprintf(fp, "  %d application%s\n", d->napps, d->napps == 1 ? "" : "s");
	for (int i = 0; i < d->napps && i < DF_MAX_APPS; i++) {
		const DfApp *a = &d->apps[i];
		const char *vendor, *name = dfAidName(a->aid, &vendor);
		fprintf(fp, "\nApplication %06lX\n", a->aid);
		if (name) fprintf(fp, "  %s (%s)\n", name, vendor);
		if ((a->aid & 0xF00000) == 0xF00000) fprintf(fp, "  MAD AID %04lX\n", a->aid >> 4 & 0xFFFF);
		if (a->hasIso) {
			fprintf(fp, "  ISO FID %04X", a->isoFid);
			if (a->nameLen) hexLine(fp, ", DF name ", a->name, a->nameLen);
			else fprintf(fp, "\n");
		}
		if (a->selSt) {
			fprintf(fp, "  select: %s\n", dfStatusName(a->selSt));
			continue;
		}
		if (a->keySt) {
			fprintf(fp, "  key settings: %s\n", dfStatusName(a->keySt));
		} else {
			fprintf(fp, "  key settings %02X, %d %s key%s\n", a->keySet, a->maxKeys & 0xF, dfKeyType(a->maxKeys),
				(a->maxKeys & 0xF) == 1 ? "" : "s");
			keySetDesc(fp, a->keySet, false);
			if (a->nKeyVer) hexLine(fp, "  key versions ", a->keyVer, a->nKeyVer);
		}
		for (int k = 0; d->keyed && k < (a->keySt ? 1 : a->maxKeys & 0xF) && k < 14; k++) keyLine(fp, k, &a->keys[k]);
		if (a->fileSt) {
			fprintf(fp, "  files: %s\n", dfStatusName(a->fileSt));
			continue;
		}
		for (int k = 0; k < a->nfiles; k++) {
			char desc[96], keys[80];
			dfFileDesc(&a->files[k], desc, sizeof(desc));
			dfFileKeys(&a->files[k], keys, sizeof(keys));
			fprintf(fp, "  file %02X: %s\n", a->files[k].fid, desc);
			if (*keys) fprintf(fp, "    %s\n", keys);
			const DfFile *f = &a->files[k];
			if (f->hasData && f->dataKey != 0xE) fprintf(fp, "    read with key %X\n", f->dataKey);
			if (f->hasData && f->dataSt) fprintf(fp, "    contents: %s\n", dfStatusName(f->dataSt));
			for (int o = 0; f->hasData && !f->dataSt && o < f->dataLen; o += 16) {
				fprintf(fp, "    %04X:", o);
				for (int i = o; i < o + 16 && i < f->dataLen; i++) fprintf(fp, " %02X", d->pool[f->dataOff + i]);
				fprintf(fp, "\n");
			}
			if (a->files[k].len) hexLine(fp, "    raw ", a->files[k].set, a->files[k].len);
		}
	}
	return !fclose(fp);
}
