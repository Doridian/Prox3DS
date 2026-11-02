// HID iClass reader over the chip monitor, see iclass.h and NOTES.md "NFC-V / iClass".

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "iclass.h"
#include "mfc.h"
#include "mon.h"
#include "nfchw.h"
#include "probe.h"

#define MS(x) ((s64)(x) * 1000000LL)

IcCard icCard;

static const u8 setDatarate[] = { 0x10, 0x20, 0x02, 0x04, 0x01, 0xB7, 0x01, 0x02 }; // I93_DATARATE 2: 1-of-4
static const u8 discoverMapV[] = { 0x10, 0x21, 0x00, 0x04, 0x01, 0x83, 0x01, 0x83 };
static const u8 discoverV[]    = { 0x10, 0x21, 0x03, 0x03, 0x01, 0x76, 0x01 };
static const u8 deactivate[]   = { 0x10, 0x21, 0x06, 0x01, 0x00 };

// The ROM's V tech setup, which the stall skips: analog (RX), coder 18 at high rate (5), no HW CRC.
static const struct {
	u32 reg, val;
} vRegs[] = { { 0x5C440, 0x08 }, { 0x5C444, 0xD5 }, { 0x5C448, 0x1C }, { 0x5C44C, 0x9A }, { 0x5C48C, 0x18 },
	{ 0x5C53C, 0x01 }, { 0x5C554, 0x18 }, { 0x5C558, 0x05 }, { 0x5C560, 0x0C } };

static void nciCmd(const u8 *c, u32 len)
{
	u8 pkt[0x100];
	i2cNfcWrite(c, len);
	while (nciRecv(pkt, sizeof(pkt), 25, false));
}

bool icStart(void)
{
	u8 pkt[0x100];
	if (!monLoad()) return false;
	nciCmd(setDatarate, sizeof(setDatarate));
	nciCmd(discoverMapV, sizeof(discoverMapV));
	if (!monCapture(true)) return false;
	i2cNfcWrite(discoverV, sizeof(discoverV)); // with capture on the ROM stalls in the poll: no answer needed
	svcSleepThread(MS(300));
	while (nciRecv(pkt, sizeof(pkt), 5, false));
	for (u32 i = 0; i < sizeof(vRegs) / sizeof(vRegs[0]); i++)
		if (!monWrite32(vRegs[i].reg, vRegs[i].val)) return false;
	return true;
}

void icStop(void)
{
	monCapture(false);
	nciCmd(deactivate, sizeof(deactivate));
}

int icXfer(const u8 *tx, u32 len, u8 *rx, u32 max)
{
	MonFrame f[8];
	if (monFrames(f, 8) < 0) return -1; // drop stale
	if (!monTxschedRegs(tx, len, len << 4, 1, 5, 0x88, NULL, 0)) return -1;
	// iClass answers ~0.3 ms after the frame; a monitor round trip is longer
	for (int i = 0; i < 4; i++) {
		int n = monFrames(f, 8);
		if (n < 0) return -1;
		if (n > 0) {
			u32 l = f[n - 1].len < max ? f[n - 1].len : max;
			memcpy(rx, f[n - 1].data, l);
			return l;
		}
		svcSleepThread(MS(1));
	}
	return 0;
}

bool icSelect(u8 csn[8])
{
	u8 b[16], asn[10];
	icXfer((const u8[]){ IC_ACTALL }, 1, b, sizeof(b)); // answers an SOF only
	if (icXfer((const u8[]){ IC_IDENTIFY }, 1, asn, sizeof(asn)) != 10 || !icCrcOk(asn, 10)) return false;
	u8 sel[9] = { IC_SELECT };
	memcpy(sel + 1, asn, 8);
	if (icXfer(sel, 9, b, sizeof(b)) != 10 || !icCrcOk(b, 10)) return false;
	memcpy(csn, b, 8);
	return true;
}

bool icWait(u8 csn[8], u32 timeoutMs)
{
	u64 start = osGetTime();
	while (!mfCancel && (!timeoutMs || osGetTime() - start < timeoutMs)) {
		if (!icStart()) {
			logp("  (iclass: monitor load failed)\n");
			continue;
		}
		u64 t0 = osGetTime();
		while (!mfCancel && osGetTime() - t0 < 4000) {
			if (icSelect(csn)) return true;
			svcSleepThread(MS(50));
		}
	}
	return false;
}

bool icRead(u8 block, u8 out[8])
{
	u8 cmd[4] = { IC_READ, block }, b[16];
	icCrc(cmd + 1, 1, cmd + 2);
	for (int t = 0; t < 3; t++)
		if (icXfer(cmd, 4, b, sizeof(b)) == 10 && icCrcOk(b, 10)) {
			memcpy(out, b, 8);
			return true;
		}
	return false;
}

int icAuth(const u8 div[8], bool kc)
{
	u8 cc[16], ccnr[12] = { 0 }, chk[9] = { IC_CHECK }, tmac[8], want[4];
	int n = icXfer((const u8[]){ kc ? IC_READCHECK_KC : IC_READCHECK_KD, 2 }, 2, cc, sizeof(cc));
	if (n < 0) return -1;
	if (n < 8) return -1; // the card always answers READCHECK
	memcpy(ccnr, cc, 8); // NR = 0
	icReaderMac(div, ccnr, chk + 5);
	n = icXfer(chk, 9, tmac, sizeof(tmac));
	if (n < 0) return -1;
	if (n < 4) return 0; // a wrong MAC gets no answer
	icTagMac(div, ccnr, want);
	return !memcmp(tmac, want, 4);
}

// --- key search ---

typedef struct {
	u8 key[8];
	int kind;
	char label[48];
} Cand;

static int addCand(Cand *c, int n, int max, const u8 *key, int kind, const char *label)
{
	if (n >= max) return n;
	memcpy(c[n].key, key, 8);
	c[n].kind = kind;
	snprintf(c[n].label, sizeof(c[n].label), "%s", label);
	return n + 1;
}

static bool hex8(const char *s, u8 out[8])
{
	for (int i = 0; i < 8; i++) {
		unsigned v;
		if (sscanf(s + 2 * i, "%2x", &v) != 1) return false;
		out[i] = v;
	}
	return true;
}

// Remembered diversified keys for this CSN, then ICLASS_KEYS.
static int fileCands(const u8 csn[8], bool kc, Cand *c, int n, int max)
{
	char line[128], want[17];
	for (int i = 0; i < 8; i++) sprintf(want + 2 * i, "%02X", csn[i]);
	FILE *f = fopen(ICLASS_KNOWN, "r");
	if (f) {
		while (fgets(line, sizeof(line), f)) {
			u8 k[8];
			char *p = line + 17 + (kc ? 17 : 0);
			if (strncasecmp(line, want, 16) || strlen(line) < 50 || !hex8(p, k)) continue;
			if (strncmp(p, "0000000000000000", 16)) n = addCand(c, n, max, k, IC_KEY_DIV, "remembered for this card");
		}
		fclose(f);
	}
	f = fopen(ICLASS_KEYS, "r");
	if (f) {
		while (fgets(line, sizeof(line), f)) {
			u8 k[8];
			if (line[0] == '#' || !hex8(line, k)) continue;
			char *p = line + 16, kindc = 's';
			while (*p == ' ' || *p == '\t') p++;
			if ((*p == 's' || *p == 'e' || *p == 'd') && (p[1] == ' ' || p[1] == '\t' || p[1] == '\n' || p[1] == '\r' || !p[1]))
				kindc = *p, p += 1;
			while (*p == ' ' || *p == '\t') p++;
			p[strcspn(p, "\r\n")] = 0;
			char label[48];
			snprintf(label, sizeof(label), "keys.txt%s%.36s", *p ? ": " : "", p);
			if (kindc == 'd') n = addCand(c, n, max, k, IC_KEY_DIV, label);
			else {
				n = addCand(c, n, max, k, kindc == 'e' ? IC_KEY_ELITE : IC_KEY_STD, label);
				n = addCand(c, n, max, k, kindc == 'e' ? IC_KEY_STD : IC_KEY_ELITE, label);
			}
		}
		fclose(f);
	}
	return n;
}

// Tries candidates; the dictionary is walked after the explicit ones. -> 1 found, 0 none, -1 lost.
static int findKey(IcCard *card, bool kc, const u8 *key, int kind)
{
	static Cand cand[96];
	int n = 0;
	if (key) n = addCand(cand, n, 96, key, kind, "given");
	else n = fileCands(card->csn, kc, cand, 0, 96);
	const IcDicts *d = icDicts();
	int total = n + (key ? 0 : 2 * d->ndef + d->nelite);
	progOp("Trying %s keys", kc ? "Kc (credit)" : "Kd (debit)");
	for (int i = 0; i < total && !mfCancel; i++) {
		u8 master[8], div[8];
		int k;
		char label[48];
		if (i < n) {
			memcpy(master, cand[i].key, 8), k = cand[i].kind;
			snprintf(label, sizeof(label), "%s", cand[i].label);
		} else if (i < n + 2 * d->ndef) {
			const IcDictKey *e = &d->def[(i - n) / 2];
			memcpy(master, e->key, 8), k = (i - n) & 1 ? IC_KEY_ELITE : IC_KEY_STD;
			snprintf(label, sizeof(label), "default%s%s", e->label[0] ? ": " : "", e->label);
		} else {
			memcpy(master, d->elite[i - n - 2 * d->ndef], 8), k = IC_KEY_ELITE;
			snprintf(label, sizeof(label), "elite dictionary");
		}
		if (i % 8 == 0) progStep(i, total);
		icDivKey(card->csn, master, k, div);
		card->keysTried++;
		int r = icAuth(div, kc);
		if (r < 0) {
			// lost or a glitch: reselect once and retry this key
			u8 csn[8];
			if (!icSelect(csn) || memcmp(csn, card->csn, 8)) return -1;
			r = icAuth(div, kc);
			if (r < 0) return -1;
		}
		if (r == 1) {
			memcpy(kc ? card->kc : card->kd, div, 8);
			memcpy(kc ? card->kcMaster : card->kdMaster, master, 8);
			*(kc ? &card->kcKind : &card->kdKind) = k;
			snprintf(kc ? card->kcLabel : card->kdLabel, sizeof(card->kdLabel), "%s", label);
			*(kc ? &card->kcKnown : &card->kdKnown) = true;
			logp("iclass: %s = %02X%02X%02X%02X%02X%02X%02X%02X (%s, %s)\n", kc ? "Kc" : "Kd", div[0], div[1], div[2],
				div[3], div[4], div[5], div[6], div[7], k == IC_KEY_DIV ? "diversified" : k == IC_KEY_ELITE ? "elite" : "standard", label);
			return 1;
		}
	}
	return 0;
}

static void remember(const IcCard *c)
{
	mkdir(MF_DIR, 0777);
	mkdir(ICLASS_DIR, 0777);
	char line[64], csn[17];
	for (int i = 0; i < 8; i++) sprintf(csn + 2 * i, "%02X", c->csn[i]);
	// keep the other cards' lines
	static char rest[8192];
	u32 len = 0;
	FILE *f = fopen(ICLASS_KNOWN, "r");
	if (f) {
		while (fgets(line, sizeof(line), f))
			if (strncasecmp(line, csn, 16) && len + strlen(line) < sizeof(rest)) len += sprintf(rest + len, "%s", line);
		fclose(f);
	}
	f = fopen(ICLASS_KNOWN, "w");
	if (!f) return;
	fwrite(rest, 1, len, f);
	fprintf(f, "%s ", csn);
	for (int k = 0; k < 2; k++) {
		const u8 *d = k ? c->kc : c->kd;
		bool known = k ? c->kcKnown : c->kdKnown;
		for (int i = 0; i < 8; i++) fprintf(f, "%02X", known ? d[i] : 0);
		fprintf(f, k ? "\n" : " ");
	}
	fclose(f);
}

static void readRange(IcCard *c, int from, int to)
{
	for (int b = from; b <= to && !mfCancel; b++) {
		if (c->have[b]) continue;
		progStep(b, c->nblocks);
		c->have[b] = icRead(b, c->blocks[b]);
	}
}

int icReadCard(IcCard *c, const u8 *key, int kind)
{
	u8 csn[8];
	memcpy(csn, c->csn, 8);
	memset(c, 0, sizeof(*c));
	memcpy(c->csn, csn, 8);
	progOp("Reading header");
	static const u8 hdr[] = { 0, 1, 2, 5 };
	for (u32 i = 0; i < sizeof(hdr); i++) {
		c->have[hdr[i]] = icRead(hdr[i], c->blocks[hdr[i]]);
		if (!c->have[hdr[i]]) {
			logp("iclass: block %d unreadable\n", hdr[i]);
			if (hdr[i] < 2) return 0;
		}
	}
	icConfig(c->blocks[1], &c->cfg);
	c->nblocks = c->cfg.lastBlock + 1;
	if (c->cfg.nonSecure) { // no keys: everything reads plain
		progOp("Reading blocks");
		readRange(c, 3, c->nblocks - 1);
	} else {
		int r = findKey(c, false, key, kind);
		if (r < 0) return 0;
		if (r) {
			progOp("Reading AA1");
			readRange(c, 6, c->cfg.keyAccessSplit ? c->cfg.appLimit : c->nblocks - 1);
		}
		if (!mfCancel && (r = findKey(c, true, key, kind)) < 0) return 0;
		if (r && icAuth(c->kc, true) == 1) {
			progOp("Reading AA2");
			readRange(c, 6, c->nblocks - 1);
		}
		if (c->kdKnown) memcpy(c->blocks[3], c->kd, 8), c->have[3] = true;
		if (c->kcKnown) memcpy(c->blocks[4], c->kc, 8), c->have[4] = true;
		if (c->kdKnown || c->kcKnown) remember(c);
	}
	u8 tk[16];
	FILE *f = fopen(ICLASS_TRANSPORT, "rb");
	c->transportKey = f && fread(tk, 1, 16, f) == 16;
	if (f) fclose(f);
	static u8 flat[ICLASS_BLOCKS * 8];
	for (int b = 0; b < c->nblocks; b++) memcpy(flat + 8 * b, c->have[b] ? c->blocks[b] : (const u8[8]){ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }, 8);
	if (c->have[6] && c->have[7]) icCredential(flat, c->nblocks, c->transportKey ? tk : NULL, &c->cred);
	return 1;
}

bool icSaveDump(const IcCard *c, char *path, u32 max)
{
	mkdir(MF_DIR, 0777);
	mkdir(ICLASS_DIR, 0777);
	char csn[17];
	for (int i = 0; i < 8; i++) sprintf(csn + 2 * i, "%02X", c->csn[i]);
	snprintf(path, max, ICLASS_DIR "/hf-iclass-%s-dump.bin", csn);
	FILE *f = fopen(path, "wb");
	if (!f) return false;
	int last = 0;
	for (int b = 0; b < c->nblocks; b++)
		if (c->have[b]) last = b;
	for (int b = 0; b <= last; b++) {
		static const u8 ff[8] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
		fwrite(c->have[b] ? c->blocks[b] : ff, 1, 8, f);
	}
	fclose(f);
	return true;
}
