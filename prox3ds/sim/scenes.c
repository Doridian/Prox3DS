// Scenes for the UI simulator: mock cards, dumps and results, put straight into the screens' state
// (hook_*.c), and key presses through the real app loop. Each SHOT writes a draw list; render.py
// draws it and checks text against the screen and the panels it sits on.
//
// Worst cases on purpose: 10-byte UIDs, long file names, every decoder branch, long dialog texts.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>

#include "../source/entry.h"
#include "../source/probe.h"
#include "../source/ndef.h"
#include "scenes.h"
#include "sim.h"

#define K_ROOT_DOWN KEYS(KEY_DOWN)

// --- cards ---

static Card card4 = { true, { 0x04, 0x00 }, { 0x9B, 0xB2, 0x09, 0x2B }, 4, 0x08 };
static Card card7 = { true, { 0x44, 0x00 }, { 0x04, 0xC8, 0xE3, 0xBA, 0x06, 0x4F, 0x80 }, 7, 0x00 };
static Card card10 = { true, { 0x84, 0x00 }, { 0x04, 0xB1, 0xB1, 0xB1, 0xB1, 0xB1, 0xB1, 0x11, 0x22, 0x33 }, 10, 0x28 };
static Card cardDf = { true, { 0x44, 0x03 }, { 0x04, 0xB1, 0xB1, 0xB1, 0xB1, 0xB1, 0xB1 }, 7, 0x20 };
static Card cardOdd = { true, { 0x48, 0x00 }, { 0x08, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00 }, 10, 0x53 };

// --- MIFARE Classic dumps ---

static MfDump mf1k, mf4k;

static void fillDump(MfDump *d, int sectors)
{
	memset(d, 0, sizeof(*d));
	d->sectors = sectors;
	for (int s = 0; s < sectors; s++) {
		int f = mfFirstBlock(s), n = mfSectorBlocks(s);
		bool keyA = s % 5 != 3, keyB = s % 3 != 2;
		d->keyFound[s][0] = keyA;
		d->keyFound[s][1] = keyB;
		memset(d->keys[s][0], 0xFF, 6);
		memcpy(d->keys[s][1], "\xA0\xA1\xA2\xA3\xA4\xA5", 6);
		for (int b = f; b < f + n; b++) {
			d->valid[b] = keyA || keyB;
			for (int i = 0; i < 16; i++) d->data[b][i] = (b * 37 + i * 11) & 0xFF;
			if (b % 3 == 0) memcpy(d->data[b], "Hello, MIFARE! \x01", 16);
		}
		u8 *t = d->data[f + n - 1];
		memcpy(t, "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x07\x80\x69\xA0\xA1\xA2\xA3\xA4\xA5", 16);
		mfAclSet(t, 0, s % 8);
		mfAclSet(t, 1, (s + 3) % 8);
		mfAclSet(t, 2, (s + 5) % 8);
		mfAclSet(t, 3, s % 8);
	}
	// block 0 with a bad BCC (shows the 7-byte reading too)
	memcpy(d->data[0], "\x04\xC8\xE3\xBA\x00\x08\x04\x00\x62\x63\x64\x65\x66\x67\x68\x69", 16);
	// sector 1: a value block (-123456, address 7)
	u8 *v = d->data[4];
	s32 val = -123456;
	memcpy(v, &val, 4);
	u32 inv = ~(u32)val;
	memcpy(v + 4, &inv, 4);
	memcpy(v + 8, &val, 4);
	v[12] = 7, v[13] = ~7, v[14] = 7, v[15] = ~7;
	// sector 2's trailer: inconsistent access bits
	d->data[11][7] ^= 0x10;
}

// --- Ultralight / NTAG dumps ---

static MfuDump n215, ev1, ulc, ulPlain, unk;

static void fillMfu(MfuDump *d, const u8 *version, int pages, const MfuType *t)
{
	memset(d, 0, sizeof(*d));
	if (version) {
		d->info.hasVersion = true;
		memcpy(d->info.version, version, 8);
		d->info.type = mfuTypeFromVersion(version);
	} else {
		d->info.type = t;
	}
	d->pages = d->info.type ? d->info.type->pages : pages;
	for (int p = 0; p < d->pages; p++) {
		d->valid[p] = true;
		for (int i = 0; i < 4; i++) d->data[p][i] = (p * 13 + i * 7) & 0xFF;
	}
	memcpy(d->data[0], "\x04\xC8\xE3\xA7", 4);
	memcpy(d->data[1], "\xBA\x06\x4F\x80", 4);
	memcpy(d->data[2], "\x73\x48\xF0\xFF", 4); // BCC1 bad, lock bits set
	memcpy(d->data[3], "\xE1\x10\x3E\x00", 4);
	memcpy(d->data[4], "NDEF", 4);
	const MfuType *ty = d->info.type;
	if (ty && ty->cfg) {
		memcpy(d->data[ty->cfg], "\x04\x00\x00\x10", 4);
		memcpy(d->data[ty->cfg + 1], "\xC5\x05\x00\x00", 4);
		d->valid[ty->cfg + 2] = d->valid[ty->cfg + 3] = false;
	}
	d->info.hasSig = true;
	for (int i = 0; i < 32; i++) d->info.sig[i] = i * 29;
	d->info.cntOk = 0x5;
	d->info.tearOk = 0x7;
	memcpy(d->info.cnt[0], "\x40\xE2\x01\xBD", 4);
	memcpy(d->info.cnt[1], "\x00\x00\x00\xBD", 4);
	memcpy(d->info.cnt[2], "\xFF\xFF\xFF\x00", 4);
}

// --- DESFire ---

static DfInfo dfi, dfIso, dfKeyed;

static void dfFile(DfFile *f, u8 fid, u8 type, u8 comm, u16 access, u32 size, int dataLen, DfInfo *d)
{
	f->fid = fid;
	f->len = 7;
	f->set[0] = type;
	f->set[1] = comm;
	f->set[2] = access & 0xFF;
	f->set[3] = access >> 8;
	f->set[4] = size, f->set[5] = size >> 8, f->set[6] = size >> 16;
	if (type == 3 || type == 4) {
		f->len = 13;
		f->set[7] = 12, f->set[10] = 9;
	}
	if (type == 2) {
		f->len = 17;
		s32 lo = -1000000, hi = 2000000000;
		memcpy(f->set + 4, &lo, 4), memcpy(f->set + 8, &hi, 4);
	}
	if (dataLen >= 0) {
		f->hasData = true;
		f->dataKey = 0xE;
		f->dataOff = d->poolUsed;
		f->dataLen = dataLen;
		for (int i = 0; i < dataLen; i++) d->pool[d->poolUsed++] = "WAVELYNX TECH 01 "[i % 17] + (i / 17);
	}
}

static void fillDf(void)
{
	DfInfo *d = &dfi;
	memset(d, 0, sizeof(*d));
	static const u8 ats[] = { 0x06, 0x75, 0x77, 0x81, 0x02, 0x80 };
	d->atsLen = sizeof(ats);
	memcpy(d->ats, ats, sizeof(ats));
	static const u8 ver[] = { 0x04, 0x01, 0x01, 0x12, 0x00, 0x1A, 0x05, 0x04, 0x01, 0x01, 0x02, 0x01, 0x1A, 0x05,
		0x04, 0xB1, 0xB1, 0xB1, 0xB1, 0xB1, 0xB1, 0xB0, 0xB0, 0xB0, 0xB0, 0xB0, 0x37, 0x21 };
	d->verLen = 28;
	memcpy(d->ver, ver, 28);
	d->hasFree = true, d->freeMem = 3584;
	d->keySet = 0x0F, d->maxKeys = 0x81, d->keyVer = 0;
	d->hasSig = true;
	for (int i = 0; i < 56; i++) d->sig[i] = i * 41 + 7;
	d->napps = 7;
	for (int i = 0; i < 7; i++) {
		DfApp *a = &d->apps[i];
		a->aid = 0xF51CDE - i * 0x10 + (i == 2 ? 0x2000 : 0);
		a->hasIso = i != 3;
		a->isoFid = 0x0900 - i * 0x100;
		if (i == 1) a->nameLen = 16, memcpy(a->name, "\xD2\x76\x00\x00\x85\x01\x01\x00\xA0\x00\x00\x03\x96\x56\x43\x41", 16);
		a->keySet = 0xEB, a->maxKeys = 0x80 | (9 + i % 3);
		a->nKeyVer = a->maxKeys & 0xF;
		for (int k = 0; k < a->nKeyVer; k++) a->keyVer[k] = i == 0 ? k : 0;
		if (i == 4) a->selSt = 0x9D;
		if (i == 5) a->fileSt = 0x9D, a->keySt = 0xAE;
		a->nfiles = i == 6 ? 0 : i == 0 ? 8 : 2;
		for (int f = 0; f < a->nfiles; f++)
			dfFile(&a->files[f], f + 1, f % 5, f & 1 ? 0x83 : 0x00, f & 1 ? 0x1E00 : 0xEEEE, 32 + 16 * f,
				f % 3 == 0 ? 32 + 16 * f : -1, d);
		if (i == 0) a->files[2].dataSt = 0x9D, a->files[5].st = 0x9D;
	}
	// the EV3 test card, read with the dictionary: AES / 3K3DES / DES apps, one key not found
	DfInfo *k = &dfKeyed;
	*k = *d;
	k->keyed = true, k->dictKeys = 17;
	k->ver[3] = 0x33, k->ver[5] = 0x18, k->freeMem = 4192;
	k->keySet = 0x0F, k->maxKeys = 0x01;
	k->piccKey = (DfKey){ true, DF_2K3DES };
	k->napps = 3;
	memset(k->apps, 0, sizeof(k->apps));
	k->poolUsed = 0;
	static const u32 aids[] = { 0xA1A1A1, 0xB2B2B2, 0xC3C3C3 };
	static const u8 mk[] = { 0x83, 0x42, 0x02 }, ksets[] = { 0x0F, 0x09, 0x0F };
	for (int i = 0; i < 3; i++) {
		DfApp *a = &k->apps[i];
		a->aid = aids[i], a->keySet = ksets[i], a->maxKeys = mk[i], a->nKeyVer = mk[i] & 0xF;
		for (int j = 0; j < a->nKeyVer; j++) {
			a->keyVer[j] = j;
			a->keys[j] = (DfKey){ j < 2, i == 0 ? DF_AES : i == 1 ? DF_3K3DES : DF_2K3DES };
			if (j == 1) memcpy(a->keys[j].key, "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF", 16);
		}
	}
	DfApp *a = &k->apps[0];
	a->nfiles = 6;
	static const u8 types[] = { 0, 0, 0, 2, 3, 1 }, comms[] = { 0, 1, 3, 3, 1, 0 };
	static const u16 acc[] = { 0xE100, 0x1110, 0x2220, 0x1110, 0x1110, 0x2220 };
	static const int lens[] = { 32, 48, -1, 4, 16, -1 };
	for (int f = 0; f < 6; f++) {
		dfFile(&a->files[f], f + 1, types[f], comms[f], acc[f], f == 1 ? 48 : f == 2 ? 64 : 32, lens[f], k);
		if (f && lens[f] >= 0) a->files[f].dataKey = 1;
	}
	k->apps[1].nfiles = 1;
	dfFile(&k->apps[1].files[0], 1, 0, 3, 0x1100, 32, 32, k);
	k->apps[1].files[0].dataKey = 1;
	k->apps[2].nfiles = 1;
	dfFile(&k->apps[2].files[0], 1, 0, 1, 0x1100, 24, 24, k);
	k->apps[2].files[0].dataKey = 1;
	k->apps[2].keyVer[1] = 0x55;
	dfFile(&a->files[2], 3, 0, 3, 0x2220, 256, 256, k); // a long one, read with key 2
	a->files[2].dataKey = 2;

	memset(&dfIso, 0, sizeof(dfIso));
	static const u8 ats2[] = { 0x13, 0x78, 0x80, 0x72, 0x02, 0x80, 0x31, 0x80, 0x66, 0xB1, 0x84, 0x0C, 0x01, 0x6E,
		0x01, 0x83, 0x00, 0x90, 0x00 };
	dfIso.atsLen = sizeof(ats2);
	memcpy(dfIso.ats, ats2, sizeof(ats2));
}

// --- SD card ---

static void writeFile(const char *path, const void *data, size_t n, time_t mtime)
{
	FILE *f = fopen(path, "wb");
	fwrite(data, 1, n, f);
	fclose(f);
	struct timespec ts[2] = { { mtime, 0 }, { mtime, 0 } };
	utimensat(AT_FDCWD, path, ts, 0);
}

static void sdSetup(void)
{
	mkdir("sdmc:", 0777);
	mkdir(APP_DIR, 0777);
	mkdir(MF_DIR, 0777);
	mkdir(MF_DUMPS, 0777);
	mkdir(MFU_DIR, 0777);
	mkdir(DF_DIR, 0777);
	mkdir(GP_CAPS, 0777);
	FILE *cap = fopen(GP_CAPS "/dspm-test.cap", "w");
	fprintf(cap, "PK");
	fclose(cap);
	cap = fopen(GP_CAPS "/ykneo-oath-with-a-rather-long-file-name-for-testing.cap", "w");
	fclose(cap);
	FILE *k = fopen(MF_KEYS, "w");
	fprintf(k, "A0A1A2A3A4A5\nD3F7D3F7D3F7\n");
	fclose(k);
	k = fopen(MFU_KEYS, "w");
	fprintf(k, "# Ultralight / NTAG passwords and UL-C keys\n1A2B3C4D # the NFC stickers from the shop\nCAFEBABE\n"
		"00112233445566778899AABBCCDDEEFF # test UL-C\n");
	fclose(k);
	static const char *mfNames[] = { "9BB2092B.bin", "04C8E3BA064F80-10.bin", "04B1B1B1B1B1B11122334455-12.bin",
		"hotel_keycard_from_the_conference_in_2025_backup.bin", "truncated.bin" };
	time_t t0 = 1790000000;
	for (int i = 0; i < 5; i++) {
		char p[160];
		snprintf(p, sizeof(p), MF_DUMPS "/%s", mfNames[i]);
		writeFile(p, mf1k.data, i == 2 ? 4096 : i == 4 ? 1000 : 1024, t0 - i * 3600);
	}
	for (int i = 0; i < 14; i++) { // more than a page
		char p[160];
		snprintf(p, sizeof(p), MF_DUMPS "/%08X.bin", 0x10000000 * (i + 1) + i);
		writeFile(p, mf1k.data, 1024, t0 - 86400 - i);
	}
	k = fopen(APP_DIR "/amiibo.json", "w"); // a few of AmiiboAPI's figures, long names and escapes
	fprintf(k, "{\"amiibos\": {\n"
		"\"0x06420000035f1102\": {\"name\": \"Pikmin\", \"release\": {\"eu\": \"2017-07-28\", \"jp\": null}},\n"
		"\"0x0000000000000002\": {\"name\": \"Mario\", \"release\": {}},\n"
		"\"0x0000000000340102\": {\"name\": \"Mario - Wedding\"},\n"
		"\"0x0001000000350102\": {\"name\": \"Peach - Wedding\"},\n"
		"\"0x0000010000190002\": {\"name\": \"Mario\"},\n"
		"\"0x01000000037c0002\": {\"name\": \"Link - Ocarina of Time\"},\n"
		"\"0x01000000034b0902\": {\"name\": \"Link - The Legend of Zelda: Breath of the Wild (Archer Pose)\"},\n"
		"\"0x0181010100b40502\": {\"name\": \"Isabelle - Winter\"},\n"
		"\"0x22430000044a1d02\": {\"name\": \"Ren\\u00e9e\"},\n"
		"\"0x3200000000300002\": {\"name\": \"Sonic\"},\n"
		"\"0x1f000000000a0002\": {\"name\": \"Kirby\"},\n"
		"\"0x0080000002e00d02\": {\"name\": \"Pikachu\"},\n"
		"\"0x00c00000037b0002\": {\"name\": \"Bowser\"},\n"
		"\"0x0240000002ec0002\": {\"name\": \"Toon Link\"}\n"
		"},\n\"amiibo_series\": {\"0x00\": \"Super Smash Bros.\", \"0x01\": \"Super Mario Bros.\", "
		"\"0x05\": \"Animal Crossing\", \"0x09\": \"The Legend of Zelda\", \"0x11\": \"Pikmin\", "
		"\"0x1d\": \"Xenoblade Chronicles 3 and its rather long amiibo series name\"},\n"
		"\"game_series\": {\"0x000\": \"Super Mario\", \"0x010\": \"The Legend of Zelda\", \"0x018\": \"Animal Crossing\", "
		"\"0x064\": \"Pikmin\", \"0x320\": \"Sonic the Hedgehog\", \"0x1f0\": \"Kirby\", \"0x224\": \"Xenoblade\"},\n"
		"\"types\": {\"0x00\": \"Figure\", \"0x01\": \"Card\", \"0x02\": \"Yarn\"},\n"
		"\"characters\": {\"0x0000\": \"Mario\", \"0x0001\": \"Peach\", \"0x0642\": \"Pikmin\", \"0x0100\": \"Link\"}\n}\n");
	fclose(k);
	static const char *mfuNames[] = { "04C8E3BA064F80.bin", "04C8E3BA064F80-2.bin", "11223300000000.bin",
		"amiibo_super_mario_odyssey_wedding_peach_backup_2.bin" };
	for (int i = 0; i < 4; i++) {
		char p[160];
		snprintf(p, sizeof(p), MFU_DIR "/%s", mfuNames[i]);
		u8 raw[MFU_HDR + 4 * 256] = { 0 };
		raw[0] = 0;
		memcpy(raw, n215.info.version, 8);
		raw[11] = n215.pages - 1;
		for (int pg = 0; pg < n215.pages; pg++) memcpy(raw + MFU_HDR + 4 * pg, n215.data[pg], 4);
		writeFile(p, raw, i == 2 ? 1020 : MFU_HDR + 4 * n215.pages, t0 - i * 60);
	}
}

// --- scene steps ---

static void reset(void) { simReset(); }
static void tagOdd(void) { simTag(&cardOdd); }
static void fillLog(void)
{
	for (int i = 0; i < 30; i++)
		logp("line %d: card: UID 04B1B1B1B1B1B11122 ATQA 0344 SAK 20, nested: sector %d key B recovered "
			"A0A1A2A3A4A5 after 1234 tries\n", i, i % 40);
}
static void busyRead(void) { simBusy("Reading card", true, false); }
static void busyStop(void) { simBusy("Writing to magic card", true, true); }
static void busyChip(void) { simBusy("Chip info", false, false); }
static void busyEnd(void) { simBusyEnd(); simFieldBars = -1; }
static void fieldLive(void) { simFieldBars = 4; simFieldLive = true; simFieldGauge = 0.64f; }
static void fieldDim(void) { simFieldBars = 2; simFieldLive = false; simFieldGauge = 0; }
static void toastHome(void) { toast("Touch locked: HOME unlocks, START exits"); }
static void toastLong(void) { toast("Deleted hotel_keycard_from_the_conference_in_2025_backup.bin"); }

static void mfcMenu(void) { simMfcMenu(); }
static void mfcNone(void) { MfMagic m = { 0 }; simMfcCard(&card4, &m); }
static void mfcGen1a2(void) { MfMagic m = { MF_MAGIC_GEN1A | MF_MAGIC_GEN2 }; simMfcCard(&card4, &m); }
static void mfcAll(void) { MfMagic m = { MF_MAGIC_GEN4 | MF_MAGIC_USCUID | MF_MAGIC_GEN2 }; simMfcCard(&card10, &m); }
static MfMagic gtu = { MF_MAGIC_GEN4, 30, { 0, 2, 0, 0, 0, 0, 3, 1, [24] = 0x84, 0x00, 0x18, 0, 0x28 } };
static void mfcGtu(void) { simMfcCard(&card10, &gtu); }
static void mfcGtuUl(void) { MfMagic m = gtu; m.cfg[0] = 1; simMfcCard(&card7, &m); simMfcGen4(); }
static void mfcUsc(void)
{
	MfMagic m = { MF_MAGIC_USCUID | MF_MAGIC_GEN1A, 0, { 0 }, { 0x85, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00 } };
	simMfcCard(&card4, &m);
}
static void mfcNotClassic(void) { MfMagic m = { 0 }; simMfcCard(&cardDf, &m); }
static void mfcGen4(void) { simMfcGen4(); }
static void mfcReadOk(void) { simMfcRead(&mf1k, 60, MF_DUMPS "/04B1B1B1B1B1B11122334455-12.bin"); }
static void mfcReadKdf(void) { MfDump d = mf1k; d.kdf = "Saflok / Maid"; simMfcRead(&d, 64, MF_DUMPS "/5A5A0002-11.bin"); }
static void mfcReadNoSd(void) { simMfcRead(&mf1k, 60, ""); }
static void mfcCloneForce(void) { simMfcClone(0, "block 0 of a Gen2 card: the UID can't change again (force)"); }
static void mfcCloneRefused(void) { simMfcClone(0, "not a magic card (no Gen1a, Gen2, GTU or USCUID answer)"); }
static void mfcCloneLost(void) { simMfcClone(-1, ""); }
static void ed1k(void) { editorOpen(&mf1k, MF_DUMPS "/04B1B1B1B1B1B11122334455-12.bin"); }
static void edValueOk(void) { u8 b[16]; mfValueBlock(4242, 6, b); simEdValue(1, 6, b); }
static void ed4k(void) { editorOpen(&mf4k, MF_DUMPS "/hotel_keycard_from_the_conference_in_2025_backup.bin"); }
static void edWbOk(void) { simEdWriteBlock(1, "key B A0A1A2A3A4A5", ""); }
static void edWbFail(void) { simEdWriteBlock(0, "key B A0A1A2A3A4A5", "auth failed: no answer to the nonce (wrong key?)"); }

static void mfuMenu(void) { simMfuMenu(); }
static void mfuN215(void) { simMfuCard(&card7, &n215, true); }
static void mfuEv1(void) { simMfuCard(&card7, &ev1, false); }
static void mfuUlc(void) { simMfuCard(&card7, &ulc, false); }
static void mfuPlain(void) { MfuDump d = ulPlain; d.info.hasSig = false; d.valid[2] = false; simMfuCard(&card7, &d, false); }
static void mfuUnk(void) { simMfuCard(&card7, &unk, true); }
static void mfuCfgLocked(void) { MfuDump d = n215; d.valid[d.info.type->cfg] = false; simMfuCard(&card7, &d, false); }
static void mfuReadOk(void) { MfuDump d = n215; simMfuRead(&d, 1, MFU_DIR "/amiibo_super_mario_odyssey_wedding_peach_backup_2.bin"); }
static void mfuRestoreOk(void) { simMfuRestore(1, 12, ""); }
static void mfuRestoreFail(void) { simMfuRestore(0, 3, "page 7 refused: NAK 0 (locked, or wrong password)"); }
static void mfuCloneOk(void) { simMfuClone(&unk, 1, ""); }
static void mfuCloneFail(void) { simMfuClone(&n215, 0, "GTU config write refused: wrong password (not 00000000?)"); }
static void pickEv1Locked(void) { MfuDump d = ev1; d.valid[d.info.type->cfg] = d.valid[d.info.type->cfg + 1] = false; simMfuPick(&card7, &d); }
static void pickN215(void) { simMfuPick(&card7, &n215); }

// An NTAG215 with three records: URI, text, Android app (MB on the first, ME on the last)
static void ndefFixture(MfuDump *d, bool empty)
{
	*d = n215;
	u8 msg[300], tlv[320];
	u32 n = 0;
	if (!empty) {
		n += ndefUri("https://github.com/Doridian/Prox3DS", msg + n, sizeof(msg) - n);
		u32 a = n;
		n += ndefText("en", "Hello from the 3DS", msg + n, sizeof(msg) - n);
		u32 b = n;
		static const u8 aar[] = { 0x54, 0x0F, 0x0E, 'a', 'n', 'd', 'r', 'o', 'i', 'd', '.', 'c', 'o', 'm', ':', 'p', 'k', 'g',
			'o', 'r', 'g', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'a', 'p' };
		memcpy(msg + n, aar, sizeof(aar));
		n += sizeof(aar);
		msg[0] &= ~0x40, msg[a] &= ~0xC0, msg[b] &= ~0x80; // only the first MB, only the last ME
	}
	u32 t = ndefTlv(msg, n, tlv, sizeof(tlv));
	static const u8 cc[4] = { 0xE1, 0x10, 0x3E, 0x00 };
	memcpy(d->data[3], cc, 4);
	for (u32 i = 0; i < (t + 3) / 4; i++) {
		memset(d->data[4 + i], 0, 4);
		memcpy(d->data[4 + i], tlv + 4 * i, t - 4 * i < 4 ? t - 4 * i : 4);
		d->valid[4 + i] = true;
	}
}
static void ndefRecords(void) { MfuDump d; ndefFixture(&d, false); simNdef(&d, &card7); }
static void ndefEmpty(void) { MfuDump d; ndefFixture(&d, true); simNdef(&d, &card7); }
static void amiiboFixture(Amiibo *a, u8 *tag, bool ok, bool locked)
{
	static const u8 head[16] = { 0x04, 0xC8, 0xE3, 0xA7, 0xBA, 0x06, 0x4F, 0x80, 0x73, 0x48, 0x0F, 0xE0, 0xF1, 0x10, 0xFF, 0xEE };
	static const u8 id[8] = { 0x06, 0x42, 0x00, 0x00, 0x03, 0x5F, 0x11, 0x02 };
	memset(a, 0, sizeof(*a));
	memset(tag, 0, AMIIBO_TAG);
	memcpy(tag, head, 16);
	if (!locked) tag[10] = tag[11] = 0;
	memcpy(a->charId, id, 8);
	a->ok = ok, a->set = 1;
	if (!ok) return;
	strcpy(a->nickname, "Peachy");
	strcpy(a->owner, "Dori");
	a->registered = a->hasAppData = true;
	a->writes = 17;
	a->setupDate = 26 << 9 | 11 << 5 | 1;
	a->writeDate = 26 << 9 | 11 << 5 | 1;
	a->appId = 0x0014F000;
}

static void amiiboOk(void) { Amiibo a; u8 t[AMIIBO_TAG]; amiiboFixture(&a, t, true, true); simAmiibo(&a, t, &card7, NULL); }
static void amiiboNewFile(void)
{
	Amiibo a;
	u8 t[AMIIBO_TAG];
	amiiboFixture(&a, t, true, false);
	a.nickname[0] = a.owner[0] = 0;
	a.registered = a.hasAppData = false;
	a.setupDate = a.writeDate = a.appId = 0;
	simAmiibo(&a, t, &card7, "amiibo_super_mario_odyssey_wedding_peach_backup_2.bin");
}
static void amiiboUnlocked(void) { Amiibo a; u8 t[AMIIBO_TAG]; amiiboFixture(&a, t, true, false); simAmiibo(&a, t, &card7, NULL); }
static void amiiboBad(void) { Amiibo a; u8 t[AMIIBO_TAG]; amiiboFixture(&a, t, false, true); simAmiibo(&a, t, &card7, NULL); }
static void amiiboCopyLock(void) { simAmiiboCopy(false, true); }
static void amiiboCopyFresh(void) { simAmiiboCopy(true, false); }
static void amiiboUnknown(void)
{
	Amiibo a;
	u8 t[AMIIBO_TAG];
	amiiboFixture(&a, t, true, true);
	a.charId[0] = 0x7E; // in no list
	simAmiibo(&a, t, &card7, NULL);
}
static void kbdMario(void) { simKbdText = "mario"; }
static void kbdNone(void) { simKbdText = "nothing like it"; }

static void ndefEmptyUrl(void) { simNdefUrl("https://example.com/a/rather/long/path?with=query"); }
static void pickAmiibo(void)
{
	MfuDump d = n215;
	memcpy(d.data[2], "\x73\x48\x0F\xE0", 4);
	memcpy(d.data[3], "\xF1\x10\xFF\xEE", 4);
	memcpy(d.data[4], "\xA5\x00\x00\x00", 4);
	d.data[d.info.type->cfg + 1][0] = 0x00; // AUTHLIM 0
	simMfuPick(&card7, &d);
}
static void pickUlc(void) { MfuDump d = ulc; d.pwdOk = false; simMfuPick(&card7, &d); }
static void cardUlcKey(void)
{
	MfuDump d = ulc;
	d.pwdOk = true;
	d.info.hasSig = false;
	memcpy(d.key, "\x49\x45\x4D\x4B\x41\x45\x52\x42\x21\x4E\x41\x43\x55\x4F\x59\x46", 16);
	simMfuCard(&card7, &d, true);
}
static void readPwdPack(void)
{
	MfuDump d = n215;
	d.pwdOk = true;
	int c = d.info.type->cfg;
	memcpy(d.data[c + 2], "\x1A\x2B\x3C\x4D", 4);
	memcpy(d.data[c + 3], "\x80\x80\x00\x00", 4);
	d.valid[c + 2] = d.valid[c + 3] = true;
	MfuKey k = { "Amiibo", { 0x1A, 0x2B, 0x3C, 0x4D }, 4, { 0x80, 0x80 }, true };
	simMfuReadKey(&d, 1, MFU_DIR "/04C8E3BA064F80-3.bin", &k);
}
static void readUlcKey(void)
{
	MfuDump d = ulc;
	d.pwdOk = true;
	MfuKey k = { "typed", { 0 }, 16 };
	simMfuReadKey(&d, 1, MFU_DIR "/04C8E3BA064F80-4.bin", &k);
}
static void edN215(void) { mfuEditorOpen(&n215, MFU_DIR "/amiibo_super_mario_odyssey_wedding_peach_backup_2.bin"); }
static void edUlc(void) { mfuEditorOpen(&ulc, MFU_DIR "/04C8E3BA064F80.bin"); }
static void edEv1(void) { mfuEditorOpen(&ev1, MFU_DIR "/04C8E3BA064F80-2.bin"); }
static void edUnk(void) { mfuEditorOpen(&unk, MFU_DIR "/11223300000000.bin"); }

static void dfMenu(void) { simDfMenu(); }

// --- smart cards ---

static Card cardJc = { true, { 0x48, 0x00 }, { 0x04, 0x6D, 0x45, 0x52, 0x8C, 0x50, 0x80 }, 7, 0x20 };
static ScInfo scJc, scBare;
static GpCard gpJc;
static OathInfo oathYk;

static void hexIn(u8 *out, u8 *len, const char *h)
{
	int n = scUnhex(h, out, 255);
	*len = n;
}

static void fillSc(void)
{
	GpCard *g = &gpJc;
	memset(g, 0, sizeof(*g));
	hexIn(g->isd, &g->isdLen, "A000000151000000");
	hexIn(g->cplc, &g->cplcLen, "4790050382116351030290610012800748880000000000000000000000000000000000000000000000");
	hexIn(g->crd, &g->crdLen, "733D06072A864886FC6B01600C060A2A864886FC6B02020101630906072A864886FC6B03640B06092A864886"
		"FC6B040300660C060A2B060104012A026E0102");
	g->kvn = 0xFF, g->scp = 3, g->hasSeq = true, g->seq = 1234;
	static const struct { u8 kind, state, priv; const char *aid, *pkg; int mods; } ents[] = {
		{ GP_ISD, 0x07, 0x9E, "A000000151000000", NULL, 0 },
		{ GP_APP, 0x07, 0x00, "F0334453504D01", "F0334453504D", 0 },
		{ GP_APP, 0x07, 0x00, "A000000527210101", "A0000005272101", 0 },
		{ GP_APP, 0x83, 0x00, "D2760001240102000000000000010000", "D27600012401", 0 },
		{ GP_APP, 0x0F, 0x80, "A000000151535041", "A0000001515350", 0 },
		{ GP_PKG, 0x01, 0x00, "A0000001515350", NULL, 1 },
		{ GP_PKG, 0x01, 0x00, "F0334453504D", NULL, 1 },
		{ GP_PKG, 0x01, 0x00, "A0000005272101", NULL, 1 },
		{ GP_PKG, 0x01, 0x00, "D27600012401", NULL, 3 },
		{ GP_PKG, 0x01, 0x00, "D276000098636F6E74726F6C6C6572", NULL, 0 },
		{ GP_PKG, 0x01, 0x00, "A0000000620001", NULL, 0 },
	};
	for (int i = 0; i < (int)(sizeof(ents) / sizeof(ents[0])); i++) {
		GpEntry *e = &g->ent[g->nent++];
		memset(e, 0, sizeof(*e));
		e->kind = ents[i].kind, e->state = ents[i].state, e->priv = ents[i].priv;
		hexIn(e->aid, &e->aidLen, ents[i].aid);
		if (ents[i].pkg) hexIn(e->pkg, &e->pkgLen, ents[i].pkg);
		else e->pkg[0] = 1, e->pkg[1] = 0;
		e->nmods = ents[i].mods;
		for (int m = 0; m < e->nmods; m++) memcpy(e->mods[m], e->aid, e->aidLen), e->modLen[m] = e->aidLen + 1;
	}
	g->listed = true;

	ScInfo *s = &scJc;
	memset(s, 0, sizeof(*s));
	hexIn(s->ats, &s->atsLen, "0578777102");
	s->hasGp = true, s->gp = *g;
	static const struct { const char *aid, *fci; u16 sw; } f[] = {
		{ "A000000151000000", "", 0x9000 }, { "A0000005272101", "79030504037108A1B2C3D4E5F60718", 0x9000 },
		{ "A000000527471117", "5669727475616C206D67722D46572076657273696F6E20352E342E33", 0x9000 },
		{ "D27600012401", "", 0x6283 }, { "F0334453504D01", "", 0x9000 },
		{ "A0000003080000100001", "61114F0600001000010079074F05A000000308", 0x9000 },
	};
	for (int i = 0; i < 6; i++) {
		ScFound *x = &s->found[s->nfound++];
		hexIn(x->aid, &x->aidLen, f[i].aid);
		hexIn(x->fci, &x->fciLen, f[i].fci);
		x->sw = f[i].sw;
		x->app = scAppletFor(x->aid, x->aidLen);
		snprintf(x->name, sizeof(x->name), "%s", x->app ? x->app->name : "My corporate badge applet");
	}
	s->found[5].app = NULL;
	snprintf(s->found[5].name, sizeof(s->found[5].name), "Door badge (aids.txt)");

	s = &scBare;
	memset(s, 0, sizeof(*s));
	hexIn(s->ats, &s->atsLen, "0D7833B2908031FE45736D61727478");

	OathInfo *o = &oathYk;
	memset(o, 0, sizeof(*o));
	o->ver[0] = 5, o->ver[1] = 4, o->ver[2] = 3;
	static const struct { const char *name; u8 type, digits; bool touch, code; u32 v; } c[] = {
		{ "GitHub:someone@example.com", OATH_TOTP, 6, false, true, 12345 },
		{ "Google:a.very.long.address.for.testing@example.org", OATH_TOTP, 6, false, true, 987654 },
		{ "60/Steam:gamer", OATH_TOTP, 8, false, true, 1234567 },
		{ "Mastodon:@me@social.example", OATH_TOTP, 6, false, true, 555 },
		{ "AWS:root", OATH_TOTP, 6, true, false, 0 },
		{ "VPN counter", OATH_HOTP, 6, false, false, 0 },
		{ "Bank", OATH_HOTP, 8, false, true, 31415926 },
		{ "Discord:me", OATH_TOTP, 6, false, true, 42 },
		{ "Proton:me", OATH_TOTP, 6, false, true, 999999 },
		{ "Tenth:account", OATH_TOTP, 6, false, true, 100000 },
	};
	for (int i = 0; i < 10; i++) {
		OathCred *x = &o->c[o->n++];
		snprintf(x->name, sizeof(x->name), "%s", c[i].name);
		x->type = c[i].type, x->alg = OATH_SHA1, x->digits = c[i].digits, x->touch = c[i].touch;
		x->hasCode = c[i].code, x->code = c[i].v, x->period = i == 2 ? 60 : 30;
	}
}

static void scMenu(void) { simScMenu(); }
static void scCard(void) { simScCard(&cardJc, &scJc, 1, ""); }
static void scBareCard(void) { simScCard(&card10, &scBare, 1, ""); }
static void scConsole(void) { simScConsole(false); }
static void scConsoleEmpty(void) { simScConsole(true); }
static void scnGpList(void) { simGp(&gpJc, true, ""); }
static void gpNoKeys(void)
{
	GpCard g = gpJc;
	g.listed = false, g.nent = 0;
	simGp(&g, false, "None of 3 known keys fits (none was sent).");
}
static void gpCaps(void) { simGpCaps(); }
static void scnOathList(void) { simOath(&oathYk, 60); }

static EmvCard emvCard;
static void emvFill(void)
{
	EmvCard *e = &emvCard;
	memset(e, 0, sizeof(*e));
	e->ppse = true, e->napps = 2;
	EmvApp *a = &e->app[0];
	hexIn(a->aid, &a->aidLen, "A0000000031010");
	strcpy(a->label, "VISA DEBIT");
	a->selected = true;
	strcpy(a->pan, "4761739001010119");
	a->hasExp = a->hasEff = true;
	memcpy(a->exp, "\x27\x12\x31", 3), memcpy(a->eff, "\x22\x01\x01", 3);
	strcpy(a->name, "DOE/JOHN");
	a->country = 0x276, a->currency = 0x978, a->panSeq = 1, a->svc = 201;
	a->hasAip = true, a->aip = 0x2000;
	a->atc = 1234, a->lastOnlineAtc = 1230, a->pinTries = 3;
	a->logSfi = 11, a->logMax = 10, a->nrec = 3;
	static const struct { const char *d, *t, *amt; u16 cur; u8 type; const char *m; } l[] = {
		{ "\x26\x10\x31", "\x15\x30\x20", "\x00\x00\x00\x00\x12\x34", 0x978, 0, "Test Merchant" },
		{ "\x26\x10\x29", "\x08\x15\x00", "\x00\x00\x00\x05\x00\x00", 0x840, 0x20, "ACME CORPORATION WITH A LONG NAME" },
		{ "\x26\x10\x28", "\x12\x00\x00", "\x00\x00\x00\x00\x50\x00", 0x392, 0x01, "" },
		{ "\x26\x10\x27", "\x09\x41\x13", "\x00\x00\x00\x00\x03\x50", 0x978, 0, "Bakery" },
		{ "\x26\x10\x26", "\x18\x02\x55", "\x00\x00\x00\x01\x99\x99", 0x826, 0, "Bookshop" },
		{ "\x26\x10\x25", "\x07\x59\x01", "\x00\x00\x00\x00\x00\x99", 0x123, 0, "Unknown currency" },
		{ "\x26\x10\x24", "\x23\x59\x59", "\x99\x99\x99\x99\x99\x99", 0x978, 0, "Biggest" },
	};
	for (int i = 0; i < 7; i++) {
		EmvLog *x = &a->log[a->nlog++];
		x->has = LOG_DATE | LOG_TIME | LOG_AMOUNT | LOG_CUR | LOG_TYPE | (*l[i].m ? LOG_MERCHANT : LOG_COUNTRY);
		memcpy(x->date, l[i].d, 3), memcpy(x->time, l[i].t, 3), memcpy(x->amount, l[i].amt, 6);
		x->currency = l[i].cur, x->type = l[i].type, x->country = 0x392;
		snprintf(x->merchant, sizeof(x->merchant), "%s", l[i].m);
	}
	a = &e->app[1];
	hexIn(a->aid, &a->aidLen, "A0000000043060");
	a->selected = true;
	strcpy(a->pan, "6703000000000000011");
	a->panSeq = a->svc = a->atc = a->lastOnlineAtc = a->pinTries = -1;
	strcpy(a->why, "GET PROCESSING OPTIONS: 6985 conditions of use not satisfied");
}
static void scnEmv(void) { emvFill(); simEmv(&emvCard, false); }
static void scnEmvFull(void) { simEmv(&emvCard, true); }

// the German ID card's EF.CardAccess, EF.DIR, EF.ATR/INFO, as read (2026-11-04)
static EidCard eidDe;
static void eidFill(void)
{
	static const char *ca = "3181C1300D060804007F00070202020201023012060A04007F000702020302020201020201413012060A04007F0007020204020202010202010D301C060904007F000702020302300C060704007F0007010202010D020141302A060804007F0007020206161E687474703A2F2F6273692E62756E642E64652F6369662F6E70612E786D6C303E060804007F000702020831323012060A04007F00070202030202020102020145301C060904007F000702020302300C060704007F0007010202010D020145";
	static u8 b[256];
	memset(&eidDe, 0, sizeof(eidDe));
	int n = scUnhex(ca, b, sizeof(b));
	if (!eidParseAccess(&eidDe, b, n) || eidDe.ninfo != 7 || eidDe.pace != 2) printf("eid: CardAccess parse wrong (%d infos, pace %d)\n", eidDe.ninfo, eidDe.pace);
	static const char *apps[] = { "A000000167455349474E", "A0000002471001", "E80704007F00070302" };
	for (int i = 0; i < 3; i++) {
		int k = scUnhex(apps[i], eidDe.app[i].aid, 16);
		eidDe.app[i].aidLen = k;
	}
	eidDe.napps = 3;
	eidDe.extIn = eidDe.extOut = 0x5F0;
	eidDe.pinSw = 0x9000;
}
static void scnEid(void) { eidFill(); simEid(&eidDe, 0); }
static void scnEidCan(void) { EidCard e = eidDe; e.pinSw = 0x63C1; simEid(&e, 1); }
static void scnEidFail(void) { EidCard e = eidDe; e.pinSw = 0x63C0; simEid(&e, 3); }
static void scnEidBac(void) { EidCard e; memset(&e, 0, sizeof(e)); e.pace = -1; e.napps = 0; simEid(&e, 0); }

// ICAO 9303's specimen passport (not a real one), read and verified as the German passport was
static MrtdDoc mrtdSpec;
static void mrtdFill(void)
{
	static u8 dg1[] = "\x61\x5B\x5F\x1F\x58"
		"P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<"
		"L898902C36UTO7408122F1204159ZE184226B<<<<<10";
	MrtdDoc *d = &mrtdSpec;
	memset(d, 0, sizeof(*d));
	strcpy(d->access, "PACE (MRZ)");
	d->f[1].data = dg1, d->f[1].len = 93, d->f[1].sw = 0x9000;
	static u8 dummy[1];
	d->f[2].data = dummy, d->f[2].len = 15000, d->f[14].data = dummy, d->f[14].len = 745;
	d->f[MRTD_COM].data = dummy, d->f[MRTD_SOD].data = dummy;
	d->f[3].sw = 0x6982;
	mrtdParseDg1(d);
	if (strcmp(d->surname, "ERIKSSON") || strcmp(d->given, "ANNA MARIA") || strcmp(d->number, "L898902C3") ||
		strcmp(d->birth, "740812") || d->sex != 'F' || strcmp(d->expiry, "120415"))
		printf("mrtd: DG1 parse wrong: '%s' '%s' '%s' %s %c %s\n", d->surname, d->given, d->number, d->birth, d->sex, d->expiry);
	d->hashLen = 32, d->listed = 0x400E, d->ok = 0x4006, d->attrs = d->sig = PA_OK;
	strcpy(d->sigAlg, "ECDSA brainpoolP256r1");
	strcpy(d->dsSubject, "Document Signer Passport, Utopia Printing Office, UTO");
	strcpy(d->dsIssuer, "csca-utopia, UTO");
	strcpy(d->dsFrom, "2014-02-03"), strcpy(d->dsTo, "2024-08-03");
	d->photoLen = 14912, d->photoOff = 88, d->photoJp2 = true;
}
static void scnMrtd(void) { mrtdFill(); simMrtd(&mrtdSpec); }
static void scnMrtdBad(void)
{
	MrtdDoc d = mrtdSpec;
	d.ok = 0x4002, d.bad = 0x4, d.sig = PA_UNSUPPORTED;
	strcpy(d.sigAlg, "RSA-PSS 4096"), strcpy(d.paWhy, "RSA key too big for the app"), strcpy(d.access, "BAC");
	simMrtd(&d);
}
static void scnMrtdNpa(void)
{
	MrtdDoc d;
	memset(&d, 0, sizeof(d));
	strcpy(d.access, "PACE (CAN)");
	d.f[1].sw = d.f[2].sw = d.f[MRTD_SOD].sw = 0x6982, d.f[MRTD_COM].sw = 0x6A82;
	simMrtd(&d);
}

// the Thales IDPrime 3940 FIDO's getInfo, as read (2026-11-03)
static FidoInfo fidoKey;
static void fidoFill(void)
{
	static const char *info = "A50182665532465F5632684649444F5F325F3002816B686D61632D7365637265740350B50D5E0A7F8149599B12"
		"F4540740750304A262726BF569636C69656E7450696EF4068101";
	static u8 b[256];
	int n = scUnhex(info, b, sizeof(b));
	memset(&fidoKey, 0, sizeof(fidoKey));
	FidoInfo *f = &fidoKey;
	f->maxMsg = f->maxCredList = f->maxCredIdLen = f->minPin = f->firmware = f->remainingRk = f->pinRetries = -1;
	strcpy(f->u2f, "U2F_V2");
	f->infoSw = 0x9000;
	f->ctap2 = fidoParseInfo(f, b, n);
	if (!f->ctap2 || f->nver != 2 || f->nopt != 2 || fidoOpt(f, "clientPin") != 0 || !fidoModel(f->aaguid))
		printf("fido: getInfo parse wrong\n");
}
static void scnFido(void) { fidoFill(); simFido(&fidoKey); }
static void scnFidoPin(void)
{
	FidoInfo f = fidoKey;
	f.opt[1].on = true, f.pinRetries = 7;
	strcpy(f.ver[f.nver++], "FIDO_2_1");
	strcpy(f.ext[f.next++], "credProtect"), strcpy(f.ext[f.next++], "largeBlobKey");
	strcpy(f.opt[f.nopt].name, "uv"), f.opt[f.nopt++].on = false;
	strcpy(f.opt[f.nopt].name, "credMgmt"), f.opt[f.nopt++].on = true;
	f.alg[f.nalg++] = -7, f.alg[f.nalg++] = -8;
	f.pinProto[f.npin++] = 2;
	strcpy(f.trans[f.ntrans++], "nfc"), strcpy(f.trans[f.ntrans++], "usb");
	f.remainingRk = 25, f.minPin = 4, f.maxMsg = 1200, f.maxCredList = 8, f.maxCredIdLen = 128, f.firmware = 0x050704;
	simFido(&f);
}
static void scnFidoU2f(void)
{
	FidoInfo f = { 0 };
	strcpy(f.u2f, "U2F_V2");
	f.infoSw = 0x6D00;
	simFido(&f);
}

static void kbDone(const char *s) { (void)s; }
static void dateDone(int y, int m, int d) {}
static void scnDate(void) { entryDate("Date of birth", "As printed on the document (the MRZ has it as YYMMDD).", 1974, 8, 12, 1906, 2026, dateDone); }
static void scnDateBad(void) { entryDate("Expiry date", "As printed on the document.", 2025, 2, 31, 2000, 2099, dateDone); }
static void scnKbText(void) { entryText("Write a URL", "https://..., tel:..., mailto:...", "https://example.org/a?b=c", 511, 0, kbDone); }
static void scnKbHex(void) { entryText("APDU", "CLA INS P1 P2 [Lc data] [Le], in hex.", "00A4040007A0000000041010", 522, ENTRY_HEX, kbDone); }
static void scnKbPw(void) { entryText("OATH password", "This applet has a password.", "hunter2", 127, ENTRY_HIDE, kbDone); }
static void scnEmuMenu(void) { simEmuMenu(); }
static void scnJc(void) { simJc(false); }
static void scnJcEmpty(void) { simJc(true); }
static void scnEmuIdle(void) { simEmuRun(false); }
static void scnEmuWritten(void) { simEmuRun(true); }
static void scnEmuUid(void) { simEmuMode(0); }
static void scnEmuLog(void) { simEmuMode(1); }
static void scnEmuMfu(void) { simEmuMfu(false); }
static void scnEmuMfuDone(void) { simEmuMfu(true); }
static void scnTear(void) { simTearScan(); }
static void scnTearCnt(void) { simTearCounter(); }

static IcCard icc;
static void icFill(bool found, bool decrypted)
{
	static const u8 dump[10][8] = {
		{ 0x01, 0x02, 0x03, 0x04, 0xF7, 0xFF, 0x12, 0xE0 }, { 0x12, 0xFF, 0xFF, 0xFF, 0xE9, 0x7F, 0xFF, 0x3C },
		{ 0xFF, 0xFF, 0xFF, 0xFF, 0x11, 0xFC, 0xFF, 0xFF }, { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 },
		{ 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11 }, { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
		{ 0x03, 0x03, 0x03, 0x03, 0x00, 0x03, 0xE0, 0x17 }, { 0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18 },
		{ 0x2A, 0xD4, 0xC8, 0x21, 0x1F, 0x99, 0x68, 0x71 }, { 0x2A, 0xD4, 0xC8, 0x21, 0x1F, 0x99, 0x68, 0x71 } };
	memset(&icc, 0, sizeof(icc));
	memcpy(icc.csn, dump[0], 8);
	icConfig(dump[1], &icc.cfg);
	icc.nblocks = icc.cfg.lastBlock + 1;
	for (int b = 0; b < icc.nblocks; b++) {
		bool hdr = b < 3 || b == 5;
		icc.have[b] = found || hdr;
		memcpy(icc.blocks[b], b < 10 ? dump[b] : dump[5], 8);
	}
	icc.keysTried = found ? 404 : 1487;
	if (found) {
		icc.kdKnown = icc.kcKnown = true;
		memcpy(icc.kd, dump[3], 8), memcpy(icc.kc, dump[4], 8);
		icc.kdKind = IC_KEY_ELITE, icc.kcKind = IC_KEY_STD;
		snprintf(icc.kdLabel, sizeof(icc.kdLabel), "elite dictionary");
		snprintf(icc.kcLabel, sizeof(icc.kcLabel), "default: from HID multiclassSE reader");
		icCredential(icc.blocks[0], icc.nblocks, NULL, &icc.cred); // encrypted: no transport key here
		if (decrypted) { // what the transport key gives for this card: C1k35s FC 1234 CN 567890
			icc.cred.encrypted = false;
			icc.cred.bits = 35;
			icc.cred.value = 0x69A5154A4ULL;
			icWiegand(icc.cred.value, 35, &icc.cred);
		}
	}
}
static void scnIclass(void) { icFill(true, true); simIclass(&icc); }
static void scnIclassEnc(void) { icFill(true, false); simIclass(&icc); }
static void scnIclassNoKey(void) { icFill(false, false); simIclass(&icc); }
static void scnIclassMenu(void) { simIclassMenu(); }
static void oathEmpty(void)
{
	OathInfo o = oathYk;
	o.n = 0;
	simOath(&o, -240);
}
static void oathAdd(void) { simOathAdd(); }
static void kbdHex(void) { simKbdText = "00A4040007A0000005272101"; }
static void dfCard(void) { simDfCard(&cardDf, &dfi, 1, ""); }
static void dfIsoCard(void) { simDfCard(&card10, &dfIso, 0, "GetVersion: permission denied 9D (not a DESFire)"); }
static void dfData(void) { simDfData(0, 3); }
static void dfDataShort(void) { simDfData(0, 0); }
static void dfValueData(void) { simDfData(0, 3); }
static void entryDone(const u8 *b, u32 len) {}
static void entryDoneDec(s64 v) {}
static void entryKey(void)
{
	static const u8 k[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
	entryHex("DESFire: key 1 of A1A1A1", "AES key (16 bytes). It authenticates key 1 and goes into the dictionary.", 16, k, entryDone);
}
static void entryData(void)
{
	u8 d[96];
	for (int i = 0; i < 96; i++) d[i] = "WAVELYNX TECH 01 "[i % 17];
	entryHex("DESFire: write A1A1A1 file 03", "New contents (96 bytes), written in full mode with key 2.", 96, d, entryDone);
}
static void entryValue(void)
{
	entryDec("DESFire: credit A1A1A1 file 04", "Amount to add to the value (limit 2000000000).", 0, 2147483647, 1000, entryDoneDec);
}
static void dfKeyedCard(void) { simDfCard(&cardDf, &dfKeyed, 1, ""); }
static void dfKeyedData(void) { simDfData(0, 2); }
static void dfRandomCard(void)
{
	static DfInfo r;
	static const Card c = { .uidLen = 4, .uid = { 0x08, 0x0E, 0xAF, 0xF8 }, .atqa = { 0x04, 0x03 }, .sak = 0x20 };
	r = dfKeyed;
	r.randomUid = r.hasRealUid = true;
	memcpy(r.realUid, "\x04\x4D\x42\x6A\x9F\x23\x90", 7);
	simDfCard(&c, &r, 1, "");
}

#define D KEYS(KEY_DOWN)
#define U KEYS(KEY_UP)
#define R KEYS(KEY_RIGHT)
#define L KEYS(KEY_LEFT)
#define A KEYS(KEY_A)
#define B KEYS(KEY_B)
#define X KEYS(KEY_X)
#define Y KEYS(KEY_Y)

static const SimStep script[] = {
	// root menu, every entry's help
	CALL(reset), SHOT("root_0"), D, SHOT("root_1"), D, SHOT("root_2"), D, SHOT("root_3"), D, SHOT("root_4"), D,
	SHOT("root_5"), D, SHOT("root_6"),
	CALL(reset), CALL(tagOdd), SHOT("tag_unsupported"), B, SHOT("root_lastcard"),
	CALL(fillLog), KEYS(KEY_SELECT), SHOT("log"), B,
	CALL(simHome), SHOT("touch_locked"), TOUCH(150, 200), D, SHOT("touch_locked_tap"), CALL(simHome), SHOT("touch_unlocked"),
	CALL(reset), CALL(simTools), SHOT("tools_0"), D, SHOT("tools_1"), D, SHOT("tools_2"), D, SHOT("tools_3"),
	CALL(fieldDim), SHOT("tools_meter_dim"), CALL(fieldLive), CALL(simTune), SHOT("tuning"), D, D, D, D, D, D, D, D, D, D,
	D, D, D, D, D, D, D, D, D, D, SHOT("tuning_settled"), CALL(busyEnd), CALL(reset),
	CALL(fieldLive), CALL(busyRead), SHOT("busy_read"), CALL(busyStop), SHOT("busy_stopping"), CALL(busyChip), SHOT("busy_chip"),
	CALL(busyEnd), CALL(toastHome), SHOT("toast_home"), CALL(toastLong), SHOT("toast_long"),

	// MIFARE Classic
	CALL(reset), CALL(mfcMenu), D, D, D, SHOT("mfc_menu_enterkey"), A, SHOT("mfc_enterkey"), A, SHOT("mfc_enterkey_added"), B,
	D, SHOT("mfc_menu_gtupwd"), A, KEYS(KEY_UP), A, SHOT("mfc_gtupwd_set"),
	CALL(reset), CALL(mfuMenu), D, D, SHOT("mfu_menu_pwd"), A, SHOT("mfu_pwd_entry"), B,
	CALL(reset), CALL(mfcMenu), SHOT("mfc_menu_0"), D, SHOT("mfc_menu_1"), D, SHOT("mfc_menu_2"),
	CALL(reset), CALL(mfcMenu), D, D, D, D, D, SHOT("mfc_menu_download"),
	CALL(reset), CALL(mfuMenu), D, D, D, D, SHOT("mfu_menu_download"),
	CALL(reset), CALL(dfMenu), D, D, D, SHOT("df_menu_download"),
	CALL(reset), CALL(mfcMenu), D, D, A, SHOT("mfc_files"), X, SHOT("mfc_files_popup"), D, A, SHOT("mfc_files_clone_confirm"), B, Y, SHOT("mfc_files_delete_confirm"), B,
	R, SHOT("mfc_files_page2"), L,
	D, D, D, A, SHOT("mfc_files_bad"), B,
	CALL(reset), CALL(mfcNone), SHOT("mfc_card_nomagic"), CALL(mfcGen1a2), SHOT("mfc_card_gen1a_gen2"),
	CALL(mfcAll), SHOT("mfc_card_all"), CALL(mfcGtu), SHOT("mfc_card_gtu"), CALL(mfcUsc), SHOT("mfc_card_uscuid"),
	CALL(mfcNotClassic), SHOT("mfc_card_notclassic"),
	CALL(mfcGtu), CALL(mfcGen4), SHOT("gen4_0"), D, SHOT("gen4_1"), D, SHOT("gen4_2"), R, A, SHOT("gen4_confirm"), B,
	CALL(mfcGtuUl), SHOT("gen4_ultralight"),
	CALL(reset), CALL(mfcReadOk), SHOT("mfc_read_done"), CALL(reset), CALL(mfcReadKdf), SHOT("mfc_read_kdf"), CALL(reset), CALL(mfcReadNoSd), SHOT("mfc_read_nosd"),
	CALL(reset), CALL(mfcCloneForce), SHOT("mfc_clone_force"), CALL(reset), CALL(mfcCloneRefused),
	SHOT("mfc_clone_refused"), CALL(reset), CALL(mfcCloneLost), SHOT("mfc_clone_lost"),

	// Classic editor
	CALL(reset), CALL(ed1k), SHOT("ed_block0"), D, SHOT("ed_data"), X, SHOT("ed_data_actions"), B, D, SHOT("ed_data2"), D, SHOT("ed_trailer"),
	R, R, R, R, R, R, A, SHOT("ed_acl_editor"), R, R, SHOT("ed_acl_editor_locked"), B,
	X, SHOT("ed_actions"), B, Y, X, SHOT("ed_actions_paste"), B, U, A, U, SHOT("ed_editing"), B,
	D, D, SHOT("ed_value"), X, SHOT("ed_value_actions"), U, SHOT("ed_value_actions_end"), B, CALL(edValueOk), SHOT("ed_value_ok"), A, U, B, SHOT("ed_modified"),
	KEYS(KEY_R), D, D, D, SHOT("ed_bad_acl"), B, SHOT("ed_close_confirm"), B,
	X, D, D, A, SHOT("ed_write_trailer"), B,
	CALL(edWbOk), SHOT("ed_wb_ok"), CALL(reset), CALL(ed1k), CALL(edWbFail), SHOT("ed_wb_fail"),
	CALL(reset), CALL(ed1k), KEYS(KEY_L), KEYS(KEY_L), SHOT("ed_unread"),
	CALL(reset), CALL(ed4k), KEYS(KEY_L), SHOT("ed_4k_last"), U, U, SHOT("ed_4k_scroll"),
	D, D, R, R, R, R, R, R, A, SHOT("ed_4k_acl"), B,

	// Ultralight / NTAG
	CALL(reset), CALL(mfuMenu), SHOT("mfu_menu_0"), D, SHOT("mfu_menu_1"), D, SHOT("mfu_menu_2"), D,
	A, SHOT("mfu_files"), X, SHOT("mfu_files_popup"), A, SHOT("mfu_files_restore_confirm"), B, X, D, A,
	SHOT("mfu_files_clone_confirm"), B, D, D, A, SHOT("mfu_files_bad"), B,
	CALL(reset), CALL(mfuN215), SHOT("mfu_card_ntag215_gtu"), CALL(mfuEv1), SHOT("mfu_card_ev1"),
	CALL(mfuUlc), SHOT("mfu_card_ulc"), CALL(mfuPlain), SHOT("mfu_card_plain"), CALL(mfuUnk), SHOT("mfu_card_unknown"),
	CALL(mfuCfgLocked), SHOT("mfu_card_cfg_locked"), CALL(cardUlcKey), SHOT("mfu_card_ulc_key"), Y, SHOT("mfu_card_ulc_menu"), D, A, A, SHOT("mfu_ulc_newkey_confirm"), B,
	CALL(reset), CALL(pickEv1Locked), SHOT("mfu_pick_ev1_unknown"), D, D, A, SHOT("mfu_pick_confirm_unknown"), B,
	U, U, A, SHOT("mfu_pick_entry"), B,
	CALL(reset), CALL(ndefRecords), SHOT("ndef_records"), D, SHOT("ndef_records_sel"), CALL(simNdefActions), SHOT("ndef_actions"), B,
	CALL(ndefEmptyUrl), SHOT("ndef_write_confirm"), B,
	CALL(reset), CALL(amiiboOk), SHOT("amiibo_ok"), CALL(simAmiiboActions), SHOT("amiibo_actions"), B,
	CALL(amiiboCopyLock), SHOT("amiibo_copy_lock"), B, CALL(amiiboCopyFresh), SHOT("amiibo_copy_fresh"), B,
	CALL(reset), CALL(amiiboUnlocked), CALL(simAmiiboActions), SHOT("amiibo_actions_unlocked"), KEYS(KEY_UP), A,
	SHOT("amiibo_lock_confirm"), A, SHOT("amiibo_lock_confirm2"), B,
	CALL(reset), CALL(amiiboUnknown), SHOT("amiibo_unknown"),
	CALL(reset), CALL(amiiboOpenMenu), SHOT("amiibo_menu"), D, SHOT("amiibo_menu_new"), D, SHOT("amiibo_menu_download"),
	CALL(simAmiiboDownloadFailed), SHOT("amiibo_download_failed"), B, U, A, SHOT("amiibo_list"),
	R, SHOT("amiibo_list_series"), R, R, R, SHOT("amiibo_list_series4"), KEYS(KEY_L), SHOT("amiibo_list_series_back"),
	A, SHOT("amiibo_list_popup"), A, SHOT("amiibo_list_confirm"), B, D, A, SHOT("amiibo_list_confirm_lock"), B,
	CALL(kbdMario), Y, SHOT("amiibo_list_search"), CALL(kbdNone), Y, SHOT("amiibo_list_nomatch"), B,
	CALL(reset), CALL(amiiboNewFile), SHOT("amiibo_new_file"), CALL(reset), CALL(amiiboBad), SHOT("amiibo_bad"), CALL(reset), CALL(ndefEmpty), SHOT("ndef_empty"),
	CALL(reset), CALL(pickN215), SHOT("mfu_pick_n215_lim5"), D, A, SHOT("mfu_pick_confirm_lim5"), B,
	CALL(reset), CALL(pickAmiibo), SHOT("mfu_pick_amiibo"), D, D, D, D, D, D, D, D, D, D, SHOT("mfu_pick_scrolled"),
	CALL(reset), CALL(pickUlc), SHOT("mfu_pick_ulc"), A, SHOT("mfu_pick_ulc_entry"), B,
	CALL(reset), CALL(readPwdPack), SHOT("mfu_read_pwd_pack"), CALL(reset), CALL(readUlcKey), SHOT("mfu_read_ulc_key"),
	CALL(reset), CALL(mfuReadOk), SHOT("mfu_read_done"), CALL(reset), CALL(mfuRestoreOk), SHOT("mfu_restore_ok"),
	CALL(reset), CALL(mfuRestoreFail), SHOT("mfu_restore_fail"), CALL(reset), CALL(mfuCloneOk), SHOT("mfu_clone_ok"),
	CALL(reset), CALL(mfuCloneFail), SHOT("mfu_clone_fail"),

	// Ultralight editor
	CALL(reset), CALL(edN215), SHOT("mfued_p0"), D, D, SHOT("mfued_p2"), D, SHOT("mfued_p3"), D, SHOT("mfued_user"),
	X, SHOT("mfued_actions"), D, D, A, SHOT("mfued_write_confirm"), B, X, D, D, D, D, D, D, A, SHOT("mfued_restore_confirm"), B,
	A, U, B, SHOT("mfued_modified"),
	CALL(reset), CALL(edN215), U, U, U, U, SHOT("mfued_cfg0"), D, SHOT("mfued_cfg1"), D, SHOT("mfued_pwd"),
	D, SHOT("mfued_pack"),
	CALL(reset), CALL(edUlc), U, U, U, U, U, U, SHOT("mfued_ulc_auth0"), D, SHOT("mfued_ulc_auth1"), D, SHOT("mfued_ulc_key"),
	U, U, U, U, SHOT("mfued_ulc_counter"),
	CALL(reset), CALL(edEv1), U, U, U, U, U, SHOT("mfued_ev1_cfg"),
	CALL(reset), CALL(edUnk), U, SHOT("mfued_unknown"),

	// DESFire
	CALL(reset), CALL(dfMenu), SHOT("df_menu"),
	CALL(dfCard), SHOT("df_card"), D, D, D, SHOT("df_card_scrolled"), U, U, U,
	A, SHOT("df_app0"), D, D, D, D, D, D, SHOT("df_app0_scrolled"), CALL(dfData), SHOT("df_data"), B,
	CALL(dfDataShort), SHOT("df_data_short"), B,
	R, SHOT("df_app1"), R, SHOT("df_app2"), R, SHOT("df_app3"), R, SHOT("df_app4_selerr"), R, SHOT("df_app5_keyerr"),
	R, SHOT("df_app6_nofiles"), B,
	CALL(reset), CALL(dfIsoCard), SHOT("df_iso_card"),
	CALL(reset), CALL(dfKeyedCard), SHOT("df_keyed_card"), A, SHOT("df_keyed_app0"), D, D, D, D, D, SHOT("df_keyed_app0_scrolled"),
	R, SHOT("df_keyed_app1"), R, SHOT("df_keyed_app2"), B,
	CALL(reset), CALL(entryKey), SHOT("entry_key"), R, R, R, KEYS(KEY_UP), SHOT("entry_key_edit"), TOUCH(40, 30),
	SHOT("entry_key_touch"), B,
	CALL(reset), CALL(entryData), KEYS(KEY_R), KEYS(KEY_R), SHOT("entry_data"), B,
	CALL(reset), CALL(entryValue), SHOT("entry_value"), TOUCH(150, 30), KEYS(0), TOUCH(90, 170), KEYS(0), TOUCH(30, 30), KEYS(0), SHOT("entry_value_typed"),
	TOUCH(260, 30), SHOT("entry_value_del"), TOUCH(260, 120), SHOT("entry_value_cancel"),
	CALL(reset), CALL(dfKeyedCard), Y, SHOT("df_card_menu"), D, A, SHOT("df_create_app"), D, A, SHOT("df_create_app_type"), B,
	TOUCH(160, 70), KEYS(0), SHOT("df_create_app_keys"), B, B,
	Y, D, D, D, D, D, A, SHOT("df_format_confirm"), B,
	Y, D, D, D, D, A, SHOT("df_picc_ks_entry"), A, SHOT("df_picc_ks_confirm"), B,
	Y, D, A, D, D, D, D, A, SHOT("df_create_app_iso"), A, B,
	Y, D, D, D, A, SHOT("df_change_picc_type"), A, SHOT("df_change_picc_entry"), A, SHOT("df_change_picc_confirm"), B,
	A, Y, SHOT("df_app_menu"), D, A, SHOT("df_create_file"), D, A, D, D, A, SHOT("df_create_file_value"), B,
	Y, A, SHOT("df_write_std"), B, D, D, D, Y, A, SHOT("df_write_value"), A, SHOT("df_write_value_amount"), B,
	Y, D, D, D, D, A, SHOT("df_change_key_no"), A, SHOT("df_change_key_new"), B,
	Y, D, D, D, D, D, D, D, A, SHOT("df_delete_app_confirm"), B,
	Y, D, D, D, D, D, A, SHOT("df_app_ks_entry"), KEYS(KEY_DOWN), A, SHOT("df_app_ks_confirm"), B, B,
	CALL(reset), CALL(dfRandomCard), SHOT("df_random_card"),
	CALL(reset), CALL(dfKeyedCard), CALL(dfKeyedData), SHOT("df_keyed_data256"), D, D, D, D, SHOT("df_keyed_data256_end"), B,
	CALL(reset), CALL(dfMenu), CALL(dfIsoCard), B, SHOT("df_menu_lastcard"),

	// smart cards
	CALL(reset), CALL(scMenu), SHOT("sc_menu"), CALL(scCard), SHOT("sc_card"), D, D, D, D, D, SHOT("sc_card_scrolled"),
	KEYS(KEY_R), SHOT("sc_details"), B, U, U, U, A, SHOT("sc_details_mgmt"), B, Y, SHOT("sc_card_menu"), B, B, SHOT("sc_menu_lastcard"),
	CALL(reset), CALL(scBareCard), SHOT("sc_card_bare"),
	CALL(reset), CALL(scConsoleEmpty), SHOT("sc_console_empty"), CALL(scConsole), SHOT("sc_console"), U, U, U, SHOT("sc_console_up"),
	CALL(reset), CALL(scnGpList), SHOT("gp_list"), D, D, D, SHOT("gp_list_locked"), D, D, D, D, D, D, D, SHOT("gp_list_end"),
	A, SHOT("gp_actions"), A, SHOT("gp_details"), B, A, D, A, SHOT("gp_delete_pkg"), B, U, U, U, U, U, U, U, U, U, A, D, A,
	SHOT("gp_delete_applet"), B, Y, SHOT("gp_menu"), D, A, SHOT("gp_key_entry"), B,
	CALL(reset), CALL(gpNoKeys), SHOT("gp_nokeys"), CALL(gpCaps), SHOT("gp_caps"), B,
	CALL(reset), CALL(scnOathList), SHOT("oath_list"), D, D, D, D, D, D, D, D, D, SHOT("oath_list_end"), Y, SHOT("oath_menu"), B,
	CALL(oathAdd), SHOT("oath_add"), B, CALL(oathEmpty), SHOT("oath_empty"),
	CALL(reset), CALL(scnEmv), SHOT("emv_card"), D, D, D, SHOT("emv_card_log_end"), CALL(scnEmvFull), SHOT("emv_card_full"),
	KEYS(KEY_R), SHOT("emv_app2"),
	CALL(reset), CALL(scnDate), SHOT("date"), R, SHOT("date_month"), U, SHOT("date_month_up"), CALL(reset), CALL(scnDateBad), SHOT("date_bad"),
	CALL(reset), CALL(scnMrtd), SHOT("mrtd_passport"), CALL(scnMrtdBad), SHOT("mrtd_bad"), CALL(scnMrtdNpa), SHOT("mrtd_npa"),
	CALL(reset), CALL(scnEid), SHOT("eid_de"), A, SHOT("eid_menu"), B, CALL(scnEidCan), SHOT("eid_de_can"), CALL(scnEidFail), SHOT("eid_de_fail"), CALL(scnEidBac), SHOT("eid_bac"),
	CALL(reset), CALL(scnFido), SHOT("fido_key"), CALL(scnFidoPin), SHOT("fido_key_pin"), CALL(scnFidoU2f), SHOT("fido_u2f"),

	// keyboard
	CALL(reset), CALL(scnKbText), SHOT("kb_text"), CALL(reset), CALL(scnKbHex), SHOT("kb_hex"),
	CALL(reset), CALL(scnKbPw), SHOT("kb_password"),

	// card emulation
	CALL(reset), CALL(scnEmuMenu), SHOT("emu_menu"), CALL(reset), CALL(scnEmuIdle), SHOT("emu_idle"), CALL(simBusyEnd),
	CALL(reset), CALL(scnEmuWritten), SHOT("emu_written"), CALL(simBusyEnd), CALL(simEmuDone), SHOT("emu_done"),
	CALL(reset), CALL(scnEmuUid), SHOT("emu_uid"), CALL(simBusyEnd), CALL(reset), CALL(scnEmuLog), SHOT("emu_log"), CALL(simBusyEnd),
	CALL(reset), CALL(simEmuForm), SHOT("emu_form"), B,
	CALL(reset), CALL(scnEmuMfu), SHOT("emu_mfu"), CALL(simBusyEnd), CALL(reset), CALL(scnEmuMfuDone), SHOT("emu_mfu_save"), B,
	CALL(reset), CALL(simEmuMfc), SHOT("emu_mfc"), CALL(simBusyEnd),
	CALL(reset), CALL(simEmuDf), SHOT("emu_df"), CALL(simBusyEnd),
	CALL(reset), CALL(scnJcEmpty), SHOT("jc_empty"), CALL(reset), CALL(scnJc), SHOT("jc_list"), KEYS(KEY_X),
	SHOT("jc_actions"), B, D, D, D, D, SHOT("jc_lib"), KEYS(KEY_X), D, A, SHOT("jc_lib_del"), A, SHOT("jc_lib_used"), B, CALL(simEmuJc), SHOT("jc_emu"), CALL(simBusyEnd),
	// tear-off
	CALL(reset), CALL(scnTear), SHOT("tear_scan"), D, D, D, D, D, D, D, D, D, D, SHOT("tear_scan_end"),
	CALL(reset), CALL(scnTearCnt), SHOT("tear_counter"), CALL(simBusyEnd),

	// iClass
	CALL(reset), CALL(scnIclassMenu), SHOT("iclass_menu"), CALL(scnIclass), SHOT("iclass_card"), D, D, D, D, D, D, D, D,
	SHOT("iclass_card_scrolled"), CALL(reset), CALL(scnIclassEnc), SHOT("iclass_card_encrypted"),
	CALL(reset), CALL(scnIclassNoKey), SHOT("iclass_card_nokey"),
	END,
};

int main(int argc, char **argv)
{
	const char *out = argc > 1 ? argv[1] : "out";
	mkdir(out, 0777);
	if (chdir(out)) return perror(out), 1;
	simSetOutDir(".");
	fillDump(&mf1k, 16);
	fillDump(&mf4k, 40);
	static const u8 vN215[] = { 0x00, 0x04, 0x04, 0x02, 0x01, 0x00, 0x11, 0x03 };
	static const u8 vEv1[] = { 0x00, 0x04, 0x03, 0x01, 0x01, 0x00, 0x0E, 0x03 };
	static const u8 vUnk[] = { 0x00, 0x04, 0x07, 0x02, 0x01, 0x00, 0x13, 0x03 };
	fillMfu(&n215, vN215, 0, NULL);
	fillMfu(&ev1, vEv1, 0, NULL);
	fillMfu(&ulc, NULL, 0, &mfuTypeULC);
	ulc.info.hasSig = false;
	fillMfu(&ulPlain, NULL, 0, mfuTypeForPages(16));
	fillMfu(&unk, vUnk, 0, NULL);
	fillDf();
	fillSc();
	sdSetup();
	uiInit();
	simScript(script);
	appRun();
	uiExit();
	return 0;
}
