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
	mkdir(MF_DIR, 0777);
	mkdir(MF_DUMPS, 0777);
	mkdir(MFU_DIR, 0777);
	mkdir(DF_DIR, 0777);
	FILE *k = fopen(MF_KEYS, "w");
	fprintf(k, "A0A1A2A3A4A5\nD3F7D3F7D3F7\n");
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
static void busyEnd(void) { simBusyEnd(); }
static void toastHome(void) { toast("HOME is off while NFC is ours: START exits"); }
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
static void mfcReadNoSd(void) { simMfcRead(&mf1k, 60, ""); }
static void mfcCloneForce(void) { simMfcClone(0, "block 0 of a Gen2 card: the UID can't change again (force)"); }
static void mfcCloneRefused(void) { simMfcClone(0, "not a magic card (no Gen1a, Gen2, GTU or USCUID answer)"); }
static void mfcCloneLost(void) { simMfcClone(-1, ""); }
static void ed1k(void) { editorOpen(&mf1k, MF_DUMPS "/04B1B1B1B1B1B11122334455-12.bin"); }
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
static void edN215(void) { mfuEditorOpen(&n215, MFU_DIR "/amiibo_super_mario_odyssey_wedding_peach_backup_2.bin"); }
static void edUlc(void) { mfuEditorOpen(&ulc, MFU_DIR "/04C8E3BA064F80.bin"); }
static void edEv1(void) { mfuEditorOpen(&ev1, MFU_DIR "/04C8E3BA064F80-2.bin"); }
static void edUnk(void) { mfuEditorOpen(&unk, MFU_DIR "/11223300000000.bin"); }

static void dfMenu(void) { simDfMenu(); }
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
	CALL(busyRead), SHOT("busy_read"), CALL(busyStop), SHOT("busy_stopping"), CALL(busyChip), SHOT("busy_chip"),
	CALL(busyEnd), CALL(toastHome), SHOT("toast_home"), CALL(toastLong), SHOT("toast_long"),

	// MIFARE Classic
	CALL(reset), CALL(mfcMenu), D, D, D, SHOT("mfc_menu_enterkey"), A, SHOT("mfc_enterkey"), A, SHOT("mfc_enterkey_added"), B,
	D, SHOT("mfc_menu_gtupwd"), A, KEYS(KEY_UP), A, SHOT("mfc_gtupwd_set"),
	CALL(reset), CALL(mfuMenu), D, D, SHOT("mfu_menu_pwd"), A, SHOT("mfu_pwd_entry"), B,
	CALL(reset), CALL(mfcMenu), SHOT("mfc_menu_0"), D, SHOT("mfc_menu_1"), D, SHOT("mfc_menu_2"),
	A, SHOT("mfc_files"), X, SHOT("mfc_files_clone_confirm"), B, Y, SHOT("mfc_files_delete_confirm"), B,
	R, SHOT("mfc_files_page2"), L,
	D, D, D, A, SHOT("mfc_files_bad"), B,
	CALL(reset), CALL(mfcNone), SHOT("mfc_card_nomagic"), CALL(mfcGen1a2), SHOT("mfc_card_gen1a_gen2"),
	CALL(mfcAll), SHOT("mfc_card_all"), CALL(mfcGtu), SHOT("mfc_card_gtu"), CALL(mfcUsc), SHOT("mfc_card_uscuid"),
	CALL(mfcNotClassic), SHOT("mfc_card_notclassic"),
	CALL(mfcGtu), CALL(mfcGen4), SHOT("gen4_0"), D, SHOT("gen4_1"), D, SHOT("gen4_2"), R, A, SHOT("gen4_confirm"), B,
	CALL(mfcGtuUl), SHOT("gen4_ultralight"),
	CALL(reset), CALL(mfcReadOk), SHOT("mfc_read_done"), CALL(reset), CALL(mfcReadNoSd), SHOT("mfc_read_nosd"),
	CALL(reset), CALL(mfcCloneForce), SHOT("mfc_clone_force"), CALL(reset), CALL(mfcCloneRefused),
	SHOT("mfc_clone_refused"), CALL(reset), CALL(mfcCloneLost), SHOT("mfc_clone_lost"),

	// Classic editor
	CALL(reset), CALL(ed1k), SHOT("ed_block0"), D, SHOT("ed_data"), D, SHOT("ed_data2"), D, SHOT("ed_trailer"),
	R, R, R, R, R, R, A, SHOT("ed_acl_editor"), R, R, SHOT("ed_acl_editor_locked"), B,
	X, SHOT("ed_actions"), B, Y, X, SHOT("ed_actions_paste"), B, U, A, U, SHOT("ed_editing"), B,
	D, D, SHOT("ed_value"), A, U, B, SHOT("ed_modified"),
	KEYS(KEY_R), D, D, D, SHOT("ed_bad_acl"), B, SHOT("ed_close_confirm"), B,
	X, D, D, A, SHOT("ed_write_trailer"), B,
	CALL(edWbOk), SHOT("ed_wb_ok"), CALL(reset), CALL(ed1k), CALL(edWbFail), SHOT("ed_wb_fail"),
	CALL(reset), CALL(ed1k), KEYS(KEY_L), KEYS(KEY_L), SHOT("ed_unread"),
	CALL(reset), CALL(ed4k), KEYS(KEY_L), SHOT("ed_4k_last"), U, U, SHOT("ed_4k_scroll"),
	D, D, R, R, R, R, R, R, A, SHOT("ed_4k_acl"), B,

	// Ultralight / NTAG
	CALL(reset), CALL(mfuMenu), SHOT("mfu_menu_0"), D, SHOT("mfu_menu_1"), D, SHOT("mfu_menu_2"),
	A, SHOT("mfu_files"), X, SHOT("mfu_files_popup"), A, SHOT("mfu_files_restore_confirm"), B, X, D, A,
	SHOT("mfu_files_clone_confirm"), B, D, D, A, SHOT("mfu_files_bad"), B,
	CALL(reset), CALL(mfuN215), SHOT("mfu_card_ntag215_gtu"), CALL(mfuEv1), SHOT("mfu_card_ev1"),
	CALL(mfuUlc), SHOT("mfu_card_ulc"), CALL(mfuPlain), SHOT("mfu_card_plain"), CALL(mfuUnk), SHOT("mfu_card_unknown"),
	CALL(mfuCfgLocked), SHOT("mfu_card_cfg_locked"),
	CALL(reset), CALL(mfuReadOk), SHOT("mfu_read_done"), CALL(reset), CALL(mfuRestoreOk), SHOT("mfu_restore_ok"),
	CALL(reset), CALL(mfuRestoreFail), SHOT("mfu_restore_fail"), CALL(reset), CALL(mfuCloneOk), SHOT("mfu_clone_ok"),
	CALL(reset), CALL(mfuCloneFail), SHOT("mfu_clone_fail"),

	// Ultralight editor
	CALL(reset), CALL(edN215), SHOT("mfued_p0"), D, D, SHOT("mfued_p2"), D, SHOT("mfued_p3"), D, SHOT("mfued_user"),
	X, SHOT("mfued_actions"), D, D, A, SHOT("mfued_write_confirm"), B, X, D, D, D, A, SHOT("mfued_restore_confirm"), B,
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
	fillMfu(&ulPlain, NULL, 0, mfuTypeForPages(16));
	fillMfu(&unk, vUnk, 0, NULL);
	fillDf();
	sdSetup();
	uiInit();
	simScript(script);
	appRun();
	uiExit();
	return 0;
}
