// MIFARE DESFire without keys over ISO-DEP, see desfire.h.

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include "desfire.h"
#include "isodep.h"
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
	}
	return "unknown status";
}

// One native command, AF frames followed; their data (without the status) joined into out, the last
// status in *st. The data length, -1 = no answer (isoDepWhy), -2 = monitor error.
static int cmd(const u8 *c, u32 len, u8 *out, u32 max, u8 *st)
{
	u8 a[64], af = 0xAF;
	u32 n = 0;
	for (int i = 0;; i++) {
		int k = isoDepTx(c, len, a, sizeof(a));
		if (k < 0) return -2;
		if (!k) return -1;
		*st = a[0];
		u32 m = (u32)k - 1 < max - n ? (u32)k - 1 : max - n;
		memcpy(out + n, a + 1, m);
		n += m;
		if (a[0] != 0xAF || i == 31) return n;
		c = &af, len = 1;
	}
}

#define RUN(c, len, out, max) ({ \
	int r_ = cmd(c, len, out, max, &st); \
	if (r_ == -2) FAIL(-1, "monitor"); \
	if (r_ == -1) FAIL(0, "lost the card: %s", isoDepWhy()); \
	r_; })

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

bool dfFreeRead(const DfFile *f)
{
	return !f->st && f->len >= 4 && ((f->set[3] >> 4) == 0xE || (f->set[2] >> 4) == 0xE);
}

// A file with free read access: ReadData / GetValue / ReadRecords into the pool.
static int readFile(DfInfo *d, DfFile *f)
{
	u8 c[8] = { 0xBD, f->fid }, st, t = f->set[0];
	u32 len = 2, room = sizeof(d->pool) - d->poolUsed, want = DF_MAX_DATA;
	if (t <= 1) { // offset 0, length (24 bit)
		u32 size = f->len >= 7 ? le24(f->set + 4) : 0;
		want = size < DF_MAX_DATA ? size : DF_MAX_DATA;
		c[5] = want, c[6] = want >> 8, len = 8;
	} else if (t == 2) {
		c[0] = 0x6C, want = 4;
	} else if (t == 3 || t == 4) { // offset 0, count 0 = every record
		c[0] = 0xBB, len = 8;
	} else {
		return 1;
	}
	if (!want || room < want) return 1;
	int n = RUN(c, len, d->pool + d->poolUsed, want);
	f->hasData = true, f->dataSt = st;
	if (st) return 1;
	f->dataOff = d->poolUsed, f->dataLen = n;
	d->poolUsed += n;
	return 1;
}

static int readApp(DfInfo *d, DfApp *a)
{
	u8 c[4] = { 0x5A, a->aid, a->aid >> 8, a->aid >> 16 }, buf[96], st;
	RUN(c, 4, buf, sizeof(buf));
	if ((a->selSt = st)) return 1;
	c[0] = 0x45;
	int n = RUN(c, 1, buf, sizeof(buf));
	a->keySt = st ? st : n < 2 ? 0x7E : 0;
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
		f->fid = buf[i];
		u8 fc[2] = { 0xF5, f->fid };
		n = RUN(fc, 2, f->set, sizeof(f->set));
		f->st = st, f->len = n;
		int r;
		if (dfFreeRead(f) && (r = readFile(d, f)) <= 0) return r;
	}
	return 1;
}

int dfReadInfo(DfInfo *d)
{
	memset(d, 0, sizeof(*d));
	int r = isoDepActivate(d->ats, sizeof(d->ats));
	if (r <= 0) FAIL(r, "%s", isoDepWhy());
	d->atsLen = d->ats[0] < sizeof(d->ats) ? d->ats[0] : sizeof(d->ats);
	u8 c[4] = { 0x60 }, buf[128], st;
	int n = RUN(c, 1, d->ver, sizeof(d->ver));
	if (st || n < 14) FAIL(0, "GetVersion: %s (not a DESFire)", n < 14 && !st ? "short answer" : dfStatusName(st));
	d->verLen = n;
	logp("DESFire: %s, %lu bytes\n", dfVersionName(d), dfStorage(d->ver[5]));

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
	if ((st == 0x90 || !st) && n >= 56) d->hasSig = true, memcpy(d->sig, buf, 56);

	c[0] = 0x6A;
	n = RUN(c, 1, buf, sizeof(buf));
	if ((d->appSt = st)) {
		logp("app list: %s\n", dfStatusName(st));
		return 1;
	}
	d->napps = n / 3;
	for (int i = 0; i < d->napps && i < DF_MAX_APPS; i++) d->apps[i].aid = le24(buf + 3 * i);
	// GetDFNames: one app per frame (AID, ISO FID, DF name)
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
		if ((r = readApp(d, &d->apps[i])) <= 0) return r;
		logp("app %06lX: %d files\n", d->apps[i].aid, d->apps[i].nfiles);
	}
	c[0] = 0x5A, c[1] = c[2] = c[3] = 0;
	RUN(c, 4, buf, sizeof(buf));
	return 1;
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
	static const char *types[] = { "standard", "backup", "value", "linear record", "cyclic record", "TMAC" };
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
	snprintf(out, max, "read %s, write %s, read/write %s, change %s", r, w, rw, ch);
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

bool dfSaveInfo(const DfInfo *d, char *path, u32 pathMax)
{
	char uid[21] = "";
	if (d->verLen >= 21)
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
	fprintf(fp, "# nfcprobe DESFire info (no keys)\nUID %s\n", uid);
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
	if (d->hasSig) hexLine(fp, "signature (not verified) ", d->sig, 56);
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
	if (d->appSt) fprintf(fp, "  applications: %s\n", dfStatusName(d->appSt));
	else fprintf(fp, "  %d application%s\n", d->napps, d->napps == 1 ? "" : "s");
	for (int i = 0; i < d->napps && i < DF_MAX_APPS; i++) {
		const DfApp *a = &d->apps[i];
		fprintf(fp, "\nApplication %06lX\n", a->aid);
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
