// desfire.c's reader side against dfemu.c in one process (isoDepTx wrapped onto dfEmuApdu): the key scan and
// writes in every comm mode, the card taken as an MF3ICD40 (D40), an EV1 and an EV3 (EV2 for AES keys).
#include <stdio.h>
#include <string.h>
#include "desfire.h"
#include "dfemu.h"

static DfInfo src, got;
static int fails;

int __wrap_isoDepActivate(u8 *ats, u32 max)
{
	dfEmuApdu(NULL, 0, NULL, 0);
	memcpy(ats, src.ats, src.atsLen);
	return src.atsLen;
}

int __wrap_isoDepTx(const u8 *inf, u32 len, u8 *out, u32 max)
{
	return dfEmuApdu(inf, len, out, max);
}

static void check(const char *what, bool ok)
{
	printf("%s %s\n", ok ? "OK " : "BAD", what);
	fails += !ok;
}

static const DfFile *fileOf(const DfInfo *d, u32 aid, u8 fid)
{
	for (int i = 0; i < d->napps; i++)
		for (int j = 0; d->apps[i].aid == aid && j < d->apps[i].nfiles; j++)
			if (d->apps[i].files[j].fid == fid) return &d->apps[i].files[j];
	return NULL;
}

static bool data(const DfInfo *d, u32 aid, u8 fid, const void *want, u32 len)
{
	const DfFile *f = fileOf(d, aid, fid);
	if (!f || !f->hasData || f->dataLen != len || memcmp(d->pool + f->dataOff, want, len)) {
		if (f) {
			printf("    got %d bytes:", f->dataLen);
			for (int i = 0; i < f->dataLen; i++) printf(" %02X", d->pool[f->dataOff + i]);
			printf("\n");
		}
		return false;
	}
	return true;
}

static DfKey key(u8 type, const char *hex)
{
	DfKey k = { true, type };
	for (u32 i = 0; i < dfKeyLen(type); i++) sscanf(hex + 2 * i, "%2hhx", &k.key[i]);
	return k;
}

static int op(u32 aid, u8 k, const DfKey *kk, const u8 *c, u32 len, u32 hdr, u8 comm, u8 flags)
{
	int r = dfOp(&got, aid, k, kk, c, len, hdr, comm, flags);
	if (r <= 0) printf("    dfOp: %s\n", dfWhy());
	return r;
}

int main(int argc, char **argv)
{
	static const char *names[] = { "D40 (MF3ICD40)", "EV1", "EV3 (EV2 for AES)" };
	static const u8 major[] = { 0x00, 0x01, 0x33 };
	for (int m = 0; m < 3; m++) {
		printf("--- as %s\n", names[m]);
		if (!dfLoadInfo(&src, argv[1])) return printf("load failed\n"), 1;
		src.ver[3] = major[m];
		dfEmuSet(&src);
		check("scan with keys", dfReadInfo(&got, true) == 1);
		check("  secure messaging picked", m == 0 ? got.d40 : m == 1 ? !got.d40 && !got.ev2 : got.ev2);
		check("  D40 full file via key 0", data(&got, 0x778899, 1, "D40-FULL-FILE-01", 16));
		check("  D40 MAC file via key 1", data(&got, 0x778899, 2, "D40-MAC-FILE", 12));
		check("  AES full file", data(&got, 0x112233, 1, "SECRET-AES-FILE!", 16));
		check("  AES MAC file", data(&got, 0x112233, 2, "EV2-MAC!", 8));
		DfKey des = key(DF_2K3DES, "11223344556677881122334455667788"), k2 = key(DF_2K3DES, "00112233445566778899AABBCCDDEEFF");
		DfKey aes = key(DF_AES, "00112233445566778899AABBCCDDEEFF");
		u8 c[64] = { 0x3D, 0x01, 0, 0, 0, 16, 0, 0 };
		memcpy(c + 8, "WRITTEN-FULL-DES", 16);
		check("write full (DES key)", op(0x778899, 0, &des, c, 24, 7, DF_FULL, 0) == 1);
		c[1] = 2, c[5] = 12;
		memcpy(c + 8, "WRITTEN-MAC!", 12);
		check("write MAC (2K3DES key)", op(0x778899, 1, &k2, c, 20, 7, DF_MACED, 0) == 1);
		c[1] = 1, c[5] = 16;
		memcpy(c + 8, "WRITTEN-FULL-AES", 16);
		check("write full (AES key)", op(0x112233, 1, &aes, c, 24, 7, DF_FULL, 0) == 1);
		c[1] = 2, c[2] = 4, c[5] = 4;
		memcpy(c + 8, "mac?", 4);
		check("write MAC at offset 4 (AES key)", op(0x112233, 1, &aes, c, 12, 7, DF_MACED, 0) == 1);
		u8 big[48] = { 0x3D, 0x01, 0, 0, 0, 32, 0, 0 };
		for (int i = 0; i < 32; i++) big[8 + i] = 0x80 + i;
		check("write 32 plain (free)", op(0x445566, 0, NULL, big, 40, 7, DF_PLAIN, 0) == 1);
		u8 cr[6] = { 0x0C, 0x02, 50, 0, 0, 0 };
		check("credit 50 + commit", op(0x445566, 0, NULL, cr, 6, 1, DF_PLAIN, DF_COMMIT) == 1);
		u8 db[6] = { 0xDC, 0x02, 0x10, 0x27, 0, 0 }; // 10000: below the lower limit
		check("debit 10000 refused", op(0x445566, 0, NULL, db, 6, 1, DF_PLAIN, DF_COMMIT) == 0);
		u8 wr[16] = { 0x3B, 0x03, 0, 0, 0, 8, 0, 0, 4, 4, 4, 4, 4, 4, 4, 4 };
		check("write record + commit", op(0x445566, 0, NULL, wr, 16, 7, DF_PLAIN, DF_COMMIT) == 1);
		wr[8] = 5;
		check("write record, no commit", op(0x445566, 0, NULL, wr, 16, 7, DF_PLAIN, 0) == 1);
		check("rescan", dfReadInfo(&got, true) == 1);
		check("  DES full file written", data(&got, 0x778899, 1, "WRITTEN-FULL-DES", 16));
		check("  DES MAC file written", data(&got, 0x778899, 2, "WRITTEN-MAC!", 12));
		check("  AES full file written", data(&got, 0x112233, 1, "WRITTEN-FULL-AES", 16));
		check("  AES MAC file written", data(&got, 0x112233, 2, "EV2-mac?", 8));
		check("  plain file written", data(&got, 0x445566, 1, big + 8, 32));
		check("  value 150", data(&got, 0x445566, 2, "\x96\0\0\0", 4));
		check("  4 records, the uncommitted one gone",
			data(&got, 0x445566, 3, "\1\1\1\1\1\1\1\1\2\2\2\2\2\2\2\2\3\3\3\3\3\3\3\3\4\4\4\4\4\4\4\4", 32));
		check("  writes counted", dfEmuWrites() == 7);
		printf("    (%lu writes)\n", (unsigned long)dfEmuWrites());
	}
	printf(fails ? "%d FAILURES\n" : "ALL OK\n", fails);
	return !!fails;
}
