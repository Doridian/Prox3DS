// NXP originality signatures, see nxpsig.h. The curve arithmetic is ecc.c's (the Java Card's).

#include <string.h>

#include "ecc.h"
#include "nxpsig.h"

static const struct {
	u32 size;          // bytes per number
	const char *p, *a, *b, *g, *n; // g = 04 x y
} curves[] = {
	{ 16, "FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFF", "FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFC", "E87579C11079F43DD824993C2CEE5ED3",
	  "04161FF7528B899B2D0C28607CA52C5B86CF5AC8395BAFEB13C02DA292DDED7A83", "FFFFFFFE0000000075A30D1B9038A115" },
	{ 28, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001",
	  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE",
	  "B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4",
	  "04B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34",
	  "FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D" },
};

static int hexVal(char c)
{
	return c <= '9' ? c - '0' : (c | 0x20) - 'a' + 10;
}

static u32 fromHex(u8 *b, const char *h)
{
	u32 len = strlen(h) / 2;
	for (u32 i = 0; i < len; i++) b[i] = hexVal(h[2 * i]) << 4 | hexVal(h[2 * i + 1]);
	return len;
}

bool ecdsaVerify(u32 size, const u8 *pub, const u8 *data, u32 len, const u8 *sig)
{
	static EcCurve c;
	static Bn r, s;
	u8 p[28], a[28], b[28], g[57], n[28];
	int k = size == 16 ? 0 : size == 28 ? 1 : -1;
	if (k < 0) return false;
	u32 pl = fromHex(p, curves[k].p), al = fromHex(a, curves[k].a), bl = fromHex(b, curves[k].b);
	u32 gl = fromHex(g, curves[k].g), nl = fromHex(n, curves[k].n);
	if (!ecCurveInit(&c, p, pl, a, al, b, bl, g, gl, n, nl)) return false;
	bnFromBytes(&r, sig, size);
	bnFromBytes(&s, sig + size, size);
	// e = the data as a number: its leading bytes if longer than the order (8 * size bits on both curves)
	return ecVerify(&c, pub, 1 + 2 * size, data, len, &r, &s);
}

// --- NXP keys (pm3 originality.c) ---

static const struct {
	int family;
	const char *name, *key; // 04 || X || Y
} keys[] = {
	{ SIG_MFU, "NXP Ultralight EV1", "0490933BDCD6E99B4E255E3DA55389A827564E11718E017292FAF23226A96614B8" },
	{ SIG_MFU, "NXP NTAG21x", "04494E1A386D3D3CFE3DC10E5DE68A499B1C202DB5B132393E89ED19FE5BE8BC61" },
	{ SIG_MFU, "NXP (TagInfo key)", "04A748B6A632FBEE2C0897702B33BEA1C074998E17B84ACA04FF267E5D2C91F6DC" },
	{ SIG_MFC, "NXP MIFARE Classic EV1", "044F6D3F294DEA5737F0F46FFEE88A356EED95695DD7E0C27A591E6F6F65962BAF" },
	{ SIG_MFC, "MIFARE Classic / QL88", "046F70AC557F5461CE5052C8E4A7838C11C7A236797E8A0730A101837C004039C2" },
	{ SIG_DESFIRE, "DESFire EV3", "041DB46C145D0A36539C6544BD6D9B0AA62FF91EC48CBC6ABAE36E0089A46F0D08C8A715EA40A63313B92E90DDC1730230E0458A33276FB743" },
	{ SIG_DESFIRE, "DESFire EV2 / NTAG 424 DNA", "04B304DC4C615F5326FE9383DDEC9AA892DF3A57FA7FFB3276192BC0EAA252ED45A865E3B093A3D0DCE5BE29E92F1392CE7DE321E3E5C52B3A" },
	{ SIG_DESFIRE, "DESFire EV2 / NTAG 424 DNA (AN12196)", "048A9B380AF2EE1B98DC417FECC263F8449C7625CECE82D9B916C992DA209D68422B81EC20B65A66B5102A61596AF3379200599316A00A1410" },
	{ SIG_DESFIRE, "DESFire EV2 XL", "04CD5D45E50B1502F0BA4656FF37669597E7E183251150F9574CC8DA56BF01C7ABE019E29FEA48F9CE22C3EA4029A765E1BC95A89543BAD1BC" },
	{ SIG_DESFIRE, "DESFire EV1 / NTAG 413 DNA", "04BB5D514F7050025C7D0F397310360EEC91EAF792E96FC7E0F496CB4E669D414F877B7B27901FE67C2E3B33CD39D1C797715189AC951C2ADD" },
	{ SIG_DESFIRE, "DESFire Light", "040E98E117AAA36457F43173DC920A8757267F44CE4EC5ADD3C54075571AEBBF7B942A9774A1D94AD02572427E5AE0A2DD36591B1FB34FCF3D" },
};

const char *nxpSigCheck(int family, const u8 *uid, u32 uidLen, const u8 *sig, u32 sigLen)
{
	u32 size = sigLen / 2;
	bool zero = true;
	for (u32 i = 0; i < sigLen; i++) zero &= !sig[i];
	if (zero || (size != 16 && size != 28)) return NULL;
	for (u32 k = 0; k < sizeof(keys) / sizeof(keys[0]); k++) {
		if (keys[k].family != family) continue;
		u8 pub[57];
		if (strlen(keys[k].key) != 2 * (1 + 2 * size)) continue;
		fromHex(pub, keys[k].key);
		if (ecdsaVerify(size, pub, uid, uidLen, sig)) return keys[k].name;
	}
	return NULL;
}
