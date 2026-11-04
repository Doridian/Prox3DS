// The Java Card's crypto natives, see jccrypto.h. Algorithms as on the J3H145: what it has (the rest throws
// NO_SUCH_ALGORITHM), its reasons for errors, and its quirks (after doFinal / sign a cipher or MAC starts
// over from a zero IV; ISO 9797 M2 decryption drops a last block without the 80 marker).

#include <stdlib.h>
#include <string.h>

#include "bn.h"
#include "dfcrypto.h"
#include "ecc.h"
#include "jccrypto.h"
#include "sha1.h"

#define S(i) ((s16)a[i])
#define RET(v) return a[0] = (u16)(v), 1

enum { CE_ILLEGAL_VALUE = 1, CE_UNINITIALIZED_KEY, CE_NO_SUCH_ALGORITHM, CE_INVALID_INIT, CE_ILLEGAL_USE };

static int cryptoErr(JcVm *vm, s16 reason)
{
	return jcThrow(vm, JCC_security_CryptoException, reason);
}

static u16 newObj(JcVm *vm, int cls)
{
	u16 h = jcNew(vm, cls);
	if (!h) jcThrow(vm, JCC_framework_SystemException, 3); // NO_RESOURCE
	return h;
}

// --- hashes ---

enum { MD_SHA = 1, MD_MD5, MD_RIPEMD160, MD_SHA_256, MD_SHA_384, MD_SHA_512, MD_SHA_224 };

typedef struct {
	u8 alg;
	union {
		Sha1 s1;
		Sha256 s256;
		Sha512 s512;
	};
} Hash;

static int hashLen(u8 alg)
{
	switch (alg) {
	case MD_SHA: return 20;
	case MD_SHA_224: return 28;
	case MD_SHA_256: return 32;
	case MD_SHA_384: return 48;
	case MD_SHA_512: return 64;
	}
	return 0;
}

static void hashStart(Hash *h, u8 alg)
{
	h->alg = alg;
	if (alg == MD_SHA) sha1Init(&h->s1);
	else if (alg == MD_SHA_224) sha224Init(&h->s256);
	else if (alg == MD_SHA_256) sha256Init(&h->s256);
	else if (alg == MD_SHA_384) sha384Init(&h->s512);
	else sha512Init(&h->s512);
}

static void hashAdd(Hash *h, const u8 *m, u32 len)
{
	if (h->alg == MD_SHA) sha1Add(&h->s1, m, len);
	else if (h->alg == MD_SHA_224 || h->alg == MD_SHA_256) sha256Add(&h->s256, m, len);
	else sha512Add(&h->s512, m, len);
}

// the digest into out, the hash started over
static int hashDone(Hash *h, u8 *out)
{
	u8 t[32];
	int n = hashLen(h->alg);
	if (h->alg == MD_SHA) sha1Done(&h->s1, out);
	else if (h->alg == MD_SHA_224) sha256Done(&h->s256, t), memcpy(out, t, 28);
	else if (h->alg == MD_SHA_256) sha256Done(&h->s256, out);
	else sha512Done(&h->s512, out, n);
	hashStart(h, h->alg);
	return n;
}

static int hashOnce(u8 alg, const u8 *m, u32 len, u8 *out)
{
	static Hash h;
	hashStart(&h, alg);
	hashAdd(&h, m, len);
	return hashDone(&h, out);
}

// MGF1: mask (len bytes) xored with the hash of seed || counter
static void mgf1(u8 alg, const u8 *seed, u32 seedLen, u8 *mask, u32 len)
{
	static Hash h;
	u8 d[64], c[4];
	int hl = hashLen(alg);
	for (u32 i = 0, done = 0; done < len; i++) {
		c[0] = i >> 24, c[1] = i >> 16, c[2] = i >> 8, c[3] = i;
		hashStart(&h, alg);
		hashAdd(&h, seed, seedLen);
		hashAdd(&h, c, 4);
		hashDone(&h, d);
		for (int k = 0; k < hl && done < len; k++) mask[done++] ^= d[k];
	}
}

// --- keys ---

enum {
	KT_DES_TRANSIENT_RESET = 1, KT_DES_TRANSIENT_DESELECT, KT_DES, KT_RSA_PUBLIC, KT_RSA_PRIVATE, KT_RSA_CRT_PRIVATE,
	KT_EC_FP_PUBLIC = 11, KT_EC_FP_PRIVATE, KT_AES_TRANSIENT_RESET, KT_AES_TRANSIENT_DESELECT, KT_AES,
	KT_RSA_PRIVATE_TRANSIENT_RESET = 22, KT_RSA_PRIVATE_TRANSIENT_DESELECT, KT_RSA_CRT_PRIVATE_TRANSIENT_RESET,
	KT_RSA_CRT_PRIVATE_TRANSIENT_DESELECT, KT_EC_FP_PRIVATE_TRANSIENT_RESET = 30, KT_EC_FP_PRIVATE_TRANSIENT_DESELECT,
};

// key kinds and their parts (the most bytes each)
enum { K_DES, K_AES, K_RSA_PUB, K_RSA_PRIV, K_RSA_CRT, K_EC_PUB, K_EC_PRIV, K_KINDS };
enum { EC_FIELD, EC_A, EC_B, EC_G, EC_R, EC_K, EC_WS };
static const u16 partMax[K_KINDS][7] = {
	[K_DES] = { 24 },
	[K_AES] = { 32 },
	[K_RSA_PUB] = { 256, 256 },
	[K_RSA_PRIV] = { 256, 256 },
	[K_RSA_CRT] = { 128, 128, 128, 128, 128 },
	[K_EC_PUB] = { 66, 66, 66, 133, 66, 2, 133 },
	[K_EC_PRIV] = { 66, 66, 66, 133, 66, 2, 66 },
};
static const s16 kindClass[K_KINDS] = { JCC_security_DESKey, JCC_security_AESKey, JCC_security_RSAPublicKey,
	JCC_security_RSAPrivateKey, JCC_security_RSAPrivateCrtKey, JCC_security_ECPublicKey, JCC_security_ECPrivateKey };

typedef struct {
	u8 type, kind; // KeyBuilder.TYPE_*, K_*
	u16 bits;
	u8 set;        // the parts set, a bit each
	u8 pad[3];
	u16 len[7];
	u8 data[];     // the parts, partMax[kind] bytes each
} NatKey;

static int kindOf(int cls)
{
	for (int k = 0; k < K_KINDS; k++)
		if (kindClass[k] == cls) return k;
	return -1;
}

static u32 kindSize(int k)
{
	u32 n = sizeof(NatKey);
	for (int i = 0; i < 7; i++) n += partMax[k][i];
	return n;
}

static int nparts(int k)
{
	int n = 0;
	while (n < 7 && partMax[k][n]) n++;
	return n;
}

static u8 *part(NatKey *k, int i)
{
	u8 *p = k->data;
	for (int j = 0; j < i; j++) p += partMax[k->kind][j];
	return p;
}

// the parts a key needs to be initialized (EC: the cofactor is optional, 1)
static u8 needed(int kind)
{
	return ((1 << nparts(kind)) - 1) & ~(kind >= K_EC_PUB ? 1 << EC_K : 0);
}

static bool initialized(const NatKey *k)
{
	return (k->set & needed(k->kind)) == needed(k->kind);
}

// a key object's state; NULL (+ an exception) if h isn't a key
static NatKey *keyOf(JcVm *vm, u16 h)
{
	JcObj *o = jcObj(vm, h);
	if (!o) return jcThrow(vm, JCC_lang_NullPointerException, 0), NULL;
	if (o->type != JT_INSTANCE || kindOf(o->cls) < 0) return cryptoErr(vm, CE_ILLEGAL_VALUE), NULL;
	return jcNat(vm, h);
}

static u32 bytesOf(const NatKey *k)
{
	return (k->bits + 7) / 8;
}

// sets part i from an array (leading zeros dropped for numbers); false after throwing
static bool setPart(JcVm *vm, NatKey *k, int i, u16 h, s16 off, s16 len, u32 max, bool number)
{
	const u8 *s = jcBytes(vm, h, off, len);
	if (!s) return false;
	while (number && len > 0 && !*s) s++, len--;
	if ((u32)len > max || len > partMax[k->kind][i]) return cryptoErr(vm, CE_ILLEGAL_VALUE), false;
	memcpy(part(k, i), s, len);
	k->len[i] = len;
	k->set |= 1 << i;
	return true;
}

// copies part i out (as set: numbers without leading zeros); its length
static int getPart(JcVm *vm, u16 *a, int i)
{
	NatKey *k = keyOf(vm, a[0]);
	if (!k) return -1;
	if (!(k->set & 1 << i)) return cryptoErr(vm, CE_UNINITIALIZED_KEY);
	if (!jcPut(vm, a[1], S(2), part(k, i), k->len[i], false)) return -1;
	RET(k->len[i]);
}

void jcCryptoNatClear(int cls, void *nat)
{
	int kind = kindOf(cls);
	if (kind < 0) return;
	NatKey *k = nat;
	k->set = 0;
	memset(k->len, 0, sizeof(k->len));
	memset(k->data, 0, kindSize(kind) - sizeof(NatKey));
}

// KeyBuilder.buildKey: the key object, 0 after throwing
static u16 buildKey(JcVm *vm, u8 type, u16 bits)
{
	int kind;
	u8 flags = 0;
	switch (type) {
	case KT_DES_TRANSIENT_RESET: case KT_DES_TRANSIENT_DESELECT: case KT_DES:
		kind = K_DES;
		if (bits != 64 && bits != 128 && bits != 192) kind = -1;
		break;
	case KT_AES_TRANSIENT_RESET: case KT_AES_TRANSIENT_DESELECT: case KT_AES:
		kind = K_AES;
		if (bits != 128 && bits != 192 && bits != 256) kind = -1;
		break;
	case KT_RSA_PUBLIC: case KT_RSA_PRIVATE: case KT_RSA_CRT_PRIVATE: case KT_RSA_PRIVATE_TRANSIENT_RESET:
	case KT_RSA_PRIVATE_TRANSIENT_DESELECT: case KT_RSA_CRT_PRIVATE_TRANSIENT_RESET:
	case KT_RSA_CRT_PRIVATE_TRANSIENT_DESELECT:
		kind = type == KT_RSA_PUBLIC ? K_RSA_PUB : type == KT_RSA_PRIVATE || type == KT_RSA_PRIVATE_TRANSIENT_RESET ||
			type == KT_RSA_PRIVATE_TRANSIENT_DESELECT ? K_RSA_PRIV : K_RSA_CRT;
		if (bits < 512 || bits > 2048 || bits % 32) kind = -1;
		break;
	case KT_EC_FP_PUBLIC: case KT_EC_FP_PRIVATE: case KT_EC_FP_PRIVATE_TRANSIENT_RESET:
	case KT_EC_FP_PRIVATE_TRANSIENT_DESELECT:
		kind = type == KT_EC_FP_PUBLIC ? K_EC_PUB : K_EC_PRIV;
		if (bits != 128 && bits != 160 && bits != 192 && bits != 224 && bits != 256 && bits != 384 && bits != 521)
			kind = -1;
		break;
	default:
		kind = -1;
	}
	if (kind < 0) return cryptoErr(vm, CE_NO_SUCH_ALGORITHM), 0;
	switch (type) {
	case KT_DES_TRANSIENT_RESET: case KT_AES_TRANSIENT_RESET: case KT_RSA_PRIVATE_TRANSIENT_RESET:
	case KT_RSA_CRT_PRIVATE_TRANSIENT_RESET: case KT_EC_FP_PRIVATE_TRANSIENT_RESET:
		flags = JO_RESET;
		break;
	case KT_DES_TRANSIENT_DESELECT: case KT_AES_TRANSIENT_DESELECT: case KT_RSA_PRIVATE_TRANSIENT_DESELECT:
	case KT_RSA_CRT_PRIVATE_TRANSIENT_DESELECT: case KT_EC_FP_PRIVATE_TRANSIENT_DESELECT:
		flags = JO_DESELECT;
		break;
	}
	u16 h = newObj(vm, kindClass[kind]);
	if (!h) return 0;
	vm->objs[h - 1].flags |= flags;
	NatKey *k = jcNat(vm, h);
	k->type = type, k->kind = kind, k->bits = bits;
	return h;
}

int jn_security_KeyBuilder_buildKey_BSZ(JcVm *vm, u16 *a)
{
	u16 h = buildKey(vm, a[0], a[1]);
	if (!h) return -1;
	RET(h);
}

// buildKey(algorithmic type, memory type, length, encryption): the same keys by their KeyBuilder.TYPE_*
int jn_security_KeyBuilder_buildKey_BBSZ(JcVm *vm, u16 *a)
{
	static const u8 types[][3] = { // ALG_TYPE_* 1..13 x JCSystem.MEMORY_TYPE_PERSISTENT / RESET / DESELECT
		{ KT_DES, KT_DES_TRANSIENT_RESET, KT_DES_TRANSIENT_DESELECT },
		{ KT_AES, KT_AES_TRANSIENT_RESET, KT_AES_TRANSIENT_DESELECT },
		{ 0 }, { 0 }, { 0 }, { 0 },
		{ KT_EC_FP_PUBLIC },
		{ KT_EC_FP_PRIVATE, KT_EC_FP_PRIVATE_TRANSIENT_RESET, KT_EC_FP_PRIVATE_TRANSIENT_DESELECT },
		{ 0 }, { 0 },
		{ KT_RSA_PUBLIC },
		{ KT_RSA_PRIVATE, KT_RSA_PRIVATE_TRANSIENT_RESET, KT_RSA_PRIVATE_TRANSIENT_DESELECT },
		{ KT_RSA_CRT_PRIVATE, KT_RSA_CRT_PRIVATE_TRANSIENT_RESET, KT_RSA_CRT_PRIVATE_TRANSIENT_DESELECT },
	};
	u8 alg = a[0], mem = a[1];
	u8 type = alg >= 1 && alg <= 13 && mem <= 2 ? types[alg - 1][mem] : 0;
	u16 h = type ? buildKey(vm, type, a[2]) : 0;
	if (!type) return cryptoErr(vm, CE_NO_SUCH_ALGORITHM);
	if (!h) return -1;
	RET(h);
}

// Key (and every key interface)
static int keyClear(JcVm *vm, u16 *a)
{
	JcObj *o = jcObj(vm, a[0]);
	if (!keyOf(vm, a[0])) return -1;
	jcCryptoNatClear(o->cls, jcNat(vm, a[0]));
	return 0;
}

static int keySize(JcVm *vm, u16 *a)
{
	NatKey *k = keyOf(vm, a[0]);
	if (!k) return -1;
	RET(k->bits);
}

static int keyType(JcVm *vm, u16 *a)
{
	NatKey *k = keyOf(vm, a[0]);
	if (!k) return -1;
	RET(k->type);
}

static int keyInit(JcVm *vm, u16 *a)
{
	NatKey *k = keyOf(vm, a[0]);
	if (!k) return -1;
	RET(initialized(k));
}

#define KEY_METHODS(n) \
	int jn_security_##n##_clearKey(JcVm *vm, u16 *a) { return keyClear(vm, a); } \
	int jn_security_##n##_getSize(JcVm *vm, u16 *a) { return keySize(vm, a); } \
	int jn_security_##n##_getType(JcVm *vm, u16 *a) { return keyType(vm, a); } \
	int jn_security_##n##_isInitialized(JcVm *vm, u16 *a) { return keyInit(vm, a); }
KEY_METHODS(Key)
KEY_METHODS(SecretKey)
KEY_METHODS(PrivateKey)
KEY_METHODS(PublicKey)
KEY_METHODS(DESKey)
KEY_METHODS(AESKey)
KEY_METHODS(RSAPublicKey)
KEY_METHODS(RSAPrivateKey)
KEY_METHODS(RSAPrivateCrtKey)
KEY_METHODS(ECPublicKey)
KEY_METHODS(ECPrivateKey)

// DESKey / AESKey: the key's bytes from the array (DES parity bits kept as given)
static int secretSet(JcVm *vm, u16 *a, int kind)
{
	NatKey *k = keyOf(vm, a[0]);
	if (!k) return -1;
	if (k->kind != kind) return cryptoErr(vm, CE_ILLEGAL_VALUE);
	return setPart(vm, k, 0, a[1], S(2), bytesOf(k), 32, false) ? 0 : -1;
}

int jn_security_DESKey_setKey(JcVm *vm, u16 *a)
{
	return secretSet(vm, a, K_DES);
}

int jn_security_AESKey_setKey(JcVm *vm, u16 *a)
{
	return secretSet(vm, a, K_AES);
}

int jn_security_DESKey_getKey(JcVm *vm, u16 *a)
{
	return getPart(vm, a, 0);
}

int jn_security_AESKey_getKey(JcVm *vm, u16 *a)
{
	return getPart(vm, a, 0);
}

// RSA: modulus and exponent up to the key's size; CRT parts up to half of it
#define RSA_SET(n, name, i) \
	int jn_security_##n##_set##name(JcVm *vm, u16 *a) \
	{ \
		NatKey *k = keyOf(vm, a[0]); \
		return k && setPart(vm, k, i, a[1], S(2), S(3), bytesOf(k), true) ? 0 : -1; \
	} \
	int jn_security_##n##_get##name(JcVm *vm, u16 *a) { return getPart(vm, a, i); }
RSA_SET(RSAPublicKey, Modulus, 0)
RSA_SET(RSAPublicKey, Exponent, 1)
RSA_SET(RSAPrivateKey, Modulus, 0)
RSA_SET(RSAPrivateKey, Exponent, 1)
#define CRT_SET(name, i) \
	int jn_security_RSAPrivateCrtKey_set##name(JcVm *vm, u16 *a) \
	{ \
		NatKey *k = keyOf(vm, a[0]); \
		return k && setPart(vm, k, i, a[1], S(2), S(3), bytesOf(k) / 2, true) ? 0 : -1; \
	} \
	int jn_security_RSAPrivateCrtKey_get##name(JcVm *vm, u16 *a) { return getPart(vm, a, i); }
CRT_SET(P, 0)
CRT_SET(Q, 1)
CRT_SET(DP1, 2)
CRT_SET(DQ1, 3)
CRT_SET(PQ, 4)

// EC (prime field only)
static u32 ecLen(const NatKey *k)
{
	return (k->bits + 7) / 8;
}

static int ecSet(JcVm *vm, u16 *a, int i)
{
	NatKey *k = keyOf(vm, a[0]);
	if (!k) return -1;
	if (k->kind < K_EC_PUB) return cryptoErr(vm, CE_ILLEGAL_VALUE);
	bool point = i == EC_G || (i == EC_WS && k->kind == K_EC_PUB);
	return setPart(vm, k, i, a[1], S(2), S(3), point ? 1 + 2 * ecLen(k) : ecLen(k), !point) ? 0 : -1;
}

static int ecSetK(JcVm *vm, u16 *a)
{
	NatKey *k = keyOf(vm, a[0]);
	if (!k) return -1;
	u8 *p = part(k, EC_K);
	p[0] = a[1] >> 8, p[1] = a[1];
	k->len[EC_K] = 2;
	k->set |= 1 << EC_K;
	return 0;
}

static int ecGetK(JcVm *vm, u16 *a)
{
	NatKey *k = keyOf(vm, a[0]);
	if (!k) return -1;
	if (!(k->set & 1 << EC_K)) RET(1);
	const u8 *p = part(k, EC_K);
	RET(p[0] << 8 | p[1]);
}

static int ecF2M(JcVm *vm, u16 *a)
{
	return cryptoErr(vm, CE_ILLEGAL_VALUE);
}

#define EC_METHODS(n) \
	int jn_security_##n##_setFieldFP(JcVm *vm, u16 *a) { return ecSet(vm, a, EC_FIELD); } \
	int jn_security_##n##_setFieldF2M_S(JcVm *vm, u16 *a) { return ecF2M(vm, a); } \
	int jn_security_##n##_setFieldF2M_SSS(JcVm *vm, u16 *a) { return ecF2M(vm, a); } \
	int jn_security_##n##_setA(JcVm *vm, u16 *a) { return ecSet(vm, a, EC_A); } \
	int jn_security_##n##_setB(JcVm *vm, u16 *a) { return ecSet(vm, a, EC_B); } \
	int jn_security_##n##_setG(JcVm *vm, u16 *a) { return ecSet(vm, a, EC_G); } \
	int jn_security_##n##_setR(JcVm *vm, u16 *a) { return ecSet(vm, a, EC_R); } \
	int jn_security_##n##_setK(JcVm *vm, u16 *a) { return ecSetK(vm, a); } \
	int jn_security_##n##_getField(JcVm *vm, u16 *a) { return getPart(vm, a, EC_FIELD); } \
	int jn_security_##n##_getA(JcVm *vm, u16 *a) { return getPart(vm, a, EC_A); } \
	int jn_security_##n##_getB(JcVm *vm, u16 *a) { return getPart(vm, a, EC_B); } \
	int jn_security_##n##_getG(JcVm *vm, u16 *a) { return getPart(vm, a, EC_G); } \
	int jn_security_##n##_getR(JcVm *vm, u16 *a) { return getPart(vm, a, EC_R); } \
	int jn_security_##n##_getK(JcVm *vm, u16 *a) { return ecGetK(vm, a); }
EC_METHODS(ECKey)
EC_METHODS(ECPublicKey)
EC_METHODS(ECPrivateKey)

int jn_security_ECPublicKey_setW(JcVm *vm, u16 *a)
{
	return ecSet(vm, a, EC_WS);
}

int jn_security_ECPublicKey_getW(JcVm *vm, u16 *a)
{
	return getPart(vm, a, EC_WS);
}

int jn_security_ECPrivateKey_setS(JcVm *vm, u16 *a)
{
	return ecSet(vm, a, EC_WS);
}

int jn_security_ECPrivateKey_getS(JcVm *vm, u16 *a)
{
	return getPart(vm, a, EC_WS);
}

// the curve of an EC key; false after throwing
static bool curveOf(JcVm *vm, NatKey *k, EcCurve *c)
{
	if (!ecCurveInit(c, part(k, EC_FIELD), k->len[EC_FIELD], part(k, EC_A), k->len[EC_A], part(k, EC_B),
		    k->len[EC_B], part(k, EC_G), k->len[EC_G], part(k, EC_R), k->len[EC_R]))
		return cryptoErr(vm, CE_ILLEGAL_VALUE), false;
	return true;
}

// --- RSA with a key ---

// in (len bytes) through the key: public / private / CRT; out gets the modulus length. false after throwing.
static bool rsaKey(JcVm *vm, NatKey *k, const u8 *in, u32 len, u8 *out)
{
	bool ok;
	if (k->kind == K_RSA_CRT) {
		const u8 *p[5];
		for (int i = 0; i < 5; i++) p[i] = part(k, i);
		ok = rsaCrt(p, k->len, in, len, out, bytesOf(k));
	} else {
		ok = k->len[0] <= bytesOf(k) && rsaExp(part(k, 0), k->len[0], part(k, 1), k->len[1], in, len, out);
		if (ok && k->len[0] < bytesOf(k)) { // a short modulus: right-align as the key's size
			u32 n = k->len[0], b = bytesOf(k);
			memmove(out + b - n, out, n);
			memset(out, 0, b - n);
		}
	}
	if (!ok) cryptoErr(vm, CE_ILLEGAL_VALUE);
	return ok;
}

static const u8 *digestInfo(u8 alg, u32 *len)
{
	static const u8 sha1[] = { 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14 };
	static const u8 sha2[] = { 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
		0x05, 0x00, 0x04, 0x20 };
	static u8 t[19];
	if (alg == MD_SHA) return *len = sizeof(sha1), sha1;
	memcpy(t, sha2, sizeof(t));
	int hl = hashLen(alg);
	t[1] = 0x11 + hl, t[14] = alg == MD_SHA_256 ? 1 : alg == MD_SHA_384 ? 2 : alg == MD_SHA_512 ? 3 : 4;
	t[18] = hl;
	*len = sizeof(t);
	return t;
}

// EMSA-PKCS1-v1_5 of a digest into em (k bytes)
static void pkcs1Sig(u8 alg, const u8 *h, u8 *em, u32 k)
{
	u32 dl, hl = hashLen(alg);
	const u8 *di = digestInfo(alg, &dl);
	em[0] = 0, em[1] = 1;
	memset(em + 2, 0xFF, k - 3 - dl - hl);
	em[k - dl - hl - 1] = 0;
	memcpy(em + k - dl - hl, di, dl);
	memcpy(em + k - hl, h, hl);
}

// EMSA-PSS (salt as long as the hash, MGF1 with the same hash) of a digest into em (k bytes, modBits)
static void pssEncode(u8 alg, const u8 *h, u8 *em, u32 k, int modBits)
{
	static Hash hs;
	u32 hl = hashLen(alg), emLen = (modBits - 1 + 7) / 8, off = k - emLen;
	u8 salt[64], z[8] = { 0 };
	jcRandom(salt, hl);
	memset(em, 0, k);
	u8 *e = em + off, *H = e + emLen - hl - 1;
	hashStart(&hs, alg);
	hashAdd(&hs, z, 8);
	hashAdd(&hs, h, hl);
	hashAdd(&hs, salt, hl);
	hashDone(&hs, H);
	u32 dbLen = emLen - hl - 1;
	e[dbLen - hl - 1] = 1;
	memcpy(e + dbLen - hl, salt, hl);
	mgf1(alg, H, hl, e, dbLen);
	e[0] &= 0xFF >> (8 * emLen - (modBits - 1));
	e[emLen - 1] = 0xBC;
}

static bool pssVerify(u8 alg, const u8 *h, u8 *em, u32 k, int modBits)
{
	static Hash hs;
	u32 hl = hashLen(alg), emLen = (modBits - 1 + 7) / 8, off = k - emLen;
	for (u32 i = 0; i < off; i++)
		if (em[i]) return false;
	u8 *e = em + off, *H = e + emLen - hl - 1, h2[64], z[8] = { 0 };
	u32 dbLen = emLen - hl - 1;
	if (emLen < 2 * hl + 2 || e[emLen - 1] != 0xBC || e[0] & ~(0xFF >> (8 * emLen - (modBits - 1)))) return false;
	mgf1(alg, H, hl, e, dbLen);
	e[0] &= 0xFF >> (8 * emLen - (modBits - 1));
	for (u32 i = 0; i < dbLen - hl - 1; i++)
		if (e[i]) return false;
	if (e[dbLen - hl - 1] != 1) return false;
	hashStart(&hs, alg);
	hashAdd(&hs, z, 8);
	hashAdd(&hs, h, hl);
	hashAdd(&hs, e + dbLen - hl, hl);
	hashDone(&hs, h2);
	return !memcmp(h2, H, hl);
}

bool rsaVerifyDigest(const u8 *n, u32 nLen, const u8 *e, u32 eLen, const u8 *h, u32 hl, const u8 *sig, u32 sigLen,
	bool pss)
{
	static u8 em[4 * BN_N], want[4 * BN_N];
	static Bn m;
	u8 alg = hl == 20 ? MD_SHA : hl == 28 ? MD_SHA_224 : hl == 32 ? MD_SHA_256 : hl == 48 ? MD_SHA_384 :
		hl == 64 ? MD_SHA_512 : 0;
	while (nLen && !*n) n++, nLen--;
	if (!alg || nLen < 64 || nLen > 256 || sigLen > nLen) return false; // RSA-2048 at most (bn.h)
	if (!rsaExp(n, nLen, e, eLen, sig, sigLen, em)) return false;
	if (pss) {
		bnFromBytes(&m, n, nLen);
		return pssVerify(alg, h, em, nLen, bnBits(&m));
	}
	if (nLen < hl + 30) return false;
	pkcs1Sig(alg, h, want, nLen);
	return !memcmp(em, want, nLen);
}

static int modBits(NatKey *k)
{
	static Bn n;
	if (k->kind == K_RSA_CRT) {
		static Bn q;
		bnFromBytes(&n, part(k, 0), k->len[0]);
		bnFromBytes(&q, part(k, 1), k->len[1]);
		bnMul(&n, &n, &q);
	} else {
		bnFromBytes(&n, part(k, 0), k->len[0]);
	}
	return bnBits(&n);
}

// --- MessageDigest ---

int jn_security_MessageDigest_getInstance(JcVm *vm, u16 *a)
{
	u8 alg = a[0];
	if (!hashLen(alg)) return cryptoErr(vm, CE_NO_SUCH_ALGORITHM);
	u16 h = newObj(vm, JCC_security_MessageDigest);
	if (!h) return -1;
	hashStart(jcNat(vm, h), alg);
	RET(h);
}

int jn_security_MessageDigest_update(JcVm *vm, u16 *a)
{
	u8 *m = jcBytes(vm, a[1], S(2), S(3));
	if (!m) return -1;
	hashAdd(jcNat(vm, a[0]), m, S(3));
	return 0;
}

int jn_security_MessageDigest_doFinal(JcVm *vm, u16 *a)
{
	Hash *d = jcNat(vm, a[0]);
	u8 *m = jcBytes(vm, a[1], S(2), S(3)), h[64];
	if (!m) return -1;
	hashAdd(d, m, S(3));
	int n = hashDone(d, h);
	if (!jcPut(vm, a[4], S(5), h, n, false)) return -1;
	RET(n);
}

int jn_security_MessageDigest_reset(JcVm *vm, u16 *a)
{
	Hash *d = jcNat(vm, a[0]);
	hashStart(d, d->alg);
	return 0;
}

int jn_security_MessageDigest_getAlgorithm(JcVm *vm, u16 *a)
{
	RET(((Hash *)jcNat(vm, a[0]))->alg);
}

int jn_security_MessageDigest_getLength(JcVm *vm, u16 *a)
{
	RET(hashLen(((Hash *)jcNat(vm, a[0]))->alg));
}

// --- Cipher ---

enum { C_DES_CBC_NOPAD = 1, C_DES_CBC_M1, C_DES_CBC_M2, C_DES_ECB_NOPAD = 5, C_DES_ECB_M1, C_DES_ECB_M2,
	C_RSA_PKCS1 = 10, C_RSA_NOPAD = 12, C_AES_128_CBC_NOPAD, C_AES_128_ECB_NOPAD, C_RSA_PKCS1_OAEP,
	C_AES_CBC_M1 = 22, C_AES_CBC_M2, C_AES_ECB_M1 = 25, C_AES_ECB_M2 };
enum { MODE_DECRYPT = 1, MODE_ENCRYPT };
enum { PAD_NONE, PAD_M1, PAD_M2 };

typedef struct {
	u8 alg, mode, inited, nbuf;
	u16 key, rsaLen;
	u8 iv[16];
	u8 buf[256]; // a partial block; RSA: the input so far
} NatCipher;

typedef struct {
	u8 kind; // K_DES / K_AES / K_RSA_PUB (any RSA)
	bool cbc;
	u8 pad;
} CipherAlg;

static bool cipherAlg(u8 alg, CipherAlg *c)
{
	switch (alg) {
	case C_DES_CBC_NOPAD: case C_DES_CBC_M1: case C_DES_CBC_M2:
		*c = (CipherAlg){ K_DES, true, alg - C_DES_CBC_NOPAD };
		return true;
	case C_DES_ECB_NOPAD: case C_DES_ECB_M1: case C_DES_ECB_M2:
		*c = (CipherAlg){ K_DES, false, alg - C_DES_ECB_NOPAD };
		return true;
	case C_AES_128_CBC_NOPAD: case C_AES_CBC_M1: case C_AES_CBC_M2:
		*c = (CipherAlg){ K_AES, true, alg == C_AES_128_CBC_NOPAD ? PAD_NONE : alg - C_AES_CBC_M1 + 1 };
		return true;
	case C_AES_128_ECB_NOPAD: case C_AES_ECB_M1: case C_AES_ECB_M2:
		*c = (CipherAlg){ K_AES, false, alg == C_AES_128_ECB_NOPAD ? PAD_NONE : alg - C_AES_ECB_M1 + 1 };
		return true;
	case C_RSA_PKCS1: case C_RSA_NOPAD: case C_RSA_PKCS1_OAEP:
		*c = (CipherAlg){ K_RSA_PUB };
		return true;
	}
	return false;
}

static void blockCipher(DfCipher *dc, const NatKey *k)
{
	static const u8 aesType[] = { DF_AES, DF_AES192, DF_AES256 };
	if (k->kind == K_AES) dfCipherInit(dc, aesType[(k->bits - 128) / 64], k->data);
	else dfCipherInit(dc, k->bits == 64 ? DF_DES : k->bits == 128 ? DF_2K3DES : DF_3K3DES, k->data);
}

// the key of an initialized cipher / signature (it may have been cleared since); NULL after throwing
static NatKey *usedKey(JcVm *vm, u16 h)
{
	NatKey *k = keyOf(vm, h);
	if (k && !initialized(k)) return cryptoErr(vm, CE_UNINITIALIZED_KEY), NULL;
	return k;
}

int jn_crypto_Cipher_getInstance_BZ(JcVm *vm, u16 *a)
{
	CipherAlg c;
	if (!cipherAlg(a[0], &c)) return cryptoErr(vm, CE_NO_SUCH_ALGORITHM);
	u16 h = newObj(vm, JCC_x_crypto_Cipher);
	if (!h) return -1;
	((NatCipher *)jcNat(vm, h))->alg = a[0];
	RET(h);
}

int jn_crypto_Cipher_getInstance_BBZ(JcVm *vm, u16 *a)
{
	return cryptoErr(vm, CE_NO_SUCH_ALGORITHM);
}

int jn_crypto_Cipher_getAlgorithm(JcVm *vm, u16 *a)
{
	RET(((NatCipher *)jcNat(vm, a[0]))->alg);
}

static bool keyFits(const NatKey *k, u8 kind)
{
	if (kind == K_RSA_PUB) return k->kind == K_RSA_PUB || k->kind == K_RSA_PRIV || k->kind == K_RSA_CRT;
	return k->kind == kind;
}

static int cipherInit(JcVm *vm, u16 *a, const u8 *iv, s16 ivLen)
{
	NatCipher *c = jcNat(vm, a[0]);
	CipherAlg ca;
	cipherAlg(c->alg, &ca);
	NatKey *k = keyOf(vm, a[1]);
	if (!k) return -1;
	u8 mode = a[2];
	if (!keyFits(k, ca.kind) || (mode != MODE_DECRYPT && mode != MODE_ENCRYPT)) return cryptoErr(vm, CE_ILLEGAL_VALUE);
	if (!initialized(k)) return cryptoErr(vm, CE_UNINITIALIZED_KEY);
	int bs = ca.kind == K_AES ? 16 : 8;
	if (iv && (!ca.cbc || ca.kind == K_RSA_PUB || ivLen != bs)) return cryptoErr(vm, CE_ILLEGAL_VALUE);
	memset(c->iv, 0, sizeof(c->iv));
	if (iv) memcpy(c->iv, iv, bs);
	c->mode = mode, c->key = a[1], c->inited = 1, c->nbuf = 0, c->rsaLen = 0;
	return 0;
}

int jn_crypto_Cipher_init_KeyB(JcVm *vm, u16 *a)
{
	return cipherInit(vm, a, NULL, 0);
}

int jn_crypto_Cipher_init_KeyBaBSS(JcVm *vm, u16 *a)
{
	const u8 *iv = jcBytes(vm, a[3], S(4), S(5));
	return iv ? cipherInit(vm, a, iv, S(5)) : -1;
}

// whole blocks of buf + in through the cipher into out; keep: hold back a last whole block (padded
// decryption). The bytes out.
static u32 blocks(NatCipher *c, const DfCipher *dc, bool cbc, const u8 *in, u32 len, u8 *out, bool keep)
{
	u32 bs = dc->bs, total = c->nbuf + len, n = total / bs * bs, done = 0;
	if (keep && n && n == total) n -= bs;
	while (done < n) {
		u8 b[16];
		u32 from = 0;
		if (c->nbuf) memcpy(b, c->buf, c->nbuf), from = c->nbuf, c->nbuf = 0;
		memcpy(b + from, in, bs - from);
		in += bs - from, len -= bs - from;
		bool enc = c->mode == MODE_ENCRYPT;
		if (cbc && enc)
			for (u32 i = 0; i < bs; i++) b[i] ^= c->iv[i];
		u8 ct[16];
		memcpy(ct, b, bs);
		dfBlock(dc, b, enc);
		if (cbc) {
			if (enc) memcpy(c->iv, b, bs);
			else {
				for (u32 i = 0; i < bs; i++) b[i] ^= c->iv[i];
				memcpy(c->iv, ct, bs);
			}
		}
		memcpy(out + done, b, bs);
		done += bs;
	}
	memcpy(c->buf + c->nbuf, in, len);
	c->nbuf += len;
	return done;
}

// in (copied: it may overlap out) for update / doFinal; NULL after throwing
static u8 *inCopy(JcVm *vm, u16 *a, u32 extra)
{
	const u8 *in = jcBytes(vm, a[1], S(2), S(3));
	if (!in) return NULL;
	u8 *t = malloc(S(3) + extra + 32);
	if (!t) return jcThrow(vm, JCC_framework_SystemException, 3), NULL;
	memcpy(t, in, S(3));
	return t;
}

static NatCipher *cipherReady(JcVm *vm, u16 h)
{
	NatCipher *c = jcNat(vm, h);
	if (!c->inited) return cryptoErr(vm, CE_INVALID_INIT), NULL;
	return c;
}

int jn_crypto_Cipher_update(JcVm *vm, u16 *a)
{
	NatCipher *c = cipherReady(vm, a[0]);
	if (!c) return -1;
	CipherAlg ca;
	cipherAlg(c->alg, &ca);
	NatKey *k = usedKey(vm, c->key);
	if (!k) return -1;
	if (ca.kind == K_RSA_PUB) {
		const u8 *in = jcBytes(vm, a[1], S(2), S(3));
		if (!in) return -1;
		if (c->rsaLen + S(3) > (int)bytesOf(k)) return cryptoErr(vm, CE_ILLEGAL_USE);
		memcpy(c->buf + c->rsaLen, in, S(3));
		c->rsaLen += S(3);
		RET(0);
	}
	static DfCipher dc;
	blockCipher(&dc, k);
	u8 *in = inCopy(vm, a, 0), *out = in ? malloc(S(3) + 32) : NULL;
	if (!out) return free(in), in ? jcThrow(vm, JCC_framework_SystemException, 3) : -1;
	NatCipher save = *c;
	u32 n = blocks(c, &dc, ca.cbc, in, S(3), out, ca.pad == PAD_M2 && c->mode == MODE_DECRYPT);
	bool ok = jcPut(vm, a[4], S(5), out, n, false);
	if (!ok) *c = save;
	free(in), free(out);
	if (!ok) return -1;
	RET(n);
}

// RSA doFinal: the whole input in t (len bytes), the result into out; its length, -1 after throwing
static int rsaFinal(JcVm *vm, NatCipher *c, NatKey *k, u8 *t, u32 len, u8 *out)
{
	static u8 em[256];
	u32 kb = bytesOf(k);
	bool pub = k->kind == K_RSA_PUB;
	if (c->alg == C_RSA_NOPAD) {
		if (len != kb) return cryptoErr(vm, CE_ILLEGAL_USE);
		return rsaKey(vm, k, t, len, out) ? (int)kb : -1;
	}
	if (c->mode == MODE_ENCRYPT) {
		if (c->alg == C_RSA_PKCS1) {
			if (len > kb - 11) return cryptoErr(vm, CE_ILLEGAL_USE);
			em[0] = 0, em[1] = pub ? 2 : 1;
			u32 ps = kb - 3 - len;
			if (pub) {
				jcRandom(em + 2, ps);
				for (u32 i = 0; i < ps; i++)
					while (!em[2 + i]) jcRandom(em + 2 + i, 1);
			} else {
				memset(em + 2, 0xFF, ps);
			}
			em[2 + ps] = 0;
			memcpy(em + 3 + ps, t, len);
		} else { // OAEP, SHA-1, no label
			if (len > kb - 42) return cryptoErr(vm, CE_ILLEGAL_USE);
			memset(em, 0, kb);
			u8 *seed = em + 1, *db = em + 21;
			u32 dbLen = kb - 21;
			hashOnce(MD_SHA, NULL, 0, db);
			db[dbLen - len - 1] = 1;
			memcpy(db + dbLen - len, t, len);
			jcRandom(seed, 20);
			mgf1(MD_SHA, seed, 20, db, dbLen);
			mgf1(MD_SHA, db, dbLen, seed, 20);
		}
		return rsaKey(vm, k, em, kb, out) ? (int)kb : -1;
	}
	if (len != kb) return cryptoErr(vm, CE_ILLEGAL_USE);
	if (!rsaKey(vm, k, t, len, em)) return -1;
	u32 at;
	if (c->alg == C_RSA_PKCS1) {
		if (em[0] || em[1] != (pub ? 1 : 2)) return cryptoErr(vm, CE_ILLEGAL_VALUE);
		for (at = 2; at < kb && em[at]; at++)
			if (pub && em[at] != 0xFF) return cryptoErr(vm, CE_ILLEGAL_VALUE);
		if (at >= kb || at < 10) return cryptoErr(vm, CE_ILLEGAL_VALUE);
		at++;
	} else {
		u8 *seed = em + 1, *db = em + 21, lh[20];
		u32 dbLen = kb - 21;
		mgf1(MD_SHA, db, dbLen, seed, 20);
		mgf1(MD_SHA, seed, 20, db, dbLen);
		hashOnce(MD_SHA, NULL, 0, lh);
		if (em[0] || memcmp(db, lh, 20)) return cryptoErr(vm, CE_ILLEGAL_VALUE);
		for (at = 20; at < dbLen && !db[at]; at++)
			;
		if (at >= dbLen || db[at] != 1) return cryptoErr(vm, CE_ILLEGAL_VALUE);
		at += 22;
	}
	memcpy(out, em + at, kb - at);
	return kb - at;
}

int jn_crypto_Cipher_doFinal(JcVm *vm, u16 *a)
{
	NatCipher *c = cipherReady(vm, a[0]);
	if (!c) return -1;
	CipherAlg ca;
	cipherAlg(c->alg, &ca);
	NatKey *k = usedKey(vm, c->key);
	if (!k) return -1;
	u8 *t = inCopy(vm, a, 512), *out = t ? malloc(S(3) + 512) : NULL;
	if (!out) return free(t), t ? jcThrow(vm, JCC_framework_SystemException, 3) : -1;
	int n;
	if (ca.kind == K_RSA_PUB) {
		u32 len = c->rsaLen + S(3);
		if (len > bytesOf(k)) {
			n = cryptoErr(vm, CE_ILLEGAL_USE);
		} else {
			memmove(t + c->rsaLen, t, S(3));
			memcpy(t, c->buf, c->rsaLen);
			n = rsaFinal(vm, c, k, t, len, out);
		}
		c->rsaLen = 0;
	} else {
		static DfCipher dc;
		blockCipher(&dc, k);
		u32 bs = dc.bs, len = S(3), total = c->nbuf + len;
		bool enc = c->mode == MODE_ENCRYPT;
		n = -1;
		if (enc) {
			if (ca.pad == PAD_M2) t[len++] = 0x80;
			if (ca.pad != PAD_NONE)
				while ((c->nbuf + len) % bs) t[len++] = 0;
			total = c->nbuf + len;
		}
		if (total % bs || (ca.pad == PAD_NONE && !total)) {
			n = cryptoErr(vm, CE_ILLEGAL_USE);
		} else {
			n = blocks(c, &dc, ca.cbc, t, len, out, false);
			if (!enc && ca.pad == PAD_M2 && n) { // drop the padding; no 80 marker: the whole last block goes
				int i = n - 1;
				while (i >= n - (int)bs && !out[i]) i--;
				n = i >= n - (int)bs && out[i] == 0x80 ? i : n - (int)bs;
			}
		}
		c->nbuf = 0;
		memset(c->iv, 0, sizeof(c->iv)); // as the J3H145: a zero IV, not the init one
	}
	bool ok = n >= 0 && jcPut(vm, a[4], S(5), out, n, false);
	free(t), free(out);
	if (!ok) return -1;
	RET(n);
}

// --- Signature ---

enum { SG_DES_MAC8_NOPAD = 2, SG_DES_MAC8_M1 = 4, SG_DES_MAC4_M2, SG_DES_MAC8_M2, SG_RSA_SHA_ISO9796 = 9, SG_RSA_SHA_PKCS1,
	SG_ECDSA_SHA = 17, SG_AES_MAC_128_NOPAD, SG_DES_MAC4_ALG3_M2, SG_DES_MAC8_ALG3_M2, SG_RSA_SHA_PKCS1_PSS,
	SG_ECDSA_SHA_256 = 33, SG_ECDSA_SHA_384, SG_ECDSA_SHA_224 = 37, SG_ECDSA_SHA_512, SG_RSA_SHA_224_PKCS1,
	SG_RSA_SHA_256_PKCS1, SG_RSA_SHA_384_PKCS1, SG_RSA_SHA_512_PKCS1, SG_RSA_SHA_224_PKCS1_PSS,
	SG_RSA_SHA_256_PKCS1_PSS, SG_RSA_SHA_384_PKCS1_PSS, SG_RSA_SHA_512_PKCS1_PSS, SG_DES_MAC8_ALG3_M1 = 48 };
enum { SIGN = 1, VERIFY };
enum { S_MAC, S_PKCS1, S_PSS, S_ECDSA, S_ISO9796 };

typedef struct {
	u8 type;   // S_*
	u8 kind;   // the key kind (MACs: K_DES / K_AES)
	u8 pad;    // MACs: PAD_*
	u8 len;    // MACs: the MAC's bytes
	bool alg3; // ISO 9797-1 MAC algorithm 3
	u8 hash;   // the others: MD_*
} SigAlg;

static bool sigAlg(u8 alg, SigAlg *s)
{
	memset(s, 0, sizeof(*s));
	switch (alg) {
	case SG_DES_MAC8_NOPAD: *s = (SigAlg){ S_MAC, K_DES, PAD_NONE, 8 }; return true;
	case SG_DES_MAC8_M1: *s = (SigAlg){ S_MAC, K_DES, PAD_M1, 8 }; return true;
	case SG_DES_MAC4_M2: *s = (SigAlg){ S_MAC, K_DES, PAD_M2, 4 }; return true;
	case SG_DES_MAC8_M2: *s = (SigAlg){ S_MAC, K_DES, PAD_M2, 8 }; return true;
	case SG_DES_MAC4_ALG3_M2: *s = (SigAlg){ S_MAC, K_DES, PAD_M2, 4, true }; return true;
	case SG_DES_MAC8_ALG3_M2: *s = (SigAlg){ S_MAC, K_DES, PAD_M2, 8, true }; return true;
	case SG_DES_MAC8_ALG3_M1: *s = (SigAlg){ S_MAC, K_DES, PAD_M1, 8, true }; return true;
	case SG_AES_MAC_128_NOPAD: *s = (SigAlg){ S_MAC, K_AES, PAD_NONE, 16 }; return true;
	case SG_RSA_SHA_ISO9796: *s = (SigAlg){ S_ISO9796, K_RSA_PUB, .hash = MD_SHA }; return true;
	case SG_RSA_SHA_PKCS1: *s = (SigAlg){ S_PKCS1, K_RSA_PUB, .hash = MD_SHA }; return true;
	case SG_RSA_SHA_224_PKCS1: *s = (SigAlg){ S_PKCS1, K_RSA_PUB, .hash = MD_SHA_224 }; return true;
	case SG_RSA_SHA_256_PKCS1: *s = (SigAlg){ S_PKCS1, K_RSA_PUB, .hash = MD_SHA_256 }; return true;
	case SG_RSA_SHA_384_PKCS1: *s = (SigAlg){ S_PKCS1, K_RSA_PUB, .hash = MD_SHA_384 }; return true;
	case SG_RSA_SHA_512_PKCS1: *s = (SigAlg){ S_PKCS1, K_RSA_PUB, .hash = MD_SHA_512 }; return true;
	case SG_RSA_SHA_PKCS1_PSS: *s = (SigAlg){ S_PSS, K_RSA_PUB, .hash = MD_SHA }; return true;
	case SG_RSA_SHA_224_PKCS1_PSS: *s = (SigAlg){ S_PSS, K_RSA_PUB, .hash = MD_SHA_224 }; return true;
	case SG_RSA_SHA_256_PKCS1_PSS: *s = (SigAlg){ S_PSS, K_RSA_PUB, .hash = MD_SHA_256 }; return true;
	case SG_RSA_SHA_384_PKCS1_PSS: *s = (SigAlg){ S_PSS, K_RSA_PUB, .hash = MD_SHA_384 }; return true;
	case SG_RSA_SHA_512_PKCS1_PSS: *s = (SigAlg){ S_PSS, K_RSA_PUB, .hash = MD_SHA_512 }; return true;
	case SG_ECDSA_SHA: *s = (SigAlg){ S_ECDSA, K_EC_PUB, .hash = MD_SHA }; return true;
	case SG_ECDSA_SHA_224: *s = (SigAlg){ S_ECDSA, K_EC_PUB, .hash = MD_SHA_224 }; return true;
	case SG_ECDSA_SHA_256: *s = (SigAlg){ S_ECDSA, K_EC_PUB, .hash = MD_SHA_256 }; return true;
	case SG_ECDSA_SHA_384: *s = (SigAlg){ S_ECDSA, K_EC_PUB, .hash = MD_SHA_384 }; return true;
	case SG_ECDSA_SHA_512: *s = (SigAlg){ S_ECDSA, K_EC_PUB, .hash = MD_SHA_512 }; return true;
	}
	return false;
}

typedef struct {
	u8 alg, mode, inited, nbuf;
	u16 key;
	u8 pad[2];
	u8 cv[16], buf[16]; // MACs: the chaining value, the last (partial) block
	Hash h;             // the others
	u16 msgLen;         // ISO 9796-2: the message's length so far, its first bytes (what a block can recover)
	u8 msg[256];
} NatSig;

int jn_security_Signature_getInstance_BZ(JcVm *vm, u16 *a)
{
	SigAlg s;
	if (!sigAlg(a[0], &s)) return cryptoErr(vm, CE_NO_SUCH_ALGORITHM);
	u16 h = newObj(vm, JCC_security_Signature);
	if (!h) return -1;
	((NatSig *)jcNat(vm, h))->alg = a[0];
	RET(h);
}

int jn_security_Signature_getInstance_BBBZ(JcVm *vm, u16 *a)
{
	return cryptoErr(vm, CE_NO_SUCH_ALGORITHM);
}

int jn_security_Signature_getAlgorithm(JcVm *vm, u16 *a)
{
	RET(((NatSig *)jcNat(vm, a[0]))->alg);
}

static int sigInit(JcVm *vm, u16 *a, const u8 *iv, s16 ivLen)
{
	NatSig *s = jcNat(vm, a[0]);
	SigAlg sa;
	sigAlg(s->alg, &sa);
	NatKey *k = keyOf(vm, a[1]);
	if (!k) return -1;
	u8 mode = a[2];
	bool fits;
	if (sa.type == S_MAC) fits = k->kind == sa.kind;
	else if (sa.type == S_ECDSA) fits = k->kind == (mode == SIGN ? K_EC_PRIV : K_EC_PUB);
	else fits = mode == SIGN ? k->kind == K_RSA_PRIV || k->kind == K_RSA_CRT : k->kind == K_RSA_PUB;
	if (!fits || (mode != SIGN && mode != VERIFY)) return cryptoErr(vm, CE_ILLEGAL_VALUE);
	if (!initialized(k)) return cryptoErr(vm, CE_UNINITIALIZED_KEY);
	int bs = sa.kind == K_AES ? 16 : 8;
	if (iv && (sa.type != S_MAC || ivLen != bs)) return cryptoErr(vm, CE_ILLEGAL_VALUE);
	memset(s->cv, 0, sizeof(s->cv));
	if (iv) memcpy(s->cv, iv, bs);
	s->mode = mode, s->key = a[1], s->inited = 1, s->nbuf = 0;
	if (sa.type != S_MAC) hashStart(&s->h, sa.hash);
	s->msgLen = 0;
	return 0;
}

int jn_security_Signature_init_KeyB(JcVm *vm, u16 *a)
{
	return sigInit(vm, a, NULL, 0);
}

int jn_security_Signature_init_KeyBaBSS(JcVm *vm, u16 *a)
{
	const u8 *iv = jcBytes(vm, a[3], S(4), S(5));
	return iv ? sigInit(vm, a, iv, S(5)) : -1;
}

static NatSig *sigReady(JcVm *vm, u16 h, SigAlg *sa, NatKey **k)
{
	NatSig *s = jcNat(vm, h);
	if (!s->inited) return cryptoErr(vm, CE_INVALID_INIT), NULL;
	sigAlg(s->alg, sa);
	*k = usedKey(vm, s->key);
	return *k ? s : NULL;
}

int jn_security_Signature_getLength(JcVm *vm, u16 *a)
{
	SigAlg sa;
	NatKey *k;
	NatSig *s = sigReady(vm, a[0], &sa, &k);
	if (!s) return -1;
	if (sa.type == S_MAC) RET(sa.len);
	if (sa.type == S_ECDSA) RET(2 * (ecLen(k) + 3) + 2);
	RET(bytesOf(k));
}

// MAC: whole blocks into the chaining value, the last one so far (whole or not) kept in buf for the end.
// Algorithm 3: single DES with key part 1 for every block but the last.
static void macBlocks(NatSig *s, const SigAlg *sa, const NatKey *k, const u8 *in, u32 len)
{
	static DfCipher full, first;
	blockCipher(&full, k);
	if (sa->alg3) dfCipherInit(&first, DF_DES, k->data);
	u32 bs = full.bs;
	for (;;) {
		while (len && s->nbuf < bs) s->buf[s->nbuf++] = *in++, len--;
		if (s->nbuf < bs || !len) return;
		for (u32 i = 0; i < bs; i++) s->cv[i] ^= s->buf[i];
		dfBlock(sa->alg3 ? &first : &full, s->cv, true);
		s->nbuf = 0;
	}
}

// the MAC of everything so far + in; false after throwing (the state then starts over too)
static bool macFinal(JcVm *vm, NatSig *s, const SigAlg *sa, const NatKey *k, const u8 *in, u32 len, u8 *mac)
{
	static DfCipher full, first;
	blockCipher(&full, k);
	if (sa->alg3) dfCipherInit(&first, DF_DES, k->data);
	u32 bs = full.bs;
	macBlocks(s, sa, k, in, len);
	// the last block(s): pad
	u8 last[32];
	u32 n = s->nbuf;
	memcpy(last, s->buf, n);
	if (sa->pad == PAD_M2) last[n++] = 0x80;
	if (sa->pad != PAD_NONE)
		while (n % bs) last[n++] = 0;
	bool ok = n && n % bs == 0;
	for (u32 b = 0; ok && b < n; b += bs) {
		for (u32 i = 0; i < bs; i++) s->cv[i] ^= last[b + i];
		dfBlock(sa->alg3 && b + bs < n ? &first : &full, s->cv, true);
	}
	if (ok) memcpy(mac, s->cv, sa->len);
	memset(s->cv, 0, sizeof(s->cv)); // as the J3H145: a zero IV after
	s->nbuf = 0;
	if (!ok) cryptoErr(vm, CE_ILLEGAL_USE);
	return ok;
}

// ISO 9796-2 scheme 1 (SHA-1, trailer BC), as Bouncy Castle's ISO9796d2Signer: the message's start in the
// block (all of it: header 4, else 6), padded with BB..BA, then the hash. s->msg / msgLen: the message so far.
static void keepMsg(NatSig *s, const u8 *in, u32 len)
{
	for (u32 i = 0; i < len && s->msgLen + i < sizeof(s->msg); i++) s->msg[s->msgLen + i] = in[i];
	s->msgLen = s->msgLen + len > 0xFFFF ? 0xFFFF : s->msgLen + len;
}

static void iso9796Encode(const NatSig *s, const u8 *h, u8 *em, u32 k, int modBits)
{
	int x = (20 + s->msgLen) * 8 + 8 + 4 - modBits;
	u32 mR = x > 0 ? s->msgLen - (x + 7) / 8 : s->msgLen;
	u8 header = x > 0 ? 0x60 : 0x40;
	memset(em, 0, k);
	em[k - 1] = 0xBC;
	memcpy(em + k - 21, h, 20);
	u32 delta = k - 21 - mR;
	memcpy(em + delta, s->msg, mR);
	if (delta > 1) {
		memset(em + 1, 0xBB, delta - 1);
		em[delta - 1] ^= 1;
		em[0] = 0x0B | header;
	} else {
		em[0] = 0x0A | header;
	}
}

static bool iso9796Verify(const NatSig *s, const u8 *h, const u8 *em, u32 k)
{
	if (em[k - 1] != 0xBC || (em[0] & 0xC0) != 0x40 || memcmp(em + k - 21, h, 20)) return false;
	u32 at = 1;
	if ((em[0] & 0x0F) == 0x0B) {
		while (at < k - 21 && em[at] == 0xBB) at++;
		if (at >= k - 21 || em[at] != 0xBA) return false;
		at++;
	} else if ((em[0] & 0x0F) != 0x0A) {
		return false;
	}
	u32 mR = k - 21 - at;
	bool full = !(em[0] & 0x20);
	if (mR > s->msgLen || (full && mR != s->msgLen) || mR > sizeof(s->msg)) return false;
	return !memcmp(em + at, s->msg, mR);
}

int jn_security_Signature_update(JcVm *vm, u16 *a)
{
	SigAlg sa;
	NatKey *k;
	NatSig *s = sigReady(vm, a[0], &sa, &k);
	if (!s) return -1;
	const u8 *in = jcBytes(vm, a[1], S(2), S(3));
	if (!in) return -1;
	if (sa.type == S_MAC) macBlocks(s, &sa, k, in, S(3));
	else hashAdd(&s->h, in, S(3)), keepMsg(s, in, S(3));
	return 0;
}

static u32 derInt(u8 *out, const Bn *v, u32 len)
{
	u8 b[68];
	bnToBytes(v, b, len);
	u32 i = 0;
	while (i < len - 1 && !b[i]) i++;
	bool pad = b[i] & 0x80;
	out[0] = 2, out[1] = len - i + pad;
	if (pad) out[2] = 0;
	memcpy(out + 2 + pad, b + i, len - i);
	return 2 + pad + len - i;
}

// an ECDSA signature (DER SEQUENCE of r, s) into out; its length
static u32 derSig(u8 *out, const Bn *r, const Bn *s, u32 len)
{
	u8 t[2 * 70];
	u32 n = derInt(t, r, len);
	n += derInt(t + n, s, len);
	u32 h = 0;
	out[h++] = 0x30;
	if (n >= 128) out[h++] = 0x81;
	out[h++] = n;
	memcpy(out + h, t, n);
	return h + n;
}

static bool derLen(const u8 **p, const u8 *end, u32 *len)
{
	if (*p >= end) return false;
	u32 l = *(*p)++;
	if (l == 0x81) {
		if (*p >= end) return false;
		l = *(*p)++;
	} else if (l > 0x80) {
		return false;
	}
	*len = l;
	return *p + l <= end;
}

static bool derParse(const u8 *sig, u32 len, Bn *r, Bn *s)
{
	const u8 *p = sig, *end = sig + len;
	u32 l;
	if (len < 8 || *p++ != 0x30 || !derLen(&p, end, &l) || p + l != end) return false;
	for (int i = 0; i < 2; i++) {
		if (p >= end || *p++ != 2 || !derLen(&p, end, &l) || !l || l > 67) return false;
		bnFromBytes(i ? s : r, p, l);
		p += l;
	}
	return p == end;
}

// sign (sig != NULL: into it, the length back) or verify (the signature in vsig) a digest h; -1 after
// throwing, verify: 1 / 0
static int sigDigest(JcVm *vm, const SigAlg *sa, NatSig *ns, NatKey *k, const u8 *h, u8 *sig, const u8 *vsig,
	u32 vlen)
{
	static u8 em[256], em2[256];
	static EcCurve curve;
	u32 kb = bytesOf(k);
	if (sa->type == S_ECDSA) {
		if (!curveOf(vm, k, &curve)) return -1;
		static Bn d, r, s;
		if (sig) {
			bnFromBytes(&d, part(k, EC_WS), k->len[EC_WS]);
			ecSign(&curve, &d, h, hashLen(sa->hash), jcRandom, &r, &s);
			return derSig(sig, &r, &s, curve.len);
		}
		return derParse(vsig, vlen, &r, &s) &&
			ecVerify(&curve, part(k, EC_WS), k->len[EC_WS], h, hashLen(sa->hash), &r, &s);
	}
	int mb = modBits(k);
	if (sig) {
		if (sa->type == S_PKCS1) pkcs1Sig(sa->hash, h, em, kb);
		else if (sa->type == S_ISO9796) iso9796Encode(ns, h, em, kb, mb);
		else pssEncode(sa->hash, h, em, kb, mb);
		return rsaKey(vm, k, em, kb, sig) ? (int)kb : -1;
	}
	if (vlen != kb) return 0;
	static Bn x, n;
	bnFromBytes(&x, vsig, vlen);
	bnFromBytes(&n, part(k, 0), k->len[0]);
	if (bnCmp(&x, &n) >= 0 || !rsaKey(vm, k, vsig, vlen, em)) {
		vm->exc = 0;
		return 0;
	}
	if (sa->type == S_PSS) return pssVerify(sa->hash, h, em, kb, mb);
	if (sa->type == S_ISO9796) return iso9796Verify(ns, h, em, kb);
	pkcs1Sig(sa->hash, h, em2, kb);
	return !memcmp(em, em2, kb);
}

int jn_security_Signature_sign(JcVm *vm, u16 *a)
{
	SigAlg sa;
	NatKey *k;
	NatSig *s = sigReady(vm, a[0], &sa, &k);
	if (!s) return -1;
	if (s->mode != SIGN) return cryptoErr(vm, CE_ILLEGAL_USE);
	const u8 *in = jcBytes(vm, a[1], S(2), S(3));
	if (!in) return -1;
	static u8 sig[256];
	int n;
	if (sa.type == S_MAC) {
		n = macFinal(vm, s, &sa, k, in, S(3), sig) ? sa.len : -1;
	} else {
		u8 h[64];
		hashAdd(&s->h, in, S(3));
		hashDone(&s->h, h);
		keepMsg(s, in, S(3));
		n = sigDigest(vm, &sa, s, k, h, sig, NULL, 0);
		s->msgLen = 0;
	}
	if (n < 0 || !jcPut(vm, a[4], S(5), sig, n, false)) return -1;
	RET(n);
}

int jn_security_Signature_signPreComputedHash(JcVm *vm, u16 *a)
{
	SigAlg sa;
	NatKey *k;
	NatSig *s = sigReady(vm, a[0], &sa, &k);
	if (!s) return -1;
	if (s->mode != SIGN || sa.type == S_MAC || sa.type == S_ISO9796) return cryptoErr(vm, CE_ILLEGAL_USE);
	const u8 *h = jcBytes(vm, a[1], S(2), S(3));
	if (!h) return -1;
	if (S(3) != hashLen(sa.hash)) return cryptoErr(vm, CE_ILLEGAL_VALUE);
	static u8 sig[256];
	int n = sigDigest(vm, &sa, s, k, h, sig, NULL, 0);
	hashStart(&s->h, sa.hash);
	if (n < 0 || !jcPut(vm, a[4], S(5), sig, n, false)) return -1;
	RET(n);
}

int jn_security_Signature_verify(JcVm *vm, u16 *a)
{
	SigAlg sa;
	NatKey *k;
	NatSig *s = sigReady(vm, a[0], &sa, &k);
	if (!s) return -1;
	if (s->mode != VERIFY) return cryptoErr(vm, CE_ILLEGAL_USE);
	const u8 *in = jcBytes(vm, a[1], S(2), S(3)), *sig = in ? jcBytes(vm, a[4], S(5), S(6)) : NULL;
	if (!sig) return -1;
	if (sa.type == S_MAC) {
		u8 mac[16];
		if (!macFinal(vm, s, &sa, k, in, S(3), mac)) return -1;
		RET(S(6) == sa.len && !memcmp(mac, sig, sa.len));
	}
	u8 h[64];
	hashAdd(&s->h, in, S(3));
	hashDone(&s->h, h);
	keepMsg(s, in, S(3));
	int r = sigDigest(vm, &sa, s, k, h, NULL, sig, S(6));
	s->msgLen = 0;
	if (r < 0) return -1;
	RET(r);
}

// --- KeyAgreement (ECDH) ---

// 1-4 as in 3.0.4; the J3H145 has 5 and 6 of 3.0.5 too: ALG_EC_PACE_GM (d * G + the public data, the
// private key as the nonce), ALG_EC_SVDP_DH_PLAIN_XY (the shared point)
enum { KA_EC_SVDP_DH = 1, KA_EC_SVDP_DHC, KA_EC_SVDP_DH_PLAIN, KA_EC_SVDP_DHC_PLAIN, KA_EC_PACE_GM,
	KA_EC_SVDP_DH_PLAIN_XY };

typedef struct {
	u8 alg, inited;
	u16 key;
} NatAgree;

int jn_security_KeyAgreement_getInstance(JcVm *vm, u16 *a)
{
	u8 alg = a[0];
	if (alg < KA_EC_SVDP_DH || alg > KA_EC_SVDP_DH_PLAIN_XY) return cryptoErr(vm, CE_NO_SUCH_ALGORITHM);
	u16 h = newObj(vm, JCC_security_KeyAgreement);
	if (!h) return -1;
	((NatAgree *)jcNat(vm, h))->alg = alg;
	RET(h);
}

int jn_security_KeyAgreement_getAlgorithm(JcVm *vm, u16 *a)
{
	RET(((NatAgree *)jcNat(vm, a[0]))->alg);
}

int jn_security_KeyAgreement_init_PrivateKey(JcVm *vm, u16 *a)
{
	NatAgree *g = jcNat(vm, a[0]);
	NatKey *k = keyOf(vm, a[1]);
	if (!k) return -1;
	if (k->kind != K_EC_PRIV) return cryptoErr(vm, CE_ILLEGAL_VALUE);
	if (!initialized(k)) return cryptoErr(vm, CE_UNINITIALIZED_KEY);
	g->key = a[1], g->inited = 1;
	return 0;
}

int jn_security_KeyAgreement_generateSecret(JcVm *vm, u16 *a)
{
	NatAgree *g = jcNat(vm, a[0]);
	if (!g->inited) return cryptoErr(vm, CE_INVALID_INIT);
	NatKey *k = usedKey(vm, g->key);
	const u8 *pub = k ? jcBytes(vm, a[1], S(2), S(3)) : NULL;
	if (!pub) return -1;
	static EcCurve curve;
	static Bn d;
	if (!curveOf(vm, k, &curve)) return -1;
	bnFromBytes(&d, part(k, EC_WS), k->len[EC_WS]);
	u8 x[1 + 2 * 66];
	bool xy = g->alg >= KA_EC_PACE_GM;
	if (!(g->alg == KA_EC_PACE_GM ? ecPaceGm(&curve, &d, pub, S(3), x) : ecdh(&curve, &d, pub, S(3), x, xy)))
		return cryptoErr(vm, CE_ILLEGAL_VALUE);
	int n = xy ? 1 + 2 * curve.len : curve.len;
	if (g->alg == KA_EC_SVDP_DH || g->alg == KA_EC_SVDP_DHC) n = hashOnce(MD_SHA, x, n, x);
	if (!jcPut(vm, a[4], S(5), x, n, false)) return -1;
	RET(n);
}

// --- KeyPair ---

enum { KP_RSA = 1, KP_RSA_CRT, KP_DSA, KP_EC_F2M, KP_EC_FP };

typedef struct {
	u8 alg, pad;
	u16 pub, priv;
} NatPair;

static int pairAlg(NatKey *pub, NatKey *priv)
{
	if (pub->kind == K_RSA_PUB && priv->kind == K_RSA_PRIV) return KP_RSA;
	if (pub->kind == K_RSA_PUB && priv->kind == K_RSA_CRT) return KP_RSA_CRT;
	if (pub->kind == K_EC_PUB && priv->kind == K_EC_PRIV) return KP_EC_FP;
	return 0;
}

int jn_security_KeyPair_init_BS(JcVm *vm, u16 *a)
{
	NatPair *p = jcNat(vm, a[0]);
	u8 alg = a[1];
	u16 bits = a[2];
	u8 pubType, privType;
	switch (alg) {
	case KP_RSA: pubType = KT_RSA_PUBLIC, privType = KT_RSA_PRIVATE; break;
	case KP_RSA_CRT: pubType = KT_RSA_PUBLIC, privType = KT_RSA_CRT_PRIVATE; break;
	case KP_EC_FP: pubType = KT_EC_FP_PUBLIC, privType = KT_EC_FP_PRIVATE; break;
	default: return cryptoErr(vm, CE_NO_SUCH_ALGORITHM);
	}
	u16 pub = buildKey(vm, pubType, bits), priv = pub ? buildKey(vm, privType, bits) : 0;
	if (!priv) return -1;
	p->alg = alg, p->pub = pub, p->priv = priv;
	return 0;
}

int jn_security_KeyPair_init_PublicKeyPrivateKey(JcVm *vm, u16 *a)
{
	NatPair *p = jcNat(vm, a[0]);
	NatKey *pub = keyOf(vm, a[1]), *priv = pub ? keyOf(vm, a[2]) : NULL;
	if (!priv) return -1;
	int alg = pairAlg(pub, priv);
	if (!alg || pub->bits != priv->bits) return cryptoErr(vm, CE_ILLEGAL_VALUE);
	p->alg = alg, p->pub = a[1], p->priv = a[2];
	return 0;
}

int jn_security_KeyPair_getPublic(JcVm *vm, u16 *a)
{
	RET(((NatPair *)jcNat(vm, a[0]))->pub);
}

int jn_security_KeyPair_getPrivate(JcVm *vm, u16 *a)
{
	RET(((NatPair *)jcNat(vm, a[0]))->priv);
}

static void putPart(NatKey *k, int i, const u8 *v, u32 len)
{
	memcpy(part(k, i), v, len);
	k->len[i] = len;
	k->set |= 1 << i;
}

// a number into part i (big-endian, at most len bytes, leading zeros dropped)
static void putNum(NatKey *k, int i, const Bn *v, u32 len)
{
	u8 b[4 * BN_N];
	bnToBytes(v, b, len);
	u32 z = 0;
	while (z < len - 1 && !b[z]) z++;
	putPart(k, i, b + z, len - z);
}

// the curve from the public key, else the private one (none: UNINITIALIZED_KEY, as the J3H145: no default)
static int genEc(JcVm *vm, NatKey *pub, NatKey *priv)
{
	static EcCurve curve;
	static Bn d;
	NatKey *from = pub->set & 1 << EC_FIELD ? pub : priv->set & 1 << EC_FIELD ? priv : NULL;
	if (!from) return cryptoErr(vm, CE_UNINITIALIZED_KEY);
	NatKey *to = from == pub ? priv : pub;
	for (int i = EC_FIELD; i <= EC_K; i++)
		if (from->set & 1 << i) putPart(to, i, part(from, i), from->len[i]);
	if (!curveOf(vm, pub, &curve)) return -1;
	ecRandomScalar(&curve, &d, jcRandom);
	putNum(priv, EC_WS, &d, curve.len);
	u8 w[1 + 2 * 66];
	ecPublic(&curve, &d, w);
	putPart(pub, EC_WS, w, 1 + 2 * curve.len);
	return 0;
}

static int genRsa(JcVm *vm, NatKey *pub, NatKey *priv)
{
	static Bn p, q, n, t, d, one, e;
	u32 kb = bytesOf(pub), half = pub->bits / 2;
	u32 ev = 65537;
	if (pub->set & 1 << 1) { // the exponent the applet set
		bnFromBytes(&e, part(pub, 1), pub->len[1]);
		if (bnBits(&e) > 32 || !(e.v[0] & 1) || e.v[0] < 3) return cryptoErr(vm, CE_ILLEGAL_VALUE);
		ev = e.v[0];
	}
	bnSet(&one, 1);
	do {
		bnPrime(&p, half, ev, jcRandom);
		do bnPrime(&q, half, ev, jcRandom);
		while (!bnCmp(&p, &q));
		if (bnCmp(&p, &q) < 0) t = p, p = q, q = t; // p > q (PQ = q^-1 mod p)
		bnMul(&n, &p, &q);
	} while (bnBits(&n) != pub->bits);
	putNum(pub, 0, &n, kb);
	bnSet(&e, ev);
	putNum(pub, 1, &e, 4);
	if (priv->kind == K_RSA_PRIV) {
		static Bn pm1, qm1, phi;
		bnSub(&pm1, &p, &one);
		bnSub(&qm1, &q, &one);
		bnMul(&phi, &pm1, &qm1);
		bnInvSmall(&d, ev, &phi);
		putNum(priv, 0, &n, kb);
		putNum(priv, 1, &d, kb);
		return 0;
	}
	static BnMont P;
	putNum(priv, 0, &p, kb / 2);
	putNum(priv, 1, &q, kb / 2);
	bnSub(&t, &p, &one);
	bnInvSmall(&d, ev, &t);
	putNum(priv, 2, &d, kb / 2);
	bnSub(&t, &q, &one);
	bnInvSmall(&d, ev, &t);
	putNum(priv, 3, &d, kb / 2);
	bnMontInit(&P, &p);
	bnModInvPrime(&P, &d, &q);
	putNum(priv, 4, &d, kb / 2);
	return 0;
}

int jn_security_KeyPair_genKeyPair(JcVm *vm, u16 *a)
{
	NatPair *p = jcNat(vm, a[0]);
	NatKey *pub = keyOf(vm, p->pub), *priv = pub ? keyOf(vm, p->priv) : NULL;
	if (!priv) return -1;
	// new W / S, n / d / CRT parts; the curve and an exponent set before stay
	if (pub->kind == K_EC_PUB) {
		pub->set &= ~(1 << EC_WS);
		priv->set &= ~(1 << EC_WS);
		return genEc(vm, pub, priv);
	}
	jcCryptoNatClear(kindClass[priv->kind], priv);
	pub->set &= ~1;
	return genRsa(vm, pub, priv);
}

// --- native state sizes ---

u16 jcCryptoNatSize(int c)
{
	int k = kindOf(c);
	if (k >= 0) return kindSize(k);
	switch (c) {
	case JCC_security_MessageDigest: return sizeof(Hash);
	case JCC_x_crypto_Cipher: return sizeof(NatCipher);
	case JCC_security_Signature: return sizeof(NatSig);
	case JCC_security_KeyAgreement: return sizeof(NatAgree);
	case JCC_security_KeyPair: return sizeof(NatPair);
	}
	return 0;
}
