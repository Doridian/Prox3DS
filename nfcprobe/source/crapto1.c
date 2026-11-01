// Crypto1 key recovery (crapto1 port) for the ARM11. Faithful translation of the validated
// tools/crapto1.py: lfsr_recovery32 (extend_table / recover with top-byte bucketing) + rollback.
// Self-contained (no 3DS headers) so it host-compiles for testing.

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "crapto1.h"

#define LF_POLY_ODD  0x29CE5C
#define LF_POLY_EVEN 0x870804

static int filter(uint32_t x)
{
	uint32_t f;
	f  = 0xf22c0 >> (x       & 0xf) & 16;
	f |= 0x6c9c0 >> (x >>  4 & 0xf) &  8;
	f |= 0x3c8b0 >> (x >>  8 & 0xf) &  4;
	f |= 0x1e458 >> (x >> 12 & 0xf) &  2;
	f |= 0x0d938 >> (x >> 16 & 0xf) &  1;
	return (0xEC57E80A >> f) & 1;
}

static int par(uint32_t x)
{
	return __builtin_parity(x);
}

static int bebit(uint32_t x, int n)
{
	return (x >> (n ^ 24)) & 1;
}

int (*crapto1_tick)(int permille);

static int tick(int permille)
{
	return crapto1_tick && crapto1_tick(permille);
}

// --- forward cipher (matches crypto1.py), for candidate filtering / verification ---

typedef struct {
	uint32_t odd, even;
} C1;

static int c1_bitx(C1 *c, int in, int fb);

static void c1_init(C1 *c, uint64_t key)
{
	c->odd = c->even = 0;
	for (int i = 47; i > 0; i -= 2) {
		c->odd = c->odd << 1 | ((key >> ((i - 1) ^ 7)) & 1);
		c->even = c->even << 1 | ((key >> (i ^ 7)) & 1);
	}
}

static int c1_bit(C1 *c, int in)
{
	return c1_bitx(c, in, 0);
}

// fb: feed the keystream bit back too (encrypted input, as when decrypting a nested nonce)
static int c1_bitx(C1 *c, int in, int fb)
{
	int ret = filter(c->odd);
	uint32_t feed = ((in ? 1 : 0) ^ (fb ? ret : 0)) ^ (LF_POLY_ODD & c->odd) ^ (LF_POLY_EVEN & c->even);
	c->even = ((c->even << 1) | par(feed)) & 0xFFFFFF;
	uint32_t t = c->odd;
	c->odd = c->even;
	c->even = t;
	return ret;
}

uint32_t crapto1_ks32(uint64_t key, uint32_t in)
{
	C1 c;
	c1_init(&c, key);
	uint32_t ret = 0;
	for (int i = 0; i < 32; i++)
		ret |= (uint32_t)c1_bit(&c, (in >> (i ^ 24)) & 1) << (i ^ 24);
	return ret;
}

// --- growable u32 array ---

typedef struct {
	uint32_t *a;
	size_t n, cap;
} Vec;

static void vpush(Vec *v, uint32_t x)
{
	if (v->n == v->cap) {
		v->cap = v->cap ? v->cap * 2 : 1024;
		v->a = realloc(v->a, v->cap * sizeof(uint32_t));
	}
	v->a[v->n++] = x;
}

typedef struct {
	uint32_t odd, even;
	size_t n, cap;
	uint64_t *a; // packed (odd<<32 | even) states
} SVec;

static void spush(SVec *s, uint32_t odd, uint32_t even)
{
	if (s->n == s->cap) {
		s->cap = s->cap ? s->cap * 2 : 4096;
		s->a = realloc(s->a, s->cap * sizeof(uint64_t));
	}
	s->a[s->n++] = (uint64_t)odd << 32 | even;
}

// --- recovery ---

static uint32_t update_contribution(uint32_t item, uint32_t m1, uint32_t m2)
{
	uint32_t p = item >> 25;
	p = p << 1 | par(item & m1);
	p = p << 1 | par(item & m2);
	return (p << 24) | (item & 0xFFFFFF);
}

static Vec extend_table(Vec in, int bit, uint32_t m1, uint32_t m2, uint32_t inn)
{
	inn <<= 24;
	Vec o = {0};
	for (size_t i = 0; i < in.n; i++) {
		uint32_t t = in.a[i] << 1;
		if (filter(t) ^ filter(t | 1)) {
			t |= filter(t) ^ bit;
			vpush(&o, update_contribution(t, m1, m2) ^ inn);
		} else if (filter(t) == bit) {
			vpush(&o, update_contribution(t, m1, m2) ^ inn);
			vpush(&o, update_contribution(t | 1, m1, m2) ^ inn);
		}
	}
	return o;
}

static Vec extend_table_simple(Vec in, int bit)
{
	Vec o = {0};
	for (size_t i = 0; i < in.n; i++) {
		uint32_t t = in.a[i] << 1;
		if (filter(t) ^ filter(t | 1)) {
			vpush(&o, t | (filter(t) ^ bit));
		} else if (filter(t) == bit) {
			vpush(&o, t);
			vpush(&o, t | 1);
		}
	}
	return o;
}

// Owns odd/even (frees them); appends final states to out. The top call's buckets report progress.
static void recover(Vec odd, uint32_t oks, Vec even, uint32_t eks, int rem, SVec *out, uint32_t inn, int top)
{
	if (rem == -1) {
		for (size_t ei = 0; ei < even.n; ei++) {
			uint32_t e = (even.a[ei] << 1) ^ par(even.a[ei] & LF_POLY_EVEN) ^ ((inn & 4) ? 1 : 0);
			for (size_t oi = 0; oi < odd.n; oi++)
				spush(out, e ^ par(odd.a[oi] & LF_POLY_ODD), odd.a[oi]);
		}
		free(odd.a);
		free(even.a);
		return;
	}
	int i = 0;
	while (i < 4) {
		int old = rem;
		rem--;
		if (old == 0)
			break;
		oks >>= 1;
		eks >>= 1;
		inn >>= 2;
		Vec no = extend_table(odd, oks & 1, (LF_POLY_EVEN << 1) | 1, LF_POLY_ODD << 1, 0);
		free(odd.a);
		odd = no;
		Vec ne = extend_table(even, eks & 1, LF_POLY_ODD, (LF_POLY_EVEN << 1) | 1, inn & 3);
		free(even.a);
		even = ne;
		if (!odd.n || !even.n) {
			free(odd.a);
			free(even.a);
			return;
		}
		i++;
	}
	Vec *ob = calloc(256, sizeof(Vec)), *eb = calloc(256, sizeof(Vec));
	for (size_t k = 0; k < odd.n; k++)
		vpush(&ob[odd.a[k] >> 24], odd.a[k]);
	for (size_t k = 0; k < even.n; k++)
		vpush(&eb[even.a[k] >> 24], even.a[k]);
	free(odd.a);
	free(even.a);
	int stop = 0;
	for (int b = 0; b < 256; b++) {
		if (top && !stop) stop = tick(250 + 750 * b / 256); // the buckets take about the same time each
		if (ob[b].n && eb[b].n && !stop) {
			recover(ob[b], oks, eb[b], eks, rem, out, inn, 0);
		} else {
			free(ob[b].a);
			free(eb[b].a);
		}
	}
	free(ob);
	free(eb);
}

static void lfsr_recovery32(uint32_t ks2, uint32_t inn, SVec *out)
{
	uint32_t oks = 0, eks = 0;
	for (int i = 31; i >= 0; i -= 2)
		oks = oks << 1 | bebit(ks2, i);
	for (int i = 30; i >= 0; i -= 2)
		eks = eks << 1 | bebit(ks2, i);
	Vec odd = {0}, even = {0};
	tick(0);
	odd.cap = even.cap = 1 << 20; // reserve to avoid realloc churn in the seed loop
	odd.a = malloc(odd.cap * sizeof(uint32_t));
	even.a = malloc(even.cap * sizeof(uint32_t));
	for (uint32_t i = 0; i <= (1u << 20); i++) {
		if (filter(i) == (int)(oks & 1))
			vpush(&odd, i);
		if (filter(i) == (int)(eks & 1))
			vpush(&even, i);
	}
	tick(100);
	for (int r = 0; r < 4; r++) {
		oks >>= 1;
		eks >>= 1;
		Vec no = extend_table_simple(odd, oks & 1);
		free(odd.a);
		odd = no;
		Vec ne = extend_table_simple(even, eks & 1);
		free(even.a);
		even = ne;
	}
	inn = (inn >> 16 & 0xff) | (inn << 16) | (inn & 0xff00);
	recover(odd, oks, even, eks, 11, out, inn << 1, 1);
	tick(1000);
}

static int rollback_bit(uint32_t *s, int in, int fb)
{
	s[0] &= 0xFFFFFF;
	uint32_t t = s[0];
	s[0] = s[1];
	s[1] = t;
	uint32_t out = s[1] & 1;
	s[1] >>= 1;
	out ^= LF_POLY_EVEN & s[1];
	out ^= LF_POLY_ODD & s[0];
	out ^= in ? 1 : 0;
	int ret = filter(s[0]);
	out ^= ret & (fb ? 1 : 0);
	s[1] |= (uint32_t)par(out) << 23;
	return ret;
}

static void rollback_word(uint32_t *s, uint32_t in, int fb)
{
	for (int i = 31; i >= 0; i--)
		rollback_bit(s, bebit(in, i), fb);
}

static uint64_t get_lfsr(uint32_t odd, uint32_t even)
{
	uint64_t l = 0;
	for (int i = 23; i >= 0; i--) {
		l = l << 1 | ((odd >> (i ^ 3)) & 1);
		l = l << 1 | ((even >> (i ^ 3)) & 1);
	}
	return l;
}

int crapto1_recover(uint32_t uid, uint32_t nt, uint32_t ks, uint64_t *out, int max)
{
	SVec sv = {0};
	uint32_t inn = uid ^ nt;
	lfsr_recovery32(ks, inn, &sv);
	int cnt = 0;
	for (size_t i = 0; i < sv.n && cnt < max; i++) {
		uint32_t s[2] = { (uint32_t)(sv.a[i] >> 32), (uint32_t)sv.a[i] };
		rollback_word(s, inn, 0);
		out[cnt++] = get_lfsr(s[0], s[1]);
	}
	free(sv.a);
	return cnt;
}

uint32_t crapto1_nt_decrypt(uint64_t key, uint32_t uid, uint32_t ntEnc)
{
	C1 c;
	c1_init(&c, key);
	uint32_t in = uid ^ ntEnc, ks = 0;
	for (int i = 0; i < 32; i++)
		ks |= (uint32_t)c1_bitx(&c, (in >> (i ^ 24)) & 1, 1) << (i ^ 24);
	return ntEnc ^ ks;
}

static int oddpar8(uint32_t b)
{
	return !par(b & 0xFF);
}

int crapto1_static(uint32_t uid, uint32_t nt, uint32_t ntEnc, int parEnc, uint64_t *out, int max)
{
	SVec sv = {0};
	uint32_t inn = uid ^ nt;
	lfsr_recovery32(nt ^ ntEnc, inn, &sv);
	int want = oddpar8(nt) ^ (parEnc & 1), cnt = 0;
	for (size_t i = 0; i < sv.n && cnt < max; i++) {
		uint32_t s[2] = { (uint32_t)(sv.a[i] >> 32), (uint32_t)sv.a[i] };
		rollback_word(s, inn, 0);
		uint64_t key = get_lfsr(s[0], s[1]);
		// The last nonce byte's parity bit is encrypted with the first keystream bit after nt.
		C1 c;
		c1_init(&c, key);
		for (int b = 0; b < 32; b++)
			c1_bit(&c, (inn >> (b ^ 24)) & 1);
		if (filter(c.odd) == want)
			out[cnt++] = key;
	}
	free(sv.a);
	return cnt;
}

uint64_t crapto1_nested(uint32_t uid, uint32_t nt1, uint32_t ks1, uint32_t nt2, uint32_t ks2)
{
	SVec sv = {0};
	uint32_t in1 = uid ^ nt1, in2 = uid ^ nt2;
	lfsr_recovery32(ks1, in1, &sv);
	uint64_t found = 0;
	for (size_t i = 0; i < sv.n; i++) {
		uint32_t s[2] = { (uint32_t)(sv.a[i] >> 32), (uint32_t)sv.a[i] };
		rollback_word(s, in1, 0);
		uint64_t key = get_lfsr(s[0], s[1]);
		if (crapto1_ks32(key, in2) == ks2) { // keystream consistent with the 2nd nonce
			found = key;
			break;
		}
	}
	free(sv.a);
	return found;
}
