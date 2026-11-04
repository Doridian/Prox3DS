// Crypto1 key recovery (crapto1 port) for the ARM11. Faithful translation of the validated
// tools/crapto1.py: lfsr_recovery32 (extend_table / recover with top-byte bucketing) + rollback.
// Self-contained (no 3DS headers) so it host-compiles for testing. The big table passes run on
// every core (par.h), the results in the same order as one core would give them.
// Derived from crapto1 (C) 2008-2014 bla <blapost@gmail.com> and the Proxmark3 contributors, GPL; see CREDITS.md.

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "crapto1.h"
#include "par.h"

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

static volatile int stopped; // the hook said stop, the recovery winds down (helpers check it too)

static int tick(int permille)
{
	if (crapto1_tick && crapto1_tick(permille)) stopped = 1;
	return stopped;
}

// parFor with progress: n items, the bar from `from` to `to` permille as they are handed out, ticked
// by the caller's thread before each of its items (so items should be short: ~10 ms on the 3DS).
typedef struct {
	void (*fn)(void *arg, int i);
	void *arg;
	int n, from, to;
	volatile int started;
} Each;

static void eachItem(void *p, int i)
{
	Each *e = p;
	if (stopped) return;
	int k = __atomic_fetch_add(&e->started, 1, __ATOMIC_RELAXED);
	if (parMain()) tick(e->from + (e->to - e->from) * k / e->n);
	e->fn(e->arg, i);
}

static void each(int n, void (*fn)(void *arg, int i), void *arg, int from, int to)
{
	Each e = { fn, arg, n, from, to, 0 };
	parFor(n, eachItem, &e);
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

// A table pass in SPLIT chunks over [0, total) on every core: fn(ctx, lo, hi, out) appends to out[0]
// (and out[1] for the seed pass); the chunks' outputs are joined in order.
#define SPLIT 64

typedef struct {
	void (*fn)(void *ctx, size_t lo, size_t hi, Vec *out);
	void *ctx;
	size_t total;
	Vec part[SPLIT][2];
} Split;

static void splitItem(void *p, int c)
{
	Split *s = p;
	s->fn(s->ctx, (uint64_t)s->total * c / SPLIT, (uint64_t)s->total * (c + 1) / SPLIT, s->part[c]);
}

static void split(void (*fn)(void *ctx, size_t lo, size_t hi, Vec *out), void *ctx, size_t total, Vec *out,
	int nout, int from, int to)
{
	Split *s = calloc(1, sizeof(Split));
	if (!s) {
		stopped = 1;
		return;
	}
	s->fn = fn, s->ctx = ctx, s->total = total;
	each(SPLIT, splitItem, s, from, to);
	for (int k = 0; k < nout; k++) {
		size_t n = 0;
		for (int c = 0; c < SPLIT; c++) n += s->part[c][k].n;
		out[k].n = 0, out[k].cap = n ? n : 1;
		out[k].a = malloc(out[k].cap * sizeof(uint32_t));
		for (int c = 0; c < SPLIT; c++) {
			if (out[k].a) memcpy(out[k].a + out[k].n, s->part[c][k].a, s->part[c][k].n * sizeof(uint32_t));
			out[k].n += s->part[c][k].n;
			free(s->part[c][k].a);
		}
		if (!out[k].a) out[k].n = 0, stopped = 1;
	}
	free(s);
}

typedef struct {
	const uint32_t *in;
	int bit, simple;
	uint32_t m1, m2, inn;
} Ext;

static void extend_part(void *ctx, size_t lo, size_t hi, Vec *o)
{
	const Ext *x = ctx;
	uint32_t inn = x->inn << 24;
	for (size_t i = lo; i < hi; i++) {
		uint32_t t = x->in[i] << 1;
		if (x->simple) {
			if (filter(t) ^ filter(t | 1)) {
				vpush(o, t | (filter(t) ^ x->bit));
			} else if (filter(t) == x->bit) {
				vpush(o, t);
				vpush(o, t | 1);
			}
		} else if (filter(t) ^ filter(t | 1)) {
			t |= filter(t) ^ x->bit;
			vpush(o, update_contribution(t, x->m1, x->m2) ^ inn);
		} else if (filter(t) == x->bit) {
			vpush(o, update_contribution(t, x->m1, x->m2) ^ inn);
			vpush(o, update_contribution(t | 1, x->m1, x->m2) ^ inn);
		}
	}
}

// Scratch for the tables below the top call: one top-level group's whole subtree takes a few
// dozen KB, handed out from one block (malloc, a lock shared by the cores, is what the subtrees cost
// otherwise) and given back as a whole when the call that took it returns. Tables that don't fit
// (and the top call's) come from malloc.
#define SCRATCH (64 << 10) // entries

typedef struct {
	uint32_t *base;
	size_t used;
} Scratch;

static uint32_t *take(Scratch *sc, size_t n)
{
	if (sc && sc->base && sc->used + n <= SCRATCH) {
		sc->used += n;
		return sc->base + sc->used - n;
	}
	uint32_t *p = malloc(n * sizeof(uint32_t) + 1);
	if (!p) stopped = 1;
	return p;
}

static void give(Scratch *sc, uint32_t *p)
{
	if (!sc || p < sc->base || p >= sc->base + SCRATCH) free(p);
}

// Split over the cores for the top-level tables (from < to), else here into a table sized for the
// worst case (every entry kept twice), trimmed to what it got when it's the newest scratch.
static Vec extend(Vec in, int bit, int simple, uint32_t m1, uint32_t m2, uint32_t inn, int from, int to, Scratch *sc)
{
	Ext x = { in.a, bit, simple, m1, m2, inn };
	Vec o = {0};
	if (from < to) {
		split(extend_part, &x, in.n, &o, 1, from, to);
	} else if ((o.a = take(sc, 2 * in.n + 1))) {
		o.cap = 2 * in.n + 1;
		extend_part(&x, 0, in.n, &o);
		if (sc && o.a + o.cap == sc->base + sc->used) sc->used -= o.cap - o.n;
	}
	return o;
}

// The table grouped by top byte (a stable counting sort: the order within a group stays), group b at
// at[b] .. at[b + 1] of the result.
static uint32_t *group(Vec v, size_t at[257], Scratch *sc)
{
	size_t pos[256] = {0};
	for (size_t i = 0; i < v.n; i++) pos[v.a[i] >> 24]++;
	at[0] = 0;
	for (int b = 0; b < 256; b++) at[b + 1] = at[b] + pos[b], pos[b] = at[b];
	uint32_t *g = take(sc, v.n);
	if (g)
		for (size_t i = 0; i < v.n; i++) g[pos[v.a[i] >> 24]++] = v.a[i];
	return g;
}

static Vec part(uint32_t *g, const size_t *at, int b)
{
	return (Vec){ g + at[b], at[b + 1] - at[b], 0 };
}

static void recover(Vec odd, uint32_t oks, Vec even, uint32_t eks, int rem, SVec *out, uint32_t inn, Scratch *sc,
	int top);

// The top call's 256 groups, one per item, each into its own list and with its own scratch.
typedef struct {
	uint32_t *og, *eg;
	size_t oat[257], eat[257];
	uint32_t oks, eks, inn;
	int rem;
	SVec out[256];
} Groups;

static void groupItem(void *p, int b)
{
	Groups *k = p;
	Vec o = part(k->og, k->oat, b), e = part(k->eg, k->eat, b);
	if (!o.n || !e.n) return;
	Scratch sc = { malloc(SCRATCH * sizeof(uint32_t)), 0 };
	recover(o, k->oks, e, k->eks, k->rem, &k->out[b], k->inn, &sc, 0);
	free(sc.base);
}

// Appends the final states to out; odd and even stay the caller's. The top call's work is spread
// over the cores and reports progress.
static void recover(Vec odd, uint32_t oks, Vec even, uint32_t eks, int rem, SVec *out, uint32_t inn, Scratch *sc,
	int top)
{
	if (stopped) return;
	if (rem == -1) {
		for (size_t ei = 0; ei < even.n; ei++) {
			uint32_t e = (even.a[ei] << 1) ^ par(even.a[ei] & LF_POLY_EVEN) ^ ((inn & 4) ? 1 : 0);
			for (size_t oi = 0; oi < odd.n; oi++)
				spush(out, e ^ par(odd.a[oi] & LF_POLY_ODD), odd.a[oi]);
		}
		return;
	}
	size_t mark = sc ? sc->used : 0;
	int i = 0, own = 0; // own: odd / even are tables made here
	while (i < 4) {
		int old = rem, p = 110 + 35 * i; // the top call's extends: the biggest tables
		rem--;
		if (old == 0)
			break;
		oks >>= 1;
		eks >>= 1;
		inn >>= 2;
		Vec no = extend(odd, oks & 1, 0, (LF_POLY_EVEN << 1) | 1, LF_POLY_ODD << 1, 0, p, top ? p + 17 : p, sc);
		Vec ne = extend(even, eks & 1, 0, LF_POLY_ODD, (LF_POLY_EVEN << 1) | 1, inn & 3, p + 17, top ? p + 35 : p, sc);
		if (own) {
			give(sc, odd.a);
			give(sc, even.a);
		}
		odd = no, even = ne, own = 1;
		if (!odd.n || !even.n) break;
		i++;
	}
	Groups *k = NULL;
	size_t oat[257], eat[257];
	uint32_t *og = NULL, *eg = NULL;
	if (odd.n && even.n && !stopped) {
		if (top && !(k = calloc(1, sizeof(Groups)))) stopped = 1;
		og = group(odd, k ? k->oat : oat, sc);
		eg = group(even, k ? k->eat : eat, sc);
	}
	if (own) {
		give(sc, odd.a);
		give(sc, even.a);
	}
	if (og && eg && top && !stopped) {
		k->og = og, k->eg = eg, k->oks = oks, k->eks = eks, k->inn = inn, k->rem = rem;
		each(256, groupItem, k, 250, 1000); // about the same time each, 75% of it all
		for (int b = 0; b < 256; b++) {
			for (size_t j = 0; j < k->out[b].n; j++)
				spush(out, k->out[b].a[j] >> 32, (uint32_t)k->out[b].a[j]);
			free(k->out[b].a);
		}
	} else if (og && eg) {
		for (int b = 0; b < 256 && !stopped; b++) {
			Vec o = part(og, oat, b), e = part(eg, eat, b);
			if (o.n && e.n) recover(o, oks, e, eks, rem, out, inn, sc, 0);
		}
	}
	give(sc, og);
	give(sc, eg);
	free(k);
	if (sc) sc->used = mark;
}

typedef struct {
	int oks, eks;
} Seed;

static void seed_part(void *ctx, size_t lo, size_t hi, Vec *o)
{
	const Seed *x = ctx;
	for (uint32_t i = lo; i < hi; i++) {
		int f = filter(i);
		if (f == x->oks) vpush(&o[0], i);
		if (f == x->eks) vpush(&o[1], i);
	}
}

static void lfsr_recovery32(uint32_t ks2, uint32_t inn, SVec *out)
{
	uint32_t oks = 0, eks = 0;
	for (int i = 31; i >= 0; i -= 2)
		oks = oks << 1 | bebit(ks2, i);
	for (int i = 30; i >= 0; i -= 2)
		eks = eks << 1 | bebit(ks2, i);
	stopped = 0;
	tick(0);
	Seed sd = { oks & 1, eks & 1 };
	Vec oe[2] = { {0}, {0} };
	split(seed_part, &sd, (1u << 20) + 1, oe, 2, 0, 15);
	Vec odd = oe[0], even = oe[1];
	for (int r = 0; r < 4 && !stopped; r++) {
		int p = 15 + 95 * r / 4;
		oks >>= 1;
		eks >>= 1;
		Vec no = extend(odd, oks & 1, 1, 0, 0, 0, p, p + 12, NULL), ne = extend(even, eks & 1, 1, 0, 0, 0, p + 12, p + 23, NULL);
		free(odd.a);
		free(even.a);
		odd = no, even = ne;
	}
	inn = (inn >> 16 & 0xff) | (inn << 16) | (inn & 0xff00);
	recover(odd, oks, even, eks, 11, out, inn << 1, NULL, 1);
	free(odd.a);
	free(even.a);
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

// The checks after lfsr_recovery32, in SPLIT chunks of its states on every core: each state rolled
// back over in (uid ^ nt) to a key, kept (in state order) when keep says so. first: only the first
// one wanted, so a chunk stops once it or one before it has one.
typedef struct {
	const uint64_t *st;
	size_t n;
	uint32_t in;
	int (*keep)(const void *ctx, uint64_t key);
	const void *ctx;
	int first;
	int hit; // first: the lowest chunk with a key so far
	SVec part[SPLIT];
} Check;

static void checkItem(void *p, int c)
{
	Check *k = p;
	size_t lo = (uint64_t)k->n * c / SPLIT, hi = (uint64_t)k->n * (c + 1) / SPLIT;
	for (size_t i = lo; i < hi && !(k->first && __atomic_load_n(&k->hit, __ATOMIC_RELAXED) <= c); i++) {
		uint32_t s[2] = { (uint32_t)(k->st[i] >> 32), (uint32_t)k->st[i] };
		rollback_word(s, k->in, 0);
		uint64_t key = get_lfsr(s[0], s[1]);
		if (k->keep && !k->keep(k->ctx, key)) continue;
		spush(&k->part[c], key >> 32, (uint32_t)key);
		for (int h = __atomic_load_n(&k->hit, __ATOMIC_RELAXED); k->first && c < h && !__atomic_compare_exchange_n(&k->hit, &h, c, 0, __ATOMIC_RELAXED,
			__ATOMIC_RELAXED);)
			;
	}
}

// lfsr_recovery32 + the checks; returns the count written to out (capped at max).
static int recover_keys(uint32_t ks, uint32_t in, int (*keep)(const void *ctx, uint64_t key), const void *ctx,
	int first, uint64_t *out, int max)
{
	SVec sv = {0};
	lfsr_recovery32(ks, in, &sv);
	Check *k = calloc(1, sizeof(Check));
	int cnt = 0;
	if (k) {
		k->st = sv.a, k->n = sv.n, k->in = in, k->keep = keep, k->ctx = ctx, k->first = first, k->hit = SPLIT;
		each(SPLIT, checkItem, k, 1000, 1000);
		for (int c = 0; c < SPLIT; c++) {
			for (size_t i = 0; i < k->part[c].n && cnt < max; i++) out[cnt++] = k->part[c].a[i];
			free(k->part[c].a);
		}
	}
	free(k);
	free(sv.a);
	return cnt;
}

int crapto1_recover(uint32_t uid, uint32_t nt, uint32_t ks, uint64_t *out, int max)
{
	return recover_keys(ks, uid ^ nt, NULL, NULL, 0, out, max);
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

typedef struct {
	uint32_t in;
	int want;
} StaticPar;

// The last nonce byte's parity bit is encrypted with the first keystream bit after nt.
static int static_keep(const void *ctx, uint64_t key)
{
	const StaticPar *x = ctx;
	C1 c;
	c1_init(&c, key);
	for (int b = 0; b < 32; b++)
		c1_bit(&c, (x->in >> (b ^ 24)) & 1);
	return filter(c.odd) == x->want;
}

int crapto1_static(uint32_t uid, uint32_t nt, uint32_t ntEnc, int parEnc, uint64_t *out, int max)
{
	StaticPar x = { uid ^ nt, oddpar8(nt) ^ (parEnc & 1) };
	return recover_keys(nt ^ ntEnc, uid ^ nt, static_keep, &x, 0, out, max);
}

uint64_t crapto1_nested(uint32_t uid, uint32_t nt1, uint32_t ks1, uint32_t nt2, uint32_t ks2)
{
	return crapto1_nested_any(uid, nt1, ks1, &nt2, &ks2, 1);
}

typedef struct {
	uint32_t uid;
	const uint32_t *nt2, *ks2;
	int n2;
} Second;

// Keystream consistent with one of the second nonces.
static int nested_keep(const void *ctx, uint64_t key)
{
	const Second *x = ctx;
	for (int j = 0; j < x->n2; j++)
		if (crapto1_ks32(key, x->uid ^ x->nt2[j]) == x->ks2[j]) return 1;
	return 0;
}

uint64_t crapto1_nested_any(uint32_t uid, uint32_t nt1, uint32_t ks1, const uint32_t *nt2, const uint32_t *ks2, int n2)
{
	Second x = { uid, nt2, ks2, n2 };
	uint64_t found = 0;
	recover_keys(ks1, uid ^ nt1, nested_keep, &x, 1, &found, 1);
	return found;
}

// --- Darkside / common-prefix recovery (pm3 lfsr_common_prefix + nonce2key), always-leak path ---
// The card leaks a 4-bit encrypted NACK regardless of parity (par_info == 0). With nt held fixed and
// only the top 3 bits of the last nr byte swept (nt_diff 0..7), the 8 NACK keystreams pin the cipher
// state down; one run gives a large candidate list, the key is the one common to several runs. See
// docs/NOTES.md and tools/darkside.py (the validated reference).

// crapto1 fast-forward tables: advance a 21-bit half-state by the cipher's run over nt_diff = c.
static const uint32_t fastfwd[2][8] = {
	{ 0, 0x4BC53, 0x0ECB1, 0x450E2, 0x25E29, 0x6E27A, 0x2B298, 0x60ECB }, // even (isodd 0)
	{ 0, 0x1D962, 0x4BC53, 0x56531, 0x0ECB1, 0x135D3, 0x450E2, 0x58980 }, // odd  (isodd 1)
};

// filter() over its 20 input bits as a bitmap, for the darkside's hot loops (built once, 128 KB).
static uint8_t *ftab;

static int ftab_init(void)
{
	if (!ftab && (ftab = malloc(1 << 17)))
		for (uint32_t x = 0; x < (1u << 20); x += 8) {
			uint8_t b = 0;
			for (int k = 0; k < 8; k++) b |= filter(x + k) << k;
			ftab[x >> 3] = b;
		}
	return ftab != NULL;
}

static int ffilter(uint32_t x)
{
	x &= 0xFFFFF;
	return ftab[x >> 3] >> (x & 7) & 1;
}

// rollback_word with the keystream fed back, on ffilter.
static void rollback_word_fb(uint32_t *s, uint32_t in)
{
	for (int i = 31; i >= 0; i--) {
		s[0] &= 0xFFFFFF;
		uint32_t t = s[0];
		s[0] = s[1];
		s[1] = t;
		uint32_t out = s[1] & 1;
		s[1] >>= 1;
		out ^= (LF_POLY_EVEN & s[1]) ^ (LF_POLY_ODD & s[0]);
		out ^= bebit(in, i) ^ ffilter(s[0]);
		s[1] |= (uint32_t)par(out) << 23;
	}
}

// 21-bit partial states of one LFSR half consistent with the 8 observed NACK keystreams.
typedef struct {
	const uint8_t *ks;
	int isodd;
} Pfx;

static void prefix_part(void *ctx, size_t lo, size_t hi, Vec *out)
{
	const Pfx *x = ctx;
	for (uint32_t i = lo; i < hi; i++) {
		int good = 1;
		for (int c = 0; good && c < 8; c++) {
			uint32_t e = i ^ fastfwd[x->isodd][c];
			good &= ((x->ks[c] >> x->isodd) & 1) == ffilter(e >> 1);
			good &= ((x->ks[c] >> (x->isodd + 2)) & 1) == ffilter(e);
		}
		if (good) vpush(out, i);
	}
}

static Vec prefix_ks(const uint8_t ks[8], int isodd, int from, int to)
{
	Pfx x = { ks, isodd };
	Vec o = {0};
	split(prefix_part, &x, 1u << 21, &o, 1, from, to);
	return o;
}

static int cmp_u64(const void *a, const void *b)
{
	uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
	return x < y ? -1 : x > y ? 1 : 0;
}

// The darkside rollback's linear stretches (no keystream feedback, so linear over GF(2) in the state,
// plus a constant for a known input) as byte lookup tables over the 48-bit state odd | even << 24.
typedef uint64_t LinTab[6][256];
static LinTab dsPre, dsPost;

static uint64_t lin_apply(const LinTab t, uint64_t v)
{
	return t[0][v & 0xFF] ^ t[1][v >> 8 & 0xFF] ^ t[2][v >> 16 & 0xFF] ^ t[3][v >> 24 & 0xFF] ^ t[4][v >> 32 & 0xFF]
	     ^ t[5][v >> 40 & 0xFF];
}

static void lin_build(LinTab t, uint64_t (*f)(uint64_t))
{
	uint64_t img[48];
	for (int i = 0; i < 48; i++) img[i] = f(1ull << i);
	for (int j = 0; j < 6; j++)
		for (int b = 0; b < 256; b++) {
			uint64_t x = 0;
			for (int k = 0; k < 8; k++)
				if (b >> k & 1) x ^= img[8 * j + k];
			t[j][b] = x;
		}
}

// After the NACK back to the end of {nr}: 3 keystream bits and the {ar} word, input 0.
static uint64_t ds_pre(uint64_t v)
{
	uint32_t s[2] = { v & 0xFFFFFF, v >> 24 & 0xFFFFFF };
	rollback_bit(s, 0, 0);
	rollback_bit(s, 0, 0);
	rollback_bit(s, 0, 0);
	rollback_word(s, 0, 0);
	return (s[0] & 0xFFFFFF) | (uint64_t)(s[1] & 0xFFFFFF) << 24;
}

// Back over uid ^ nt (its input's part is the constant ds_post's caller adds) and read the key.
static uint64_t ds_post(uint64_t v)
{
	uint32_t s[2] = { v & 0xFFFFFF, v >> 24 & 0xFFFFFF };
	rollback_word(s, 0, 0);
	return get_lfsr(s[0], s[1]);
}

// The earlier run's list (ascending), indexed by the keys' top 16 bits: the lookups in the candidate
// loop then search a few dozen keys, not the whole list.
typedef struct {
	const uint64_t *a;
	uint32_t *idx; // idx[h] .. idx[h + 1]: the keys with k >> 32 == h
} KeySet;

static int keyset_init(KeySet *ks, const uint64_t *a, int n)
{
	ks->a = a;
	if (!(ks->idx = malloc(65537 * sizeof(uint32_t)))) return 0;
	int j = 0;
	for (uint32_t h = 0; h <= 65536; h++) {
		while (j < n && a[j] >> 32 < h) j++;
		ks->idx[h] = j;
	}
	return 1;
}

static int keyset_has(const KeySet *ks, uint64_t k)
{
	uint32_t lo = ks->idx[k >> 32], hi = ks->idx[(k >> 32) + 1];
	while (lo < hi) {
		uint32_t m = (lo + hi) / 2;
		if (ks->a[m] < k) lo = m + 1;
		else hi = m;
	}
	return lo < ks->idx[(k >> 32) + 1] && ks->a[lo] == k;
}

static void kpush(SVec *s, uint64_t k)
{
	spush(s, k >> 32, (uint32_t)k);
}

// The candidate loop over (odd, even) pairs in DS_ITEMS items: every pair gives 64 keys. Without a
// list to keep, item c writes its keys straight into their place in keys; with one, into its own
// list (few survive).
#define DS_ITEMS 256

typedef struct {
	Vec odd, even;
	uint32_t nrWire;
	uint64_t kc;
	const KeySet *in;
	uint64_t *keys;
	SVec part[DS_ITEMS];
} DsLoop;

static void dsItem(void *p, int c)
{
	DsLoop *d = p;
	size_t total = d->odd.n * d->even.n, lo = (uint64_t)total * c / DS_ITEMS, hi = (uint64_t)total * (c + 1) / DS_ITEMS;
	uint64_t *w = d->keys ? d->keys + lo * 64 : NULL;
	for (size_t j = lo; j < hi; j++) {
		uint32_t o = d->odd.a[j / d->even.n], e = d->even.a[j % d->even.n];
		for (int top = 0; top < 64; top++) {
			o += 1u << 21;
			e += ((top & 7 ? 0 : 1) + 1) << 21;
			// check_pfx_parity, no_par: advance to nt_diff 0, roll back to the post-nt state. Only {nr}
			// (keystream fed back) isn't linear.
			uint64_t v = ((o ^ fastfwd[1][0]) & 0xFFFFFF) | (uint64_t)((e ^ fastfwd[0][0]) & 0xFFFFFF) << 24;
			v = lin_apply(dsPre, v);
			uint32_t s[2] = { v & 0xFFFFFF, v >> 24 };
			rollback_word_fb(s, d->nrWire);
			uint64_t k = lin_apply(dsPost, (s[0] & 0xFFFFFF) | (uint64_t)(s[1] & 0xFFFFFF) << 24) ^ d->kc;
			if (w) *w++ = k;
			else if (keyset_has(d->in, k)) kpush(&d->part[c], k);
		}
	}
}

// Sort + unique, in place: the keys go to buckets by their top byte (an in-place radix pass), then
// the buckets are sorted on every core and closed up.
typedef struct {
	uint64_t *a;
	size_t start[257], uniq[256];
} DsSort;

static void sortItem(void *p, int b)
{
	DsSort *d = p;
	uint64_t *a = d->a + d->start[b];
	size_t n = d->start[b + 1] - d->start[b], u = 0;
	qsort(a, n, sizeof(uint64_t), cmp_u64);
	for (size_t i = 0; i < n; i++)
		if (!u || a[i] != a[u - 1]) a[u++] = a[i];
	d->uniq[b] = u;
}

static size_t sort_unique(uint64_t *a, size_t n)
{
	DsSort *d = malloc(sizeof(DsSort));
	if (!d) return 0;
	size_t next[256] = {0};
	for (size_t i = 0; i < n; i++) next[a[i] >> 40 & 0xFF]++;
	d->a = a, d->start[0] = 0;
	for (int b = 0; b < 256; b++) d->start[b + 1] = d->start[b] + next[b], next[b] = d->start[b];
	for (int b = 0; b < 256; b++)
		while (next[b] < d->start[b + 1]) {
			uint64_t v = a[next[b]];
			for (int t = v >> 40 & 0xFF; t != b; t = v >> 40 & 0xFF) {
				uint64_t x = a[next[t]];
				a[next[t]++] = v;
				v = x;
			}
			a[next[b]++] = v;
		}
	each(256, sortItem, d, 800, 1000);
	size_t u = 0;
	for (int b = 0; b < 256; b++) {
		memmove(a + u, a + d->start[b], d->uniq[b] * sizeof(uint64_t));
		u += d->uniq[b];
	}
	free(d);
	return u;
}

uint64_t *crapto1_darkside(uint32_t uid, uint32_t nt, uint32_t nrWire, const uint8_t ks3x[8], const uint64_t *in,
	int nin, int *n)
{
	*n = 0;
	stopped = 0;
	if (!ftab_init()) return NULL;
	if (!dsPre[0][1]) lin_build(dsPre, ds_pre), lin_build(dsPost, ds_post);
	KeySet set = {0};
	DsLoop *d = calloc(1, sizeof(DsLoop));
	uint64_t *keys = NULL;
	if (!d || (in && !keyset_init(&set, in, nin))) goto out;
	d->odd = prefix_ks(ks3x, 1, 0, 50);
	d->even = prefix_ks(ks3x, 0, 50, 100);
	// no_par: every (o, e, top) yields one post-nt state (the parity filter is skipped); roll it back
	// over uid ^ nt and read the key.
	size_t total = d->odd.n * d->even.n * 64;
	if (stopped || !(keys = malloc((in ? 0 : total) * sizeof(uint64_t) + sizeof(uint64_t)))) goto out;
	uint32_t z[2] = { 0, 0 };
	rollback_word(z, uid ^ nt, 0);
	d->kc = get_lfsr(z[0], z[1]); // uid ^ nt's share of the key
	d->nrWire = nrWire;
	d->in = &set;
	d->keys = in ? NULL : keys;
	each(DS_ITEMS, dsItem, d, 100, in ? 1000 : 800);
	size_t cnt = total;
	if (in) {
		cnt = 0;
		for (int c = 0; c < DS_ITEMS; c++) cnt += d->part[c].n;
		uint64_t *k = realloc(keys, (cnt + 1) * sizeof(uint64_t));
		if (k) {
			keys = k, cnt = 0;
			for (int c = 0; c < DS_ITEMS; c++) {
				memcpy(keys + cnt, d->part[c].a, d->part[c].n * sizeof(uint64_t));
				cnt += d->part[c].n;
			}
		} else {
			stopped = 1;
		}
	}
	size_t u = stopped ? 0 : sort_unique(keys, cnt);
	if (stopped) {
		free(keys);
		keys = NULL;
		goto out;
	}
	*n = u;
	uint64_t *k = realloc(keys, (u + 1) * sizeof(uint64_t));
	if (k) keys = k;
out:
	if (d) {
		for (int c = 0; c < DS_ITEMS; c++) free(d->part[c].a);
		free(d->odd.a);
		free(d->even.a);
	}
	free(d);
	free(set.idx);
	return keys;
}
