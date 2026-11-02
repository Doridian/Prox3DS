// The Amiibo figure list, see amiibodb.h. amiibo.json is parsed in place (strings unescaped and
// NUL-terminated in the file's buffer), which the entries then point into.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "amiibodb.h"

typedef struct {
	u32 key;
	const char *name;
} Named;

typedef struct {
	Named *v;
	int n, cap;
} NamedList;

typedef struct {
	char *buf;
	AmiiboDbEnt *ents;
	int n, cap;
	NamedList chars, games, types, series; // "characters", "game_series", "types", "amiibo_series"
} Db;

static Db db, nd; // the list loaded, the one being parsed
static char why[96];
static char *p, *end;

const char *amiiboDbWhy(void)
{
	return why;
}

static void dbFree(Db *d)
{
	free(d->buf);
	free(d->ents);
	free(d->chars.v), free(d->games.v), free(d->types.v), free(d->series.v);
	memset(d, 0, sizeof(*d));
}

// --- JSON, just enough for amiibo.json ---

static void ws(void)
{
	while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) p++;
}

static bool eat(char c)
{
	ws();
	if (p < end && *p == c) {
		p++;
		return true;
	}
	return false;
}

static int hexval(char c)
{
	return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
}

// A string: unescaped in place (\uXXXX as UTF-8: never longer than the escape) and NUL-terminated.
static char *str(void)
{
	if (!eat('"')) return NULL;
	char *s = p, *o = p;
	while (p < end && *p != '"') {
		char c = *p++;
		if (c != '\\' || p >= end) {
			*o++ = c;
			continue;
		}
		c = *p++;
		if (c != 'u') {
			*o++ = c == 'n' ? '\n' : c == 't' || c == 'r' || c == 'b' || c == 'f' ? ' ' : c;
			continue;
		}
		u32 u = 0;
		for (int i = 0; i < 4; i++) {
			int h = p < end ? hexval(*p) : -1;
			if (h < 0) return NULL;
			u = u << 4 | h, p++;
		}
		if (u >= 0xD800 && u < 0xE000) *o++ = '?'; // surrogates: no emoji in the system font anyway
		else if (u < 0x80) *o++ = u;
		else if (u < 0x800) *o++ = 0xC0 | u >> 6, *o++ = 0x80 | (u & 0x3F);
		else *o++ = 0xE0 | u >> 12, *o++ = 0x80 | (u >> 6 & 0x3F), *o++ = 0x80 | (u & 0x3F);
	}
	if (p >= end) return NULL;
	p++;
	*o = 0;
	return s;
}

static bool skip(void)
{
	ws();
	if (p >= end) return false;
	if (*p == '"') return str() != NULL;
	if (*p == '{' || *p == '[') {
		char close = *p++ == '{' ? '}' : ']';
		if (eat(close)) return true;
		do {
			if (close == '}' && (!str() || !eat(':'))) return false;
			if (!skip()) return false;
		} while (eat(','));
		return eat(close);
	}
	char *s = p;
	while (p < end && !strchr(",}] \t\r\n", *p)) p++; // number, true, false, null
	return p > s;
}

// An object's members: fn gets each key with p at its value, which it has to take.
static bool members(bool (*fn)(const char *key, void *ctx), void *ctx)
{
	if (!eat('{')) return false;
	if (eat('}')) return true;
	do {
		const char *k = str();
		if (!k || !eat(':') || !fn(k, ctx)) return false;
	} while (eat(','));
	return eat('}');
}

// "0x..." -> its value; digits: how many hex digits it had
static bool hexKey(const char *k, u64 *v, int *digits)
{
	if (k[0] != '0' || (k[1] != 'x' && k[1] != 'X')) return false;
	*v = 0;
	int n = 0;
	for (k += 2; *k; k++, n++) {
		int h = hexval(*k);
		if (h < 0 || n == 16) return false;
		*v = *v << 4 | h;
	}
	*digits = n;
	return n > 0;
}

static bool grow(void **v, int n, int *cap, u32 size)
{
	if (n < *cap) return true;
	int c = *cap ? *cap * 2 : 64;
	void *q = realloc(*v, c * size);
	if (!q) return false;
	*v = q, *cap = c;
	return true;
}

static bool namedMember(const char *k, void *ctx)
{
	NamedList *l = ctx;
	u64 v;
	int digits;
	const char *name = str();
	if (!name) return false;
	if (!hexKey(k, &v, &digits)) return true;
	if (!grow((void **)&l->v, l->n, &l->cap, sizeof(Named))) return false;
	l->v[l->n++] = (Named){ v, name };
	return true;
}

static bool figureField(const char *k, void *ctx)
{
	if (strcmp(k, "name")) return skip();
	return (*(const char **)ctx = str()) != NULL;
}

static bool figureMember(const char *k, void *ctx)
{
	const char *name = NULL;
	u64 v;
	int digits;
	if (!members(figureField, &name)) return false;
	if (!name || !hexKey(k, &v, &digits) || digits != 16) return true;
	if (!grow((void **)&nd.ents, nd.n, &nd.cap, sizeof(AmiiboDbEnt))) return false;
	AmiiboDbEnt *e = &nd.ents[nd.n++];
	for (int i = 0; i < 8; i++) e->id[i] = v >> (56 - 8 * i);
	e->name = name;
	e->series = "";
	return true;
}

static bool topMember(const char *k, void *ctx)
{
	if (!strcmp(k, "amiibos")) return members(figureMember, NULL);
	NamedList *l = !strcmp(k, "characters") ? &nd.chars : !strcmp(k, "game_series") ? &nd.games
		: !strcmp(k, "types") ? &nd.types : !strcmp(k, "amiibo_series") ? &nd.series : NULL;
	return l ? members(namedMember, l) : skip();
}

static const char *lookup(const NamedList *l, u32 key)
{
	for (int i = 0; i < l->n; i++)
		if (l->v[i].key == key) return l->v[i].name;
	return NULL;
}

static int entCmp(const void *a, const void *b)
{
	const AmiiboDbEnt *x = a, *y = b;
	if (!*x->series != !*y->series) return *x->series ? -1 : 1; // no series: last
	int c = strcasecmp(x->series, y->series);
	return c ? c : strcasecmp(x->name, y->name);
}

int amiiboDbLoad(const char *path)
{
	if (!path) path = AMIIBO_DB;
	memset(&nd, 0, sizeof(nd));
	FILE *f = fopen(path, "rb");
	if (!f) {
		snprintf(why, sizeof(why), "no %s", path);
		return 0;
	}
	fseek(f, 0, SEEK_END);
	long len = ftell(f);
	fseek(f, 0, SEEK_SET);
	nd.buf = len > 0 && len < (8 << 20) ? malloc(len + 1) : NULL;
	bool ok = nd.buf && fread(nd.buf, 1, len, f) == (size_t)len;
	fclose(f);
	if (!ok) {
		dbFree(&nd);
		snprintf(why, sizeof(why), "can't read %s (%ld bytes)", path, len);
		return 0;
	}
	nd.buf[len] = 0;
	p = nd.buf, end = nd.buf + len;
	if (!members(topMember, NULL)) {
		snprintf(why, sizeof(why), "%s: bad JSON at byte %ld", path, (long)(p - nd.buf));
		dbFree(&nd);
		return 0;
	}
	if (!nd.n) {
		snprintf(why, sizeof(why), "%s: no \"amiibos\" in it", path);
		dbFree(&nd);
		return 0;
	}
	for (int i = 0; i < nd.n; i++) {
		const char *s = lookup(&nd.series, nd.ents[i].id[6]);
		if (s) nd.ents[i].series = s;
	}
	qsort(nd.ents, nd.n, sizeof(AmiiboDbEnt), entCmp);
	dbFree(&db);
	db = nd;
	memset(&nd, 0, sizeof(nd));
	return db.n;
}

int amiiboDbCount(void)
{
	return db.n;
}

const AmiiboDbEnt *amiiboDbAt(int i)
{
	return i >= 0 && i < db.n ? &db.ents[i] : NULL;
}

const AmiiboDbEnt *amiiboDbFind(const u8 id[8])
{
	for (int i = 0; i < db.n; i++)
		if (!memcmp(db.ents[i].id, id, 8)) return &db.ents[i];
	return NULL;
}

const char *amiiboDbCharacter(const u8 id[8])
{
	return lookup(&db.chars, id[0] << 8 | id[1]);
}

const char *amiiboDbGame(const u8 id[8])
{
	return lookup(&db.games, id[0] << 4 | id[1] >> 4);
}

const char *amiiboDbType(const u8 id[8])
{
	return lookup(&db.types, id[3]);
}

const char *amiiboDbSeries(const u8 id[8])
{
	return lookup(&db.series, id[6]);
}
