// iClass key dictionaries: pm3's .dic files downloaded to the SD card, else the built-in copies
// (iclasskeys.c).

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "http.h"
#include "iclass.h"
#include "mfc.h"
#include "probe.h"

static char why[96];

const char *icDictWhy(void)
{
	return why;
}

typedef struct {
	u8 key[8];
	char label[40];
} DlKey;

// One list: "<16 hex> [# label]" lines, '#' comments, duplicates dropped like gen_iclasskeys.py.
// -> keys (malloc'd, NULL if none), n.
static DlKey *parse(const char *path, int *n)
{
	*n = 0;
	FILE *f = fopen(path, "r");
	if (!f) return NULL;
	DlKey *k = NULL;
	int cap = 0;
	char line[160];
	while (fgets(line, sizeof(line), f)) {
		char *p = line;
		while (*p == ' ' || *p == '\t') p++;
		int i;
		for (i = 0; i < 16 && isxdigit((unsigned char)p[i]); i++);
		if (i < 16) continue;
		u8 key[8];
		for (i = 0; i < 8; i++) {
			unsigned v;
			sscanf(p + 2 * i, "%2x", &v);
			key[i] = v;
		}
		p += 16;
		while (*p == ' ' || *p == '\t') p++;
		if (*p && *p != '#' && *p != '\r' && *p != '\n') continue;
		if (*p == '#') p++;
		while (*p == ' ' || *p == '\t') p++;
		p[strcspn(p, "\r\n")] = 0;
		bool dup = false;
		for (i = 0; i < *n && !dup; i++) dup = !memcmp(k[i].key, key, 8);
		if (dup) continue;
		if (*n == cap) {
			DlKey *b = realloc(k, (cap = cap ? 2 * cap : 64) * sizeof(*k));
			if (!b) break;
			k = b;
		}
		memcpy(k[*n].key, key, 8);
		snprintf(k[*n].label, sizeof(k[*n].label), "%s", p);
		(*n)++;
	}
	fclose(f);
	if (!*n) free(k), k = NULL;
	return k;
}

static IcDicts dicts;
static bool loaded;
static IcDictKey *dlDef; // the downloaded lists in the built-in layout
static u8 (*dlElite)[8];
static DlKey *dlDefKeys;

void icDictReload(void)
{
	free(dlDef), free(dlElite), free(dlDefKeys);
	dlDef = NULL, dlElite = NULL, dlDefKeys = NULL;
	dicts = (IcDicts){ icDefaultKeys, icNumDefaultKeys, icEliteKeys, icNumEliteKeys, false, false };
	int n;
	if ((dlDefKeys = parse(ICLASS_DICT_DEFAULT, &n)) && (dlDef = malloc(n * sizeof(*dlDef)))) {
		for (int i = 0; i < n; i++) memcpy(dlDef[i].key, dlDefKeys[i].key, 8), dlDef[i].label = dlDefKeys[i].label;
		dicts.def = dlDef, dicts.ndef = n, dicts.dlDef = true;
	}
	DlKey *e = parse(ICLASS_DICT_ELITE, &n);
	if (e && (dlElite = malloc(n * 8))) {
		for (int i = 0; i < n; i++) memcpy(dlElite[i], e[i].key, 8);
		dicts.elite = (const u8 (*)[8])dlElite, dicts.nelite = n, dicts.dlElite = true;
	}
	free(e);
	loaded = true;
	logp("iclass: dictionaries: %d default (%s), %d elite (%s)\n", dicts.ndef, dicts.dlDef ? "downloaded" : "built in",
		dicts.nelite, dicts.dlElite ? "downloaded" : "built in");
}

const IcDicts *icDicts(void)
{
	if (!loaded) icDictReload();
	return &dicts;
}

// One file: to path.new, kept only if it parses.
static int fetch(const char *name, const char *path)
{
	char url[160], tmp[96];
	snprintf(url, sizeof(url), ICLASS_DICT_URL "%s", name);
	snprintf(tmp, sizeof(tmp), "%s.new", path);
	if (!httpGetFile(url, tmp, 1 << 20, why, sizeof(why))) return 0;
	int n;
	DlKey *k = parse(tmp, &n);
	free(k);
	if (!n) {
		remove(tmp);
		snprintf(why, sizeof(why), "%s has no keys", name);
		return 0;
	}
	remove(path);
	rename(tmp, path);
	logp("iclass: %s, %d keys\n", name, n);
	return n;
}

int icDictDownload(void)
{
	mkdir(MF_DIR, 0777);
	mkdir(ICLASS_DIR, 0777);
	// A forged list only makes the key search try other keys (http.h: no certificate checks).
	return fetch("iclass_default_keys.dic", ICLASS_DICT_DEFAULT) && fetch("iclass_elite_keys.dic", ICLASS_DICT_ELITE);
}
