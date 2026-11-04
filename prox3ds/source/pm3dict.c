// pm3's key dictionaries, downloaded (see pm3dict.h).

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include "app.h"
#include "http.h"
#include "mfc.h"
#include "pm3dict.h"
#include "probe.h"

int pm3DictCount(const char *path, u64 lens)
{
	FILE *f = fopen(path, "r");
	if (!f) return -1;
	int n = 0;
	char line[160];
	while (fgets(line, sizeof(line), f)) {
		char *p = line;
		while (*p == ' ' || *p == '\t') p++;
		int d = 0;
		while (isxdigit((unsigned char)p[d])) d++;
		if (d < 64 && (lens >> d & 1) && (!p[d] || strchr(" \t#\r\n", p[d]))) n++;
	}
	fclose(f);
	return n;
}

static struct {
	const char *title, *name, *path;
	u64 lens;
	void (*done)(void);
	int n;
	char why[96];
} dl;

static void run(void)
{
	char url[160], tmp[128], dir[128];
	snprintf(url, sizeof(url), PM3_CLIENT_URL "dictionaries/%s", dl.name);
	snprintf(tmp, sizeof(tmp), "%s.new", dl.path);
	mkdir(APP_DIR, 0777);
	snprintf(dir, sizeof(dir), "%s", dl.path);
	*strrchr(dir, '/') = 0;
	mkdir(dir, 0777);
	// A forged list only makes the key search try other keys (http.h: no certificate checks).
	dl.n = 0;
	if (!httpGetFile(url, tmp, 1 << 20, dl.why, sizeof(dl.why))) return;
	if ((dl.n = pm3DictCount(tmp, dl.lens)) <= 0) {
		dl.n = 0;
		remove(tmp);
		snprintf(dl.why, sizeof(dl.why), "%s has no keys", dl.name);
		return;
	}
	remove(dl.path);
	rename(tmp, dl.path);
	logp("%s: %d keys\n", dl.name, dl.n);
}

static void finish(void)
{
	if (dl.done) dl.done();
	if (!dl.n) msgBox(dl.title, "Download failed: %s\n" PM3_CLIENT_URL "dictionaries/%s", dl.why, dl.name);
	else toast("%s: %d keys", dl.name, dl.n);
}

void pm3DictDownload(const char *title, const char *name, const char *path, u64 lens, void (*done)(void))
{
	dl.title = title, dl.name = name, dl.path = path, dl.lens = lens, dl.done = done;
	jobStart(title, run, finish, false);
}
