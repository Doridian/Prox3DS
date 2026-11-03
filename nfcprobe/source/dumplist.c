#ifndef __3DS__
#include <dirent.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <3ds.h>

#include "dumplist.h"

static DumpDir *dirs[4]; // scanned at least once: dumpForget looks there
static int ndirs;
static LightLock regLock;

static bool isDump(const char *name)
{
	int len = strlen(name);
	return len >= 5 && len < 64 && !strcasecmp(name + len - 4, ".bin");
}

static void add(DumpEnt *out, int *n, const char *name, u32 size)
{
	if (*n >= DUMP_MAX || !isDump(name)) return;
	DumpEnt *e = &out[(*n)++];
	snprintf(e->name, sizeof(e->name), "%s", name);
	e->size = size;
	e->mtime = 0;
	e->info = 0;
}

// Names and sizes, without a stat per file.
static int readDir(const char *dir, DumpEnt *out)
{
	int n = 0;
#ifdef __3DS__
	FS_Archive a;
	Handle h;
	if (R_FAILED(FSUSER_OpenArchive(&a, ARCHIVE_SDMC, fsMakePath(PATH_EMPTY, "")))) return 0;
	if (R_SUCCEEDED(FSUSER_OpenDirectory(&h, a, fsMakePath(PATH_ASCII, dir + 5)))) { // past "sdmc:"
		static FS_DirectoryEntry e[16];
		u32 got;
		while (n < DUMP_MAX && R_SUCCEEDED(FSDIR_Read(h, &got, 16, e)) && got)
			for (u32 i = 0; i < got; i++) {
				char name[256];
				ssize_t len = utf16_to_utf8((u8 *)name, e[i].name, sizeof(name) - 1);
				if (len < 0 || e[i].attributes & FS_ATTRIBUTE_DIRECTORY) continue;
				name[len] = 0;
				add(out, &n, name, e[i].fileSize);
			}
		FSDIR_Close(h);
	}
	FSUSER_CloseArchive(a);
#else
	DIR *dp = opendir(dir);
	struct dirent *e;
	while (dp && (e = readdir(dp))) {
		char path[320];
		struct stat st;
		snprintf(path, sizeof(path), "%s/%s", dir, e->d_name);
		if (!stat(path, &st) && S_ISREG(st.st_mode)) add(out, &n, e->d_name, st.st_size);
	}
	if (dp) closedir(dp);
#endif
	return n;
}

static int newestFirst(const void *a, const void *b)
{
	const DumpEnt *x = a, *y = b;
	return x->mtime < y->mtime ? 1 : x->mtime > y->mtime ? -1 : strcmp(x->name, y->name);
}

void dumpInit(void)
{
	LightLock_Init(&regLock);
}

void dumpScan(DumpDir *d)
{
	LightLock_Lock(&regLock);
	if (!d->ready) {
		LightLock_Init(&d->lock);
		d->ready = true;
		if (ndirs < 4) dirs[ndirs++] = d;
	}
	LightLock_Unlock(&regLock);

	LightLock_Lock(&d->lock);
	int n = readDir(d->dir, d->scratch);
	for (int i = 0; i < n; i++) {
		DumpEnt *e = &d->scratch[i];
		for (int k = 0; k < d->n; k++)
			if (d->ent[k].mtime && d->ent[k].size == e->size && !strcmp(d->ent[k].name, e->name)) {
				e->mtime = d->ent[k].mtime;
				e->info = d->ent[k].info;
				break;
			}
		if (e->mtime) continue;
		char path[160];
		snprintf(path, sizeof(path), "%s/%s", d->dir, e->name);
		archive_getmtime(path, &e->mtime);
		if (!e->mtime) e->mtime = 1; // known, just undated: sorts last, isn't asked again
		e->info = d->info ? d->info(path, e->size) : 0;
	}
	qsort(d->scratch, n, sizeof(*d->scratch), newestFirst);
	memcpy(d->ent, d->scratch, n * sizeof(*d->ent));
	d->n = n;
	d->scanned = true;
	LightLock_Unlock(&d->lock);
}

void dumpForget(const char *path)
{
	const char *slash = strrchr(path, '/');
	if (!slash) return;
	LightLock_Lock(&regLock);
	for (int i = 0; i < ndirs; i++) {
		DumpDir *d = dirs[i];
		if (strncmp(path, d->dir, slash - path) || d->dir[slash - path]) continue;
		LightLock_Lock(&d->lock);
		for (int k = 0; k < d->n; k++)
			if (!strcmp(d->ent[k].name, slash + 1)) d->ent[k].mtime = 0;
		LightLock_Unlock(&d->lock);
	}
	LightLock_Unlock(&regLock);
}
