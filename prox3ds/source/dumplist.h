#pragma once
// Saved dump directories (Classic, Ultralight / NTAG; DESFire info .txt): the .bin files newest first, with size, date and a
// value of the family's (Ultralight: pages). On the SD card a stat and a date cost ~20 ms each per file, so
// a scan reads the directory in batches (names and sizes) and only asks the per-file calls for files it
// hasn't seen with that size; the app warms every directory in the background at start.
#include <3ds.h>

#define DUMP_MAX 200

typedef struct {
	char name[64];
	u32 size;
	u64 mtime; // 0: unknown
	int info;  // DumpDir.info's answer
} DumpEnt;

typedef struct {
	const char *dir;                         // "sdmc:/..."
	const char *ext;                         // NULL: ".bin"
	int (*info)(const char *path, u32 size); // NULL: info 0
	DumpEnt *ent; // the listing, newest first; allocated on the first scan (inline, the initialized statics
	int n;        // would carry ~35 KB of zeros each in .data)
	DumpEnt *scratch;
	LightLock lock;
	bool ready, scanned;
} DumpDir;

void dumpInit(void); // once, before any scan
void dumpScan(DumpDir *d);
void dumpForget(const char *path); // the file at path was rewritten: its cached date and info are stale
