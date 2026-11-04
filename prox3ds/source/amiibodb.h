#pragma once
#include <3ds.h>

#include "mfc.h"

// The Amiibo figure list: AmiiboAPI's database (N3evin/AmiiboAPI, database/amiibo.json) on the SD card,
// fetched by amiiboDbDownload (amiibo.c). Names for the 8-byte model IDs (character, variant, figure
// type, model number, series, 02), and the list new figures are made from.
#define AMIIBO_DB     APP_DIR "/amiibo.json"
// Through jsDelivr: GitHub (raw.githubusercontent.com) only does AES-GCM, which the 3DS SSL module lacks
// (D8A0A03C); jsDelivr still takes AES-CBC.
#define AMIIBO_DB_URL "https://cdn.jsdelivr.net/gh/N3evin/AmiiboAPI@master/database/amiibo.json"

typedef struct {
	u8 id[8];
	const char *name;
	const char *series; // the amiibo series ("Super Smash Bros."), "" when the list has none
} AmiiboDbEnt;

// Loads path (AMIIBO_DB if NULL) in place of the list loaded so far, which stays if it fails. The
// number of figures; 0 = no list (amiiboDbWhy), and the old one kept.
int amiiboDbLoad(const char *path);
const char *amiiboDbWhy(void);

int amiiboDbCount(void);
const AmiiboDbEnt *amiiboDbAt(int i); // sorted by series, then name
const AmiiboDbEnt *amiiboDbFind(const u8 id[8]);
// The ID's parts by name (NULL: not in the list)
const char *amiiboDbCharacter(const u8 id[8]); // bytes 0-1
const char *amiiboDbGame(const u8 id[8]);      // the game series: the first 12 bits
const char *amiiboDbType(const u8 id[8]);      // byte 3
const char *amiiboDbSeries(const u8 id[8]);    // byte 6
