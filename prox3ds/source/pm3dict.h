#pragma once
#include <3ds.h>

// pm3's key dictionaries (client/dictionaries/*.dic) downloaded to the SD card on request: MIFARE
// Classic (mfc.h), DESFire (desfire.h) and Ultralight C (mfukeys.h) read them besides their own lists.
// iClass has its own download (iclassdict.c).

#define PM3_CLIENT_URL "https://cdn.jsdelivr.net/gh/RfidResearchGroup/proxmark3@master/client/" // + dictionaries/, resources/

// Keys in a .dic: lines starting with a hex key of a length in lens (bit n = n digits), then a space,
// '#' or the line's end. -1 = no file.
int pm3DictCount(const char *path, u64 lens);
// A job that downloads dictionaries/<name> to path (directories made, through path.new: an old copy
// stays unless the new one has keys), then done() on the UI thread, then a toast or the error.
void pm3DictDownload(const char *title, const char *name, const char *path, u64 lens, void (*done)(void));
