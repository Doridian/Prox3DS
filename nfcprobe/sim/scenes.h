#pragma once
// Hooks into the UI files' static state (hook_*.c include them), for scenes.c.
#include "../source/amiibo.h"
#include "../source/app.h"
#include "../source/desfire.h"
#include "../source/emv.h"
#include "../source/mfukeys.h"
#include "../source/oath.h"
#include "../source/iclass.h"
#include "../source/scard.h"

void simReset(void); // root menu, no dialog / toast / job
void simTag(const Card *c);
void simBusy(const char *title, bool cancellable, bool stopping);
void simBusyEnd(void);
void simBusyView(float (*view)(float x, float y, float w));

void simMfcCard(const Card *c, const MfMagic *m);
void simMfcGen4(void);
void simMfcRead(const MfDump *d, int got, const char *path);
void simMfcClone(int result, const char *why);
void simMfcMenu(void);
void simEdValue(int result, int dest, const u8 out[16]);
void simEdWriteBlock(int result, const char *how, const char *why);

void simMfuCard(const Card *c, const MfuDump *d, bool gtu);
void simMfuRead(const MfuDump *d, int result, const char *path);
void simMfuRestore(int result, int pages, const char *why);
void simMfuClone(const MfuDump *d, int result, const char *why);
void simMfuMenu(void);
void simNdef(const MfuDump *d, const Card *c);
void simNdefActions(void);
void simNdefUrl(const char *url);
void simAmiibo(const Amiibo *a, const u8 *tag, const Card *c, const char *name);
void simAmiiboActions(void);
void simAmiiboCopy(bool fresh, bool lock);
void simAmiiboDownloadFailed(void);
void simMfuPick(const Card *c, const MfuDump *d);
void simMfuReadKey(const MfuDump *d, int result, const char *path, const MfuKey *cand);

void simDfCard(const Card *c, const DfInfo *d, int result, const char *why);
void simDfMenu(void);
void simDfData(int app, int file);

void simScCard(const Card *c, const ScInfo *s, int result, const char *why);
void simScMenu(void);
void simScConsole(bool empty);
void simGp(const GpCard *g, bool ok, const char *why);
void simGpCaps(void);
void simOath(const OathInfo *o, int offset);
void simOathAdd(void);
void simEmv(const EmvCard *e, bool full);
void simIclass(const IcCard *c);
void simIclassMenu(void);

void simEmuMenu(void);
void simEmuRun(bool written); // the emulation busy box (written: a phone wrote a URL)
void simEmuDone(void);      // its end dialog
void simEmuMode(int which); // 0: UID-only busy box, 1: APDU log
void simEmuForm(void);      // the UID form, from a scanned NTAG
void simTearScan(void);    // write scan results, the EV1 test card's measured curve
void simTearCounter(void); // the counter reset busy box
