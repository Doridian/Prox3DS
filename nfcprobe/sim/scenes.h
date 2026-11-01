#pragma once
// Hooks into the UI files' static state (hook_*.c include them), for scenes.c.
#include "../source/app.h"
#include "../source/desfire.h"

void simReset(void); // root menu, no dialog / toast / job
void simTag(const Card *c);
void simBusy(const char *title, bool cancellable, bool stopping);
void simBusyEnd(void);

void simMfcCard(const Card *c, const MfMagic *m);
void simMfcGen4(void);
void simMfcRead(const MfDump *d, int got, const char *path);
void simMfcClone(int result, const char *why);
void simMfcMenu(void);
void simEdWriteBlock(int result, const char *how, const char *why);

void simMfuCard(const Card *c, const MfuDump *d, bool gtu);
void simMfuRead(const MfuDump *d, int result, const char *path);
void simMfuRestore(int result, int pages, const char *why);
void simMfuClone(const MfuDump *d, int result, const char *why);
void simMfuMenu(void);

void simDfCard(const Card *c, const DfInfo *d, int result, const char *why);
void simDfMenu(void);
void simDfData(int app, int file);
