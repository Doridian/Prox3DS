#pragma once
#include <3ds.h>

// Shared between the UI's card jobs (app.c) and the network server (netsrv.c).

void logp(const char *fmt, ...);
u32 irqLevel(void);
u32 nciRecv(u8 *pkt, u32 maxLen, int tries, bool verbose);
void stepTerminate(void);
bool stepOpen(int tries);
void chipTakeover(void);
void chipRelease(void);
Result chipPowerUp(void);
bool chipEnsure(void);   // takeover unless we own the chip already
void chipProbe(void);   // reset / init / patch version from a fresh takeover, chip given back
bool spdDownload(const u8 *ncd, u32 size, bool verbose);

extern Handle irqEvent;   // nonzero while we own the chip
extern LightLock hwLock;

#define NET_PORT 8020
// Self-update (netsrv OP_UPDATE*): the running .3dsx, and the request to exit and relaunch it.
extern char appPath[256];
extern volatile bool restartRequested;
extern char netAddr[32]; // "ip:port" while the server listens, else empty
// Debug: buttons a network client pressed, taken by the UI loop.
extern volatile u32 netKeys;
void netStart(void);
void netStop(void);
