#pragma once
#include <3ds.h>

// Shared between the button jobs (main.c) and the network server (netsrv.c).

void logp(const char *fmt, ...);
u32 irqLevel(void);
u32 nciRecv(u8 *pkt, u32 maxLen, int tries, bool verbose);
void stepTerminate(void);
bool stepOpen(int tries);
void chipTakeover(void);
void chipRelease(void);
Result chipPowerUp(void);
bool chipEnsure(void);   // takeover unless we own the chip already
bool spdDownload(const u8 *ncd, u32 size, bool verbose);

extern Handle irqEvent;   // nonzero while we own the chip
extern LightLock hwLock;

#define NET_PORT 8020
// Self-update (netsrv OP_UPDATE*): the running .3dsx, and the request to exit and relaunch it.
extern char appPath[256];
extern volatile bool restartRequested;
void netStart(void);
void netStop(void);
