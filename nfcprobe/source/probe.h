#pragma once
#include <3ds.h>

// Shared between the UI's card jobs (app.c) and the network server (netsrv.c).

void logp(const char *fmt, ...);

// Progress of the running card job, for the UI (the worker writes it, the UI only shows it). An op
// is one step the user waits on (a dictionary sweep, a nested attack); done/total drive its bar.
typedef struct {
	char op[64];
	u32 done, total;  // total 0 = no bar
	u64 start, opStart; // osGetTime() of the job and of the op
	u32 eta;          // ms left at etaAt (0 = unknown)
	u64 etaAt;
} Progress;
extern Progress prog;
void progJob(void);                // a new job: all cleared
void progOp(const char *fmt, ...); // a new op: no steps yet, its clock restarted
void progStep(u32 done, u32 total); // ETA from the op's rate so far
void progEta(u32 done, u32 total, u32 etaMs); // ETA known by the caller
u32 progLeft(void);                // ms left now by the last ETA, 0 = unknown
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
#ifndef NFCPROBE_RELEASE
extern char netAddr[32]; // "ip:port" while the server listens, else empty
// Debug: buttons a network client pressed, taken by the UI loop.
extern volatile u32 netKeys;
void netStart(void);
void netStop(void);
#else // the release build has no network server (netsrv.c isn't built)
#define netAddr ""
#define netKeys 0
static inline void netStart(void) {}
static inline void netStop(void) {}
#endif
