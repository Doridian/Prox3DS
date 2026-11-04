#pragma once
#include <3ds.h>

#include "gp.h"
#include "iso7816.h"
#include "mfc.h"

// Any ISO14443-4 smart card (JavaCards, YubiKeys, ...): the ATS, the GlobalPlatform security domain's
// card data, and which applets answer SELECT, from a list of known AIDs (scApplets[] in scard.c) and the
// user's own (SC_AIDS). An applet a tool knows has open set: the smart card screen offers it.
//
// A new applet tool: its screen in its own file (oathui.c is one), its open function in app.h, and an
// entry in scApplets[].

#define SC_DIR  APP_DIR "/smartcard"
#define SC_AIDS SC_DIR "/aids.txt" // more applets to look for: "<AID hex> <name>" per line, '#' comments
#define SC_MAX_FOUND 24

typedef struct {
	const char *name;
	const char *aid;  // hex; SELECT takes it as a prefix too (the first applet that starts with it answers)
	const char *help;
	void (*open)(void); // its tool (UI thread, the card on the reader), NULL = none yet
} ScApplet;
extern const ScApplet scApplets[];
extern const int scNumApplets;

typedef struct {
	char name[40];
	u8 aidLen, aid[16];
	u16 sw;
	u8 fciLen, fci[128]; // SELECT's answer
	const ScApplet *app; // NULL = one from SC_AIDS
} ScFound;

typedef struct {
	u8 atsLen, ats[32];
	bool hasGp;          // a security domain answered: its card data in gp (not listed: that takes keys)
	GpCard gp;
	int nfound;
	ScFound found[SC_MAX_FOUND];
} ScInfo;

const char *scInfoWhy(void);
// In a job, card active: ISO-DEP, the security domain, every known AID. 1 = done, 0 = no ISO-DEP
// (scInfoWhy), -1 = monitor error.
int scReadInfo(ScInfo *s);
bool scSaveInfo(const ScInfo *s, const Card *c, char *path, u32 pathMax); // SC_DIR/<UID>.txt, never overwrites
const ScApplet *scAppletFor(const u8 *aid, u32 len); // the known applet an AID starts with, NULL = none
