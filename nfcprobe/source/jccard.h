#pragma once
#include "jcvm.h"

// A Java Card around the VM (issue #19): installed applets, SELECT, an APDU through process() into a
// response, transient memory on reset / deselect, the heap saved to the SD card. The emulation hands it
// APDUs (jcCardApdu is an EmuApdu); the Python prototype is tools/jcvm/card.py.

#define JC_DIR   "sdmc:/nfcprobe/jc"
#define JC_STATE JC_DIR "/card.bin"
#define JC_BUF   261  // APDU buffer: header + 255 bytes + Le, as JCOP
#define JC_EXT   2048 // the longest command / response (extended length, applets with ExtendedLength)

typedef struct {
	u8 aid[16], aidLen;
	s8 pkg;
	u16 obj, aidObj; // the applet instance, its AID object
} JcApplet;

typedef struct {
	JcVm vm; // first: jcCardInit clears what follows it
	JcApplet applets[JC_APPLETS];
	u8 napplets;
	s8 selected, context; // applet indices, -1 = none
	bool selecting, reselecting;
	const u8 *instAid; // while install() runs: the instance AID register() takes
	u8 instAidLen;
	s8 installPkg;
	// the APDU being processed
	u16 apdu, buf; // the APDU object and its buffer (system-owned)
	u8 cmd[JC_EXT];
	u16 cmdLen, lc, le, received, cdata; // cdata: 5, or 7 (extended)
	u8 state; // APDU.STATE_*
	bool ext; // extended length
	u8 out[JC_EXT];
	u16 outLen, outExpected;
	bool dirty; // persistent memory may have changed since the last save
	u32 apdus;
} JcCard;

extern JcCard jcCard;

void jcCardInit(void); // an empty card: the API, no packages
// Loads a CAP file and installs every applet in it under its default AID. The package index, -1 = failed
// (jcCard.vm.why).
int jcCardInstallCap(const char *path);
int jcCardInstall(int pkg, const u8 *appletAid, u8 appletAidLen, const u8 *instAid, u8 instAidLen);
// The package and its applets (objects stay until the card is restored); false: another package imports it
// (vm.why).
bool jcCardDeletePkg(int pkg);
void jcCardReset(void);       // a new session: nothing selected, transient memory cleared
u32 jcCardApdu(const u8 *cmd, u32 len, u8 *resp, u32 max); // EmuApdu; cmd NULL = a new session

// The card as files: JC_STATE (packages by CAP path, heap, statics, applets). false = no / broken file.
bool jcCardSave(void);
bool jcCardRestore(void);
