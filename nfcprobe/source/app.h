#pragma once
#include <3ds.h>

#include "desfire.h"
#include "mfc.h"
#include "mfu.h"
#include "ui.h"

// The app shell (app.c): a stack of screens, dialogs, the card job worker, and the root menu with a
// generic scan that identifies the card and hands it to its family (Proxmark style: "hf search", then
// "hf mf ..."). Families: MIFARE Classic (mfui.c, editor.c), Ultralight / NTAG (mfuui.c, mfuedit.c),
// DESFire (dfui.c), any other ISO14443-4 smart card (scui.c: applets, APDUs, GlobalPlatform in gpui.c,
// applet tools such as YubiKey OATH in oathui.c).

typedef struct {
	void (*show)(void); // whenever it becomes the top screen (entered, or returned to); may be NULL
	void (*input)(u32 kDown, u32 kRepeat);
	void (*draw)(void);
	void (*bottom)(void); // its own bottom screen (uiButton...); NULL = the default: the footer's hints
	                      // as touch buttons, a D-pad and the log
} Screen;
// From a bottom screen: keys to press next frame, as if from the buttons.
void appPress(u32 keys);
void appScreen(const Screen *s); // push (nothing if it is on top already)
void appBack(void);              // pop to the screen it was entered from
const Screen *appTop(void);      // the screen on top

void appRun(void);       // UI loop, returns on exit
void appShutdown(void);  // cancels a running job and waits for it a while

// Dialogs on top of the current screen (one at a time).
void msgBox(const char *title, const char *fmt, ...);
void confirm(const char *title, void (*yes)(void), const char *fmt, ...); // A runs yes, B drops it
typedef struct {
	const char *label;
	void (*fn)(void);
} MenuItem;
void popup(const char *title, const MenuItem *items, int n);
void toast(const char *fmt, ...); // a short note at the bottom of the screen

// Runs run() on the worker with hwLock held, then done() on the UI thread. A cancellable job gets B
// for mfCancel.
void jobStart(const char *title, void (*run)(void), void (*done)(void), bool cancellable);
// The same with a bigger busy box: view draws under the progress bar (inner x, y, width) and returns
// the height it took; the log gets the rest.
void jobStartView(const char *title, void (*run)(void), void (*done)(void), bool cancellable,
	float (*view)(float x, float y, float w));
// The busy box's hint next to "B stop" for the next job started (default: keep the card on the bottom screen).
void jobNextHint(const char *hint);
void fmtDuration(char *out, u32 ms); // "m:ss"
bool cardWait(void); // in a job: take the chip, poll until a card is activated (or cancelled)

// A menu screen: entries on the left, the selected one's help on the right, status lines below.
typedef struct {
	const char *label, *help;
	void (*fn)(void);
} MenuEntry;
typedef struct {
	const char *title;
	const MenuEntry *entries;
	int n;
	void (*extra)(float x, float y, float w); // draws status lines in that area (under the menu); may be NULL
	UiList l;
} Menu;
void menuInput(Menu *m, u32 kDown, u32 kRepeat);
void menuDraw(Menu *m);
void menuLastCard(float x, float y, float w, const Card *c, const char *type); // a status line for the menu's extra()

// A form screen: a field per row (A edits it), the last row runs it.
typedef struct {
	const char *label;
	void (*value)(char *out); // its current value, in words (up to 63 chars)
	void (*edit)(void);
} Field;
// count: fields shown (they may depend on each other); run goes after the form is gone.
void formOpen(const char *title, const char *go, const char *help, const Field *f, int (*count)(void), void (*run)(void));

// A card family: what the generic scan hands a card to.
typedef struct {
	const char *name, *help;
	bool (*match)(const Card *c); // from the activation (ATQA, SAK, UID)
	int (*probe)(void);           // in the job, card active: family detection. 1 ok, 0 lost, -1 chip error,
	                              // FAMILY_PASS: not one after all, the next family that matches gets it
	void (*show)(void);           // UI thread: push its card screen
	void (*menu)(void);           // UI thread: push its menu
} CardFamily;
#define FAMILY_PASS 2
extern const CardFamily mfcFamily, mfuFamily, dfFamily, scFamily;

const char *cardTypeName(const Card *c); // best guess from ATQA / SAK, any ISO14443-A card
void uidHex(const Card *c, char *out, const char *sep); // out: up to 30 chars

// Smart cards (scard.h): applet tools, for the card on the reader
void gpOpenTool(void);   // GlobalPlatform (gpui.c)
void oathOpenTool(void); // YubiKey OATH (oathui.c)
u64 unixNow(void);       // the console clock as UTC, with the OATH tool's clock setting (oathui.c)
void emvOpenTool(void);  // EMV payment cards (emvui.c)
void apduConsole(void);  // raw APDUs (scui.c)
u32 jobCount(void);      // jobs started so far: tells a tool whether another job touched the card since

// Card emulation (emuui.c)
void emuOpenMenu(void);
void emuStartNdef(const u8 *msg, u32 len);                // a Type 4 tag with this message
void emuStartUid(const Card *c);                          // its UID, ATQA and SAK
void emuStartMfuNdef(const MfuDump *d, const char *name); // a Type 4 tag with the dump's NDEF message
void emuStartMfu(const MfuDump *d, const char *name);     // the dump's card itself (chip-answered)
void emuStartMfc(const MfDump *d, const char *name);      // the same for Classic Mini / 1K / 2K / 4K
void emuStartDf(const DfInfo *d, const char *name);       // a saved DESFire info file, answered by the host

// HID iClass / PicoPass (iclassui.c)
void iclassOpenMenu(void);

// MIFARE Classic
void cloneStart(const MfDump *d, bool force); // write a dump onto the magic card on the reader
void editorOpen(const MfDump *d, const char *path);

// MIFARE Ultralight / NTAG
void mfuRestoreStart(const MfuDump *d); // write a dump's user pages onto the card on the reader
void mfuEditorOpen(const MfuDump *d, const char *path);
void mfuCloneStart(const MfuDump *d);                 // clone onto the Gen4 GTU on the reader
void mfuCloneAsk(const MfuDump *d, const char *name); // confirm, then mfuCloneStart
void mfuFilesChanged(void); // a dump was saved behind the saved dumps list: rescan it
void mfFilesChanged(void);  // the same for Classic
void mfuFilesWarm(void);    // scan the saved dumps list once, if nothing has yet (app start, background)
void mfFilesWarm(void);
int mfuDumpActions(MenuItem *items, const MfuDump *d, const char *name); // a dump's card actions (X menus)
int mfDumpActions(MenuItem *items, const MfDump *d, const char *name);
void ndefOpenMfu(void); // read the card on the reader, then its NDEF screen (ndefui.c)
void mfuTearMenu(void);  // tear-off: write scan, EV1 counter reset (mfutear.c)
void amiiboOpenCard(void); // read the NTAG215 on the reader, then the Amiibo screen (amiiboui.c)
void amiiboOpenDump(const MfuDump *d, const char *name); // the same for a saved dump
void amiiboOpenMenu(void); // read, new figures from the figure list, its download
