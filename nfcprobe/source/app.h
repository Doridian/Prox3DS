#pragma once
#include <3ds.h>

#include "mfc.h"
#include "mfu.h"
#include "ui.h"

// The app shell (app.c): a stack of screens, dialogs, the card job worker, and the root menu with a
// generic scan that identifies the card and hands it to its family (Proxmark style: "hf search", then
// "hf mf ..."). Families: MIFARE Classic (mfui.c, editor.c), Ultralight / NTAG (mfuui.c, mfuedit.c),
// DESFire / ISO14443-4 (dfui.c).

typedef struct {
	void (*show)(void); // whenever it becomes the top screen (entered, or returned to); may be NULL
	void (*input)(u32 kDown, u32 kRepeat);
	void (*draw)(void);
} Screen;
void appScreen(const Screen *s); // push (nothing if it is on top already)
void appBack(void);              // pop to the screen it was entered from

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
	void (*extra)(float y); // draws status lines under the menu; may be NULL
	UiList l;
} Menu;
void menuInput(Menu *m, u32 kDown, u32 kRepeat);
void menuDraw(Menu *m);
void menuLastCard(float y, const Card *c, const char *type); // a status line for the menu's extra()

// A card family: what the generic scan hands a card to.
typedef struct {
	const char *name, *help;
	bool (*match)(const Card *c); // from the activation (ATQA, SAK, UID)
	int (*probe)(void);           // in the job, card active: family detection. 1 ok, 0 lost, -1 chip error
	void (*show)(void);           // UI thread: push its card screen
	void (*menu)(void);           // UI thread: push its menu
} CardFamily;
extern const CardFamily mfcFamily, mfuFamily, dfFamily;

const char *cardTypeName(const Card *c); // best guess from ATQA / SAK, any ISO14443-A card
void uidHex(const Card *c, char *out, const char *sep); // out: up to 30 chars

// MIFARE Classic
void cloneStart(const MfDump *d, bool force); // write a dump onto the magic card on the reader
void editorOpen(const MfDump *d, const char *path);

// MIFARE Ultralight / NTAG
void mfuRestoreStart(const MfuDump *d); // write a dump's user pages onto the card on the reader
void mfuEditorOpen(const MfuDump *d, const char *path);
void mfuCloneStart(const MfuDump *d);                 // clone onto the Gen4 GTU on the reader
void mfuCloneAsk(const MfuDump *d, const char *name); // confirm, then mfuCloneStart
