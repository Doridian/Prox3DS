#pragma once
#include <3ds.h>

#include "mfc.h"

// The app's screens, dialogs and the card job worker (app.c), and the dump editor (editor.c).

enum { SCR_MENU, SCR_CARD, SCR_GEN4, SCR_FILES, SCR_EDIT, SCR_LOG };
void appScreen(int scr); // remembers where it came from
void appBack(void);      // to the screen this one was entered from
void toast(const char *fmt, ...); // a short note at the bottom of the screen

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

// Runs run() on the worker with the chip ours and hwLock held, then done() on the UI thread.
// A cancellable job gets B for mfCancel.
void jobStart(const char *title, void (*run)(void), void (*done)(void), bool cancellable);
bool cardWait(void); // in a job: poll until a card is activated (or cancelled); logs the card
void cloneStart(const MfDump *d, bool force); // write a dump onto the magic card on the reader

void editorOpen(const MfDump *d, const char *path);
void editorInput(u32 kDown, u32 kRepeat);
void editorDraw(void);

const char *cardTypeName(u8 sak); // from the SAK
