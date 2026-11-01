#pragma once
#include <3ds.h>

// Number entry on a screen of its own: hex bytes (keys, passwords, file contents) or a decimal value.
// Buttons on the top screen (left / right: the digit, up / down: its value, X: clear, A: done, B:
// cancel), a keypad on the bottom screen that types and moves on. done runs after the entry screen
// is gone, so it may open the next one.

#define ENTRY_MAX 256 // bytes

void entryHex(const char *title, const char *what, u32 len, const u8 *init, void (*done)(const u8 *b, u32 len));
void entryDec(const char *title, const char *what, s64 min, s64 max, s64 init, void (*done)(s64 v));
