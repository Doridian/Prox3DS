#pragma once
#include <stdbool.h>

// Work spread over the CPU cores the app may use, for the crapto1 recoveries: the caller's core plus
// helper threads on the others (New 3DS: core 2, and core 1 within the app's CPU time limit).

// Runs fn(arg, i) for every i in [0, n) on the caller and the helpers; returns when all are done.
// Items are handed out one at a time, so uneven ones balance. Any order, any thread.
void parFor(int n, void (*fn)(void *arg, int i), void *arg);
// True on parFor's caller (and outside parFor), false on a helper: only the caller may call back
// into the UI.
bool parMain(void);
