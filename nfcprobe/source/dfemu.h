#pragma once
#include <3ds.h>

#include "desfire.h"

// DESFire card emulation from a saved info file (dfLoadInfo), answered by the host through emuRun: see dfemu.c.
void dfEmuSet(const DfInfo *d);
const DfInfo *dfEmuInfo(void);
u32 dfEmuWrites(void);              // write commands that took (committed) so far
bool dfEmuSave(char *path, u32 max); // the card as readers left it: a new info file (dfSaveInfo)
u32 dfEmuApdu(const u8 *cmd, u32 len, u8 *resp, u32 max); // an EmuApdu
