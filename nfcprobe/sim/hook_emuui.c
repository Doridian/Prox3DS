#include "../source/emuui.c"
#include "scenes.h"

void simEmuMenu(void)
{
	emuOpenMenu();
}

// A session in progress after a phone wrote a URL onto the emulated tag
void simEmuRun(bool written)
{
	u8 msg[200];
	static const char *log[] = { "> 00A4040007D2760000850101..  < 9000", "> 00A4000C02E103  < 9000",
		"> 00B000000F  < .. 9000", "> 00A4000C02E104  < 9000", "> 00B0000002  < .. 9000",
		"> 00D6000020001ED1011A5504..  < 9000" };
	emuNdefSet(msg, ndefText("en", "Hello from the 3DS", msg, sizeof(msg)));
	if (written) {
		u8 w[2 + 200];
		u32 n = ndefUri("https://github.com/Doridian/3dspm/a/rather/long/path?with=a&query=string", w + 2, 200);
		w[0] = n >> 8, w[1] = n;
		emuNdefApdu(NULL, 0, NULL, 0);
		emuNdefApdu((const u8[]){ 0x00, 0xA4, 0x04, 0x00, 0x07, 0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01 }, 12, msg, sizeof(msg));
		emuNdefApdu((const u8[]){ 0x00, 0xA4, 0x00, 0x0C, 0x02, 0xE1, 0x04 }, 7, msg, sizeof(msg));
		u8 up[5 + 202] = { 0x00, 0xD6, 0x00, 0x00, n + 2 };
		memcpy(up + 5, w, n + 2);
		emuNdefApdu(up, 5 + n + 2, msg, sizeof(msg));
	}
	memset(&emu, 0, sizeof(emu));
	memcpy(emu.uid, (const u8[]){ 0x08, 0xC0, 0x04, 0xDC }, 4);
	emu.field = emu.active = written;
	emu.fields = 16, emu.sessions = 8, emu.apdus = 40;
	for (int i = 0; i < (written ? 6 : 5); i++) snprintf(emu.log[emu.nlog++ % EMU_LOG_N], 48, "%s", log[i]);
	jobNextHint("Lay the 3DS on the reader, bottom screen down.");
	simBusy("Emulating a tag", true, false);
	simBusyView(emuView);
}

void simEmuDone(void)
{
	emuOk = true;
	doneEmu();
}
