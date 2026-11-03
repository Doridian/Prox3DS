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
	mode = MODE_NDEF;
	emu.id = (EmuId){ { 0x08, 0xC0, 0x04, 0xDC }, 4, { 0x04, 0x00 }, 0x20 };
	emu.field = emu.active = written;
	emu.fields = 16, emu.sessions = 8, emu.apdus = 40;
	for (int i = 0; i < (written ? 6 : 5); i++) snprintf(emu.log[emu.nlog++ % EMU_LOG_N], 48, "%s", log[i]);
	jobNextHint("Tap a phone on the bottom screen.");
	simBusy("Emulating a tag", true, false);
	simBusyView(emuView);
}

// UID-only (a 7-byte NTAG UID) or the APDU log, mid-session
void simEmuMode(int which)
{
	static const char *log[] = { "> 00A4040007A0000000031010..  < 6A82", "> 00A4040007A0000000041010..  < 6A82",
		"> 00A404000E325041592E5359..  < .. 9000", "> 80A8000002830000  < 6D00" };
	memset(&emu, 0, sizeof(emu));
	if (which == 0) {
		mode = MODE_UID;
		emu.id = (EmuId){ { 0x04, 0x6B, 0x21, 0x9A, 0x3C, 0x5D, 0x80 }, 7, { 0x44, 0x00 }, 0x00 };
		emu.field = true, emu.fields = 3;
	} else {
		mode = MODE_LOG;
		nrules = 2;
		emu.id = (EmuId){ { 0x08, 0x12, 0x34, 0x56 }, 4, { 0x04, 0x00 }, 0x20 };
		emu.active = emu.field = true, emu.fields = 2, emu.sessions = 2, emu.apdus = 4;
		for (int i = 0; i < 4; i++) snprintf(emu.log[emu.nlog++ % EMU_LOG_N], 48, "%s", log[i]);
	}
	jobNextHint("Tap a phone on the bottom screen.");
	simBusy(which ? "APDU log" : "Emulating a UID", true, false);
	simBusyView(emuView);
}

// A dump emulated on the chip, after a reader read it and wrote a page; then the save question
void simEmuMfu(bool done)
{
	static const char *log[] = { "GET_VERSION", "READ_SIG", "READ 04", "READ 08", "WRITE 06: CAFEBABE", "HLTA" };
	memset(&runDump, 0, sizeof(runDump));
	runDump.info.type = mfuTypeForPages(135);
	runDump.pages = 135;
	snprintf(runName, sizeof(runName), "04A1B2C3D4E5F6-16.bin");
	memset(&emu, 0, sizeof(emu));
	mode = MODE_MFU;
	emu.id = (EmuId){ { 0x04, 0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6 }, 7, { 0x44, 0x00 }, 0x00 };
	emu.field = true, emu.fields = 12, emu.frames = 87, emu.writes = 1, emu.changed = 1, emu.chipPages = 135;
	for (int i = 0; i < 6; i++) snprintf(emu.log[emu.nlog++ % EMU_LOG_N], 48, "%s", log[i]);
	if (done) {
		emuOk = true;
		doneEmu();
		return;
	}
	jobNextHint("Tap a phone on the bottom screen.");
	simBusy("Emulating a card", true, false);
	simBusyView(emuView);
}

void simEmuForm(void)
{
	card = (Card){ .atqa = { 0x44, 0x00 }, .uid = { 0x04, 0x6B, 0x21, 0x9A, 0x3C, 0x5D, 0x80 }, .uidLen = 7, .sak = 0 };
	startTyped();
}

void simEmuDone(void)
{
	emuOk = true;
	mode = MODE_NDEF;
	doneEmu();
}
