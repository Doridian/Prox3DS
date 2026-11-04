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
		u32 n = ndefUri("https://github.com/Doridian/Prox3DS/a/rather/long/path?with=a&query=string", w + 2, 200);
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

// A Classic 1K dump being read by a reader
void simEmuMfc(void)
{
	static const char *log[] = { "AUTH A 4", "{nr}{ar}", "READ 4", "READ 5", "nested AUTH B 8", "HALT" };
	snprintf(runName, sizeof(runName), "4ACF2F0C-3.bin");
	memset(&emu, 0, sizeof(emu));
	mode = MODE_MFC;
	emu.id = (EmuId){ { 0x4A, 0xCF, 0x2F, 0x0C }, 4, { 0x04, 0x00 }, 0x08 };
	emu.field = true, emu.fields = 3, emu.frames = 41, emu.chipPages = 64;
	for (int i = 0; i < 6; i++) snprintf(emu.log[emu.nlog++ % EMU_LOG_N], 48, "%s", log[i]);
	jobNextHint("Tap a phone on the bottom screen.");
	simBusy("Emulating a card", true, false);
	simBusyView(emuView);
}

// A DESFire info file mid-session: an EV3 with keyed applications
void simEmuDf(void)
{
	static DfInfo d;
	static const char *log[] = { "> 905A00000333221100  < 9100", "> 90AA0000010100  < .. 91AF",
		"> 90AF000020A3C1..  < .. 9100", "> 90F50000010100  < .. 9100", "> 90BD0000070100000000..  < .. 9100" };
	memset(&d, 0, sizeof(d));
	static const u8 ver[28] = { 0x04, 0x01, 0x01, 0x33, 0x00, 0x1A, 0x05, 0x04, 0x01, 0x01, 0x03, 0x00, 0x1A, 0x05 };
	memcpy(d.ver, ver, 28);
	d.verLen = 28, d.napps = 4, d.piccKey.known = true;
	for (int i = 0; i < 4; i++) {
		d.apps[i].nfiles = 3;
		d.apps[i].keys[0].known = d.apps[i].keys[1].known = true;
	}
	dfEmuSet(&d);
	snprintf(runName, sizeof(runName), "040C686A9F2390-9.txt");
	memset(&emu, 0, sizeof(emu));
	mode = MODE_DF;
	emu.id = (EmuId){ { 0x04, 0x0C, 0x68, 0x6A, 0x9F, 0x23, 0x90 }, 7, { 0x44, 0x03 }, 0x20 };
	emu.field = emu.active = true, emu.fields = 4, emu.sessions = 3, emu.apdus = 23;
	for (int i = 0; i < 5; i++) snprintf(emu.log[emu.nlog++ % EMU_LOG_N], 48, "%s", log[i]);
	jobNextHint("Tap a phone on the bottom screen.");
	simBusy("Emulating a card", true, false);
	simBusyView(emuView);
}

void simEmuJc(void)
{
	static const char *log[] = { "> 00A4040008A00000052721..  < .. 9000", "> 00A1000000  < .. 9000",
		"> 00A4000002000000  < .. 9000", "> 00A2000113710772666336..  < .. 9000" };
	memset(&emu, 0, sizeof(emu));
	mode = MODE_JC;
	if (jcCard.napplets) jcCard.selected = 0;
	jcCard.vm.steps = 18432;
	emu.id = (EmuId){ { 0x08, 0x5E, 0x11, 0xA7 }, 4, { 0x04, 0x00 }, 0x20 };
	emu.field = emu.active = true, emu.fields = 2, emu.sessions = 2, emu.apdus = 9;
	for (int i = 0; i < 4; i++) snprintf(emu.log[emu.nlog++ % EMU_LOG_N], 48, "%s", log[i]);
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
