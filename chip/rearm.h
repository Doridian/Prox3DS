// Listen re-arm, shared by the chip images that listen (reader.c, emu.c). After a field loss the ROM ends a
// listen session with a deactivation to idle, and the host has to send RF_DISCOVER again; through the host that
// takes 70-200 ms, while a reader that drops its field to reselect (pm3: a few ms off, WUPA 50 ms later) is back
// long before, and a field that is already on when listening starts is never seen. So for a listen-only
// discovery the chip re-arms by itself: the RF state machine (0x1AB6A, state byte 0x39E92, 0 = idle) calls the
// RAM hook *(0x3876C) with every event first; event 0 ends a session. 1 ms later (a ROM timer: run inside the
// event's handling the restart gets lost) we replay the host's RF_DISCOVER as the ROM's handler does (its
// message pointer at 0x39E8E, event 5). RF_DEACTIVATE from the host stops it.
//
// The includer defines REARM_CODE / REARM_VAR (sections: reader.c puts them in AON RAM) and DISC_VAR (disc[]),
// calls rearm_cmd() with every NCI command and sets RF_EVT_HOOK = rf_hook.
#define RF_EVT_HOOK (*(volatile u32 *)0x3876C) // nonzero return = consumed
#define RF_STATE    (*(volatile u8 *)0x39E92)
#define RF_DISC_MSG 0x39E8E // the RF_DISCOVER message (unaligned u32)
#define rf_event    ROM_FN(0x1AB6A, void (*)(u32 evt))
#define put32_rom   ROM_FN(0x1E856, void (*)(u32 v, u32 addr)) // unaligned store
#define timer_start ROM_FN(0xB04, void (*)(u32 *t, int us))    // t: next, fn, arg, deadline, flags (init 0xA90)
#define RF_EVT_END      0
#define RF_EVT_DISCOVER 5
#define REARM_NOW       0xFF // the timer's argument (no event has that number)

static int rf_hook(u32 x);
static u32 rearm_timer[5] REARM_VAR = { 0, (u32)rf_hook, REARM_NOW }; // next, callback, arg, deadline, flags

// The host's last listen-only RF_DISCOVER (up to 4 modes); disc[0] = 0: none (re-arm off).
static u8 disc[3 + 9] DISC_VAR;

// The RF event hook, and (x = REARM_NOW) the timer's callback.
REARM_CODE static int rf_hook(u32 x)
{
	if (!disc[0]) return 0;
	if (x == RF_EVT_END) {
		timer_start(rearm_timer, 1000);
	} else if (x == REARM_NOW && !RF_STATE) {
		put32_rom((u32)disc, RF_DISC_MSG);
		rf_event(RF_EVT_DISCOVER);
	}
	return 0;
}

static inline __attribute__((always_inline)) void rearm_cmd(const u8 *msg)
{
	if (msg[0] == 0x21 && (msg[1] == 0x03 || msg[1] == 0x06)) { // RF_DISCOVER: n, (mode, frequency)...; RF_DEACTIVATE
		u32 len = msg[2], n = msg[3], listen = msg[1] == 0x03 && len == 1 + 2 * n && len + 3 <= sizeof(disc);
		for (u32 i = 0; listen && i < n; i++) listen = msg[4 + 2 * i] >= 0x80;
		disc[0] = 0;
		for (u32 i = len + 3; listen && i--;) disc[i] = msg[i];
	}
}
