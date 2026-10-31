// Chip-side dumper v4 (BCM20791B5): memory reads on request via GET_PATCH_VERSION.
//
// The host sends GET_PATCH_VERSION with a payload the ROM ignores:
//   2F 2D 07 | session u8 | seq u16 | addr u32
// Received commands sit in RAM buffers (the last one before init was at 0x3AF05), so
// wrappers around SysTick and IRQ0..7 look for the newest request of this session and
// fill OUT (0x3B7A8, the 20 bytes GET_PATCH_VERSION reports) with [addr u32][16 bytes].
// The answer carries its address, so a reply that predates the fill is recognisable.
// DWT/SCS read as zero on this chip, so no watchpoints; the ROM's exception stubs jump
// through a RAM table at 0x38000 with the vector table's layout, so wrapping is a RAM write.
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;

#define OUT        ((volatile u8 *)0x3B7A8)
#define RAM_VECTOR ((volatile u32 *)0x38000)
#define VEC_SYSTICK 15
#define VEC_IRQ0    16
#define N_WRAPPED   9 // SysTick, IRQ0..7

// Host-patched (tools/dumpchip.py), at the end of the image.
struct params {
	u32 scan_start; // request buffers: checked at scan_start, scan_start + step, ...
	u32 scan_end;
	u32 step;
	u32 session;
};

int init(void);

__attribute__((section(".entry"), used)) int (*const entry)(void) = init;
__attribute__((section(".params"), used)) volatile struct params params;

__attribute__((used)) u32 orig[N_WRAPPED]; // original RAM vectors, used by the wrappers
static u32 served = 0x10000; // seq of the request OUT holds (none yet)

static void fill(u32 addr)
{
	const volatile u8 *src = (const volatile u8 *)addr;
	for (int i = 0; i < 4; i++) OUT[i] = addr >> (8 * i);
	for (int i = 0; i < 16; i++) OUT[4 + i] = src[i];
}

__attribute__((used)) void check(void)
{
	const volatile u8 *best = 0;
	u32 bestSeq = 0;
	for (u32 a = params.scan_start; a < params.scan_end; a += params.step) {
		const volatile u8 *p = (const volatile u8 *)a;
		if (p[0] != 0x2F || p[1] != 0x2D || p[2] != 0x07 || p[3] != params.session) continue;
		u32 seq = p[4] | (p[5] << 8);
		if (!best || seq > bestSeq) best = p, bestSeq = seq;
	}
	if (!best || bestSeq == served) return;
	served = bestSeq;
	fill(best[6] | (best[7] << 8) | (best[8] << 16) | ((u32)best[9] << 24));
}

// Each wrapper runs check(), then continues into the original handler exactly as the
// ROM stub would have (same registers and stack), so it works for stubs with and
// without their own push {lr}.
#define WRAP(n) \
	__attribute__((naked)) void wrap##n(void) \
	{ \
		__asm__ volatile( \
			"push {r4, lr}\n" \
			"bl check\n" \
			"pop {r4}\n" \
			"pop {r0}\n" \
			"mov lr, r0\n" \
			"ldr r0, =orig\n" \
			"ldr r0, [r0, #" #n " * 4]\n" \
			"bx r0\n" \
			".ltorg\n"); \
	}
WRAP(0) WRAP(1) WRAP(2) WRAP(3) WRAP(4) WRAP(5) WRAP(6) WRAP(7) WRAP(8)

static void (*const wrappers[N_WRAPPED])(void) = { wrap0, wrap1, wrap2, wrap3, wrap4, wrap5, wrap6, wrap7, wrap8 };

// The ROM treats a nonzero return as failure; code must start right after the entry word.
__attribute__((section(".text.init"))) int init(void)
{
	fill(0);
	for (int i = 0; i < N_WRAPPED; i++) {
		volatile u32 *v = &RAM_VECTOR[VEC_SYSTICK + i];
		orig[i] = *v;
		*v = (u32)wrappers[i];
	}
	return 0;
}
