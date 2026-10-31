// Chip-side dumper v3 (BCM20791B5, Cortex-M3): streams memory through GET_PATCH_VERSION.
//
// GET_PATCH_VERSION reports 20 bytes from OUT (0x3B7A8). A DWT read watchpoint on the
// last word of OUT raises DebugMon once the ROM handler has copied OUT into the response;
// our DebugMon handler then refills OUT with the next chunk. So every GET_PATCH_VERSION
// returns: [0..3] address, [4..19] 16 bytes from that address, and the following query
// gets the next 16 bytes. The ROM's exception stubs jump through a RAM table at 0x38000
// (same layout as the vector table), so installing the handler is a RAM write.
typedef unsigned int u32;
typedef unsigned char u8;

#define OUT        ((volatile u8 *)0x3B7A8)
#define OUT_LAST   0x3B7B8                       // word read last when OUT is copied
#define RAM_VECTOR ((volatile u32 *)0x38000)
#define VEC_DEBUGMON 12

#define REG(a)     (*(volatile u32 *)(a))
#define SHPR3      REG(0xE000ED20)               // [7:0] DebugMon priority
#define DFSR       REG(0xE000ED30)
#define DHCSR      REG(0xE000EDF0)
#define DEMCR      REG(0xE000EDFC)
#define DWT_CTRL   REG(0xE0001000)
#define DWT_COMP0  REG(0xE0001020)
#define DWT_MASK0  REG(0xE0001024)
#define DWT_FUNC0  REG(0xE0001028)

#define DEMCR_TRCENA (1u << 24)
#define DEMCR_MON_EN (1u << 16)
#define DFSR_DWTTRAP (1u << 2)
#define DWT_FUNC_READ 5

// Host-patched (tools/dumpchip.py), at the end of the image.
struct params {
	u32 start; // first address to stream
	u32 debug; // 1: instead of data, report [0..3] hit count, [4..7] PC, [8..11] LR of the reader
	           // 2: after init, report DWT_CTRL, DEMCR, DHCSR, DWT_FUNCTION0, RAM DebugMon vector
};

int init(void);
void dbgmon_entry(void);

__attribute__((section(".entry"), used)) int (*const entry)(void) = init;
__attribute__((section(".params"), used)) volatile struct params params;

static u32 cursor, hits;

static void fill(void)
{
	const volatile u8 *src = (const volatile u8 *)cursor;
	for (int i = 0; i < 4; i++) OUT[i] = cursor >> (8 * i);
	for (int i = 0; i < 16; i++) OUT[4 + i] = src[i];
	cursor += 16;
}

// sp points at the EXC_RETURN the ROM stub pushed; the exception frame is on the
// process stack if EXC_RETURN bit 2 is set, else right above it.
__attribute__((used)) static void dbgmon(u32 *sp)
{
	u32 *frame = sp + 1;
	if (sp[0] & 4) __asm__ volatile("mrs %0, psp" : "=r"(frame));
	DFSR = DFSR_DWTTRAP;
	hits++;
	if (!params.debug) {
		fill();
		return;
	}
	// The PC tells where the GET_PATCH_VERSION handler is.
	u32 vals[5] = { hits, frame[6], frame[5], 0, 0 };
	for (int i = 0; i < 20; i++) OUT[i] = ((u8 *)vals)[i];
}

// The ROM stub did push {lr} before jumping here, so return with pop {pc}.
__attribute__((naked)) void dbgmon_entry(void)
{
	__asm__ volatile(
		"mov r0, sp\n"
		"bl dbgmon\n"
		"pop {pc}\n");
}

// The ROM treats a nonzero return as failure; code must start right after the entry word.
__attribute__((section(".text.init"))) int init(void)
{
	cursor = params.start;
	fill();
	RAM_VECTOR[VEC_DEBUGMON] = (u32)dbgmon_entry;
	SHPR3 &= ~0xFFu;
	DEMCR |= DEMCR_TRCENA | DEMCR_MON_EN;
	DWT_COMP0 = OUT_LAST;
	DWT_MASK0 = 2; // whole word
	DWT_FUNC0 = DWT_FUNC_READ;
	if (params.debug == 2) {
		u32 vals[5] = { DWT_CTRL, DEMCR, DHCSR, DWT_FUNC0, RAM_VECTOR[VEC_DEBUGMON] };
		for (int i = 0; i < 20; i++) OUT[i] = ((u8 *)vals)[i];
	}
	return 0;
}
