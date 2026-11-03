// Listen-mode exploration monitor (BCM20791B5): reader.c's basic ops (same 2F 2C protocol and
// opcodes 0-4, so tools/chipmon.py drives it) plus an interrupt log for card emulation work.
//   op 5 IRQLOG  irq mask u8, only-changes u8, 5 x register u32 [, unused u8 [, swallow u8]]
//                -> 4F 2C | 00 | log address u32
//     wraps IRQ0..7 and records {timer, irq, 5 watched registers (low 16 bits)} per interrupt
//     (masked IRQs skipped; with only-changes, only when a watched register changed) into a
//     128-entry ring: count u32, then 16-byte entries.
//     swallow: IRQ0 (framer) is acked here (all sub-statuses cleared) and the ROM's handler skipped;
//     2 also snapshots the framer registers on field on / field lost (see log_irq).
//   op 6 SAMPLE  (addr = register) interval u16 ticks, count u16 -> 4F 2C | 00 | buffer u32
//     count u16 samples of the register (low half), one per interval, into the log ring's memory
//     (stops the IRQ log); blocks the NCI task meanwhile.
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;

#define CMD_HOOK  (*(volatile u32 *)0x38718)
#define OID_DEBUG 0x2C
#define MAX_DATA  0xF0

#define ROM_FN(addr, type) ((type)((addr) | 1))
#define nci_alloc ROM_FN(0x188C2, u8 *(*)(u32 total_len, u32 mt))
#define nci_send  ROM_FN(0x188E4, void (*)(u8 *pkt))

#define TIMER       (*(volatile u32 *)0x5E024)
#define REG(a)      (*(volatile u32 *)(a))

enum { OP_READ8, OP_WRITE8, OP_CALL, OP_READ32, OP_WRITE32, OP_IRQLOG, OP_SAMPLE };

// IRQ log: every interrupt (IRQ0..7, wrapped in the ROM's RAM vector table at 0x38040) with five
// watched registers, recorded before the ROM's handler runs.
#define RAM_VECTOR ((volatile u32 *)0x38000)
#define VEC_IRQ0   16
#define N_IRQ      8
#define N_LOG      128 // power of two
#define N_WATCH    5
struct ent {
	u32 timer;
	u8 irq, pad;
	u16 val[N_WATCH];
};
// In the SRAM image (downloaded as zeros): AON RAM above reader.c's 0x68410 is not free.
static struct {
	u32 count;
	struct ent ring[N_LOG];
} irqlog __attribute__((section(".data")));
static u32 watch[N_WATCH] __attribute__((section(".data")));
static u32 irq_mask __attribute__((section(".data")));
static u32 only_changes __attribute__((section(".data")));
static u16 last[N_WATCH] __attribute__((section(".data")));
__attribute__((used)) u32 orig[N_IRQ] __attribute__((section(".data")));

static u32 swallow __attribute__((section(".data"))); // IRQ0: ack the framer and skip the ROM

// Returns nonzero when the interrupt was handled here (the wrapper then returns from the exception).
__attribute__((used)) u32 log_irq(u32 irq)
{
	u32 ret = 0;
	if (irq == 0 && swallow) {
		u32 rf = REG(0x5C5C4);
		// swallow 2: snapshot 0x5C540-5FF and 0x5C640-6FF into the ring memory on field on
		// (RF status bit 0, slot 0) and field lost (bit 1, slot 1); keep the IRQ mask 0
		if (swallow == 2 && rf & 3) {
			u32 *out = (u32 *)irqlog.ring + (rf & 1 ? 0 : 96);
			for (u32 i = 0; i < 48; i++) {
				out[i] = REG(0x5C540 + 4 * i);
				out[48 + i] = REG(0x5C640 + 4 * i);
			}
		}
		REG(0x5C5C4) = rf; // write-1-clear sub-statuses (RF, TX/RX, timer)
		REG(0x5C5D0) = REG(0x5C5D0);
		REG(0x5C5DC) = REG(0x5C5DC);
		ret = !REG(0x5C5C0); // anything else pending: let the ROM have it
	}
	if (!(irq_mask >> irq & 1)) return ret;
	u16 v[N_WATCH];
	u32 changed = 0;
	for (int i = 0; i < N_WATCH; i++) {
		v[i] = watch[i] ? REG(watch[i]) : 0;
		changed |= v[i] != last[i];
		last[i] = v[i];
	}
	if (only_changes && !changed) return ret;
	struct ent *e = &irqlog.ring[irqlog.count & (N_LOG - 1)];
	e->pad = 0;
	e->timer = TIMER;
	e->irq = irq;
	for (int i = 0; i < N_WATCH; i++) e->val[i] = v[i];
	irqlog.count++;
	return ret;
}

// Each wrapper logs, then continues into the original handler exactly as the ROM stub would have
// (the stubs leave only r0 clobbered and lr = EXC_RETURN), like chip/dumper4.c, or returns from
// the exception when log_irq handled it (r1-r3 are stacked by the hardware).
#define WRAP(n) \
	__attribute__((naked)) void wrap##n(void) \
	{ \
		__asm__ volatile( \
			"push {r4, lr}\n" \
			"movs r0, #" #n "\n" \
			"bl log_irq\n" \
			"pop {r1, r2}\n" \
			"mov r4, r1\n" \
			"mov lr, r2\n" \
			"cmp r0, #0\n" \
			"beq 1f\n" \
			"bx lr\n" \
			"1:\n" \
			"ldr r0, =orig\n" \
			"ldr r0, [r0, #" #n " * 4]\n" \
			"bx r0\n" \
			".ltorg\n"); \
	}
WRAP(0) WRAP(1) WRAP(2) WRAP(3) WRAP(4) WRAP(5) WRAP(6) WRAP(7)

static void (*const wrappers[N_IRQ])(void) = { wrap0, wrap1, wrap2, wrap3, wrap4, wrap5, wrap6, wrap7 };

int init(void);

__attribute__((section(".entry"), used)) int (*const entry)(void) = init;

static u32 get32(const u8 *p)
{
	return p[0] | (p[1] << 8) | (p[2] << 16) | ((u32)p[3] << 24);
}

static void put32(u8 *p, u32 v)
{
	for (int i = 0; i < 4; i++) p[i] = v >> (8 * i);
}

static void reply(u32 status, const u8 *data, u32 len)
{
	u8 *pkt = nci_alloc(3 + 1 + len, 2);
	if (!pkt) return;
	pkt[0] |= 0xF;
	pkt[1] = OID_DEBUG;
	pkt[3] = status;
	for (u32 i = 0; i < len; i++) pkt[4 + i] = data[i];
	nci_send(pkt);
}

static int hook(u8 *msg)
{
	if ((msg[0] & 0xF) != 0xF || (msg[1] & 0x3F) != OID_DEBUG) return 0;
	u32 len = msg[2];
	const u8 *p = msg + 3;
	if (len < 5) {
		reply(1, 0, 0);
		return 1;
	}
	u32 addr = get32(p + 1), n = len - 5;
	const u8 *arg = p + 5;
	static u8 buf[MAX_DATA] __attribute__((aligned(4)));

	switch (p[0]) {
	case OP_READ8:
		if (n < 1 || arg[0] > MAX_DATA) break;
		for (u32 i = 0; i < arg[0]; i++) buf[i] = ((volatile u8 *)addr)[i];
		reply(0, buf, arg[0]);
		return 1;
	case OP_WRITE8:
		for (u32 i = 0; i < n; i++) ((volatile u8 *)addr)[i] = arg[i];
		reply(0, 0, 0);
		return 1;
	case OP_CALL: {
		if (n < 16) break;
		u32 r = ((u32 (*)(u32, u32, u32, u32))(addr | 1))(get32(arg), get32(arg + 4), get32(arg + 8), get32(arg + 12));
		put32(buf, r);
		reply(0, buf, 4);
		return 1;
	}
	case OP_READ32:
		if (n < 1 || arg[0] > MAX_DATA / 4 || addr & 3) break;
		for (u32 i = 0; i < arg[0]; i++) put32(buf + 4 * i, ((volatile u32 *)addr)[i]);
		reply(0, buf, arg[0] * 4);
		return 1;
	case OP_WRITE32:
		if (n & 3 || addr & 3) break;
		for (u32 i = 0; i < n / 4; i++) ((volatile u32 *)addr)[i] = get32(arg + 4 * i);
		reply(0, 0, 0);
		return 1;
	case OP_IRQLOG:
		if (n < 2 + 4 * N_WATCH) break;
		for (int i = 0; i < N_WATCH; i++) watch[i] = get32(arg + 2 + 4 * i);
		only_changes = arg[1];
		swallow = n > 3 + 4 * N_WATCH ? arg[3 + 4 * N_WATCH] : 0;
		irq_mask = arg[0];
		if (!orig[0])
			for (int i = 0; i < N_IRQ; i++) {
				orig[i] = RAM_VECTOR[VEC_IRQ0 + i];
				RAM_VECTOR[VEC_IRQ0 + i] = (u32)wrappers[i];
			}
		put32(buf, (u32)&irqlog);
		reply(0, buf, 4);
		return 1;
	case OP_SAMPLE: {
		// addr = register; arg: interval ticks u16, count u16 (<= 1024) -> u16 samples into the
		// log ring's memory (the IRQ log is reset); blocks the NCI task, interrupts stay on
		if (n < 4) break;
		u32 iv = arg[0] | arg[1] << 8, cnt = arg[2] | arg[3] << 8;
		if (cnt > sizeof irqlog.ring / 2) break;
		u16 *out = (u16 *)irqlog.ring;
		irq_mask = 0;
		u32 t = TIMER;
		for (u32 i = 0; i < cnt; i++) {
			out[i] = REG(addr);
			while (t - TIMER < iv) {}
			t -= iv;
		}
		irqlog.count = 0;
		put32(buf, (u32)out);
		reply(0, buf, 4);
		return 1;
	}
	}
	reply(1, 0, 0);
	return 1;
}

__attribute__((section(".text.init"))) int init(void)
{
	extern u32 __bss_start[], __bss_end[];
	for (u32 *p = __bss_start; p < __bss_end; p++) *p = 0;
	CMD_HOOK = (u32)hook;
	return 0;
}
