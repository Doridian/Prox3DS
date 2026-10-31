// Chip-side dumper v2 (BCM20791B5). Runs once as the patch's SRAM init and leaves
// 20 bytes in the struct GET_PATCH_VERSION reports from (0x3B7A8, found with dumper1):
//   mode 0: copy 20 bytes from a
//   mode 1: scan words in [a, b) for values in [lo, hi]: hit count, first 4 hit addresses
//   mode 2: scan bytes in [a, b) for the 4 bytes of ~lo: hit count, first 4 hit addresses
//           (inverted, or the copies of this patch record in RAM would match)
typedef unsigned int u32;
typedef unsigned char u8;

#define OUT ((volatile u8 *)0x3B7A8)

struct params {
	u32 mode, a, b, lo, hi;
};

int init(void);

__attribute__((section(".entry"), used)) int (*const entry)(void) = init;
__attribute__((section(".params"), used)) volatile struct params params;

static void put(int off, u32 v)
{
	for (int i = 0; i < 4; i++) OUT[off + i] = v >> (8 * i);
}

// The ROM treats a nonzero return as failure; code must start right after the entry word.
__attribute__((section(".text.init"))) int init(void)
{
	if (params.mode == 0) {
		const volatile u8 *src = (const volatile u8 *)params.a;
		for (int i = 0; i < 20; i++) OUT[i] = src[i];
	} else if (params.mode == 1) {
		u32 n = 0;
		for (const volatile u32 *p = (const volatile u32 *)params.a; p < (const volatile u32 *)params.b; p++) {
			u32 v = *p;
			if (v < params.lo || v > params.hi) continue;
			if (n < 4) put(4 + 4 * n, (u32)p);
			n++;
		}
		put(0, n);
	} else if (params.mode == 2) {
		u32 n = 0, pat = ~params.lo;
		for (const volatile u8 *p = (const volatile u8 *)params.a; p < (const volatile u8 *)params.b; p++) {
			if (p[0] != (pat & 0xFF) || p[1] != ((pat >> 8) & 0xFF) ||
				p[2] != ((pat >> 16) & 0xFF) || p[3] != (pat >> 24))
				continue;
			if (n < 4) put(4 + 4 * n, (u32)p);
			n++;
		}
		put(0, n);
	}
	return 0;
}
