// Chip-side v1 dumper (BCM20791B5). Runs once as the patch's SRAM init.
// The patch header's chip-version string is a unique marker; the ROM keeps a copy of
// the header fields that GET_PATCH_VERSION reports. Find every copy of the marker in
// RAM and overwrite the 24 reported bytes (proj, ?, string, major, minor) with:
//   [0..3] address of this copy, [4..7] copy index, [8..23] 16 bytes read from params.src
typedef unsigned int u32;
typedef unsigned char u8;

// Host-patched (tools/dumpchip.py), at the end of the image.
struct params {
	u32 src;        // memory to report
	u32 scan_start; // RAM range searched for the marker
	u32 scan_end;
	u8 mark[16];    // same bytes as the header's chip-version string
};

// The ROM treats a nonzero return from the SRAM init as failure (the chip goes silent).
int init(void);

__attribute__((section(".entry"), used)) int (*const entry)(void) = init;
__attribute__((section(".params"), used)) volatile struct params params = { 0, 0x3B000, 0x3B590, "DMP1 marker 0000" };

__attribute__((section(".text.init"))) int init(void)
{
	u32 n = 0;
	for (u8 *p = (u8 *)params.scan_start + 4; p + 20 <= (u8 *)params.scan_end; p++) {
		int i;
		for (i = 0; i < 16 && p[i] == params.mark[i]; i++);
		if (i < 16) continue;
		u8 *dst = p - 4;
		u32 vals[2] = { (u32)p, n++ };
		for (i = 0; i < 8; i++) dst[i] = ((u8 *)vals)[i];
		const volatile u8 *src = (const volatile u8 *)params.src;
		for (i = 0; i < 16; i++) dst[8 + i] = src[i];
	}
	return 0;
}
