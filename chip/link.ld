/* Patch SRAM image: entry pointer word first, code, then a params block the host patches
   at the very end. Load address = (entry & ~1) - 4, like the stock B5 patch (0x3B80C).
   Code must start right after the entry word (see docs/NOTES.md). */
ENTRY(init)
/* Where the AON code region ends and the zeroed variables start (an image can move it: --defsym). */
AON_SPLIT = DEFINED(AON_SPLIT) ? AON_SPLIT : 0x68100;
MEMORY {
	sram (rwx) : ORIGIN = 0x3B80C, LENGTH = 0x3C530 - 0x3B80C
	/* The AON patch RAM: our AON segment (mkpatch.py) takes its first 14 bytes, the stock patch's
	   AON code (not loaded) the rest. Zeroed variables live here, outside the downloaded image;
	   init() clears them. */
	aon (rw) : ORIGIN = AON_SPLIT, LENGTH = 0x68600 - AON_SPLIT
	/* Free AON RAM between our AON segment's thunk (0x68008, 14 bytes) and the zeroed variables: code that
	   doesn't fit the SRAM image (.aon, extracted as <name>.aon.bin, appended to the AON segment by
	   mkpatch.py). */
	aoncode (rwx) : ORIGIN = 0x68018, LENGTH = AON_SPLIT - 0x68018
}
SECTIONS
{
	.image : {
		KEEP(*(.entry))
		*(.text.init) *(.text*) *(.rodata*) *(.data*)
		. = ALIGN(4);
		KEEP(*(.params))
	} > sram
	.aon : {
		*(.aon*)
	} > aoncode
	.bss (NOLOAD) : {
		__bss_start = .;
		*(.bss*) *(COMMON)
		. = ALIGN(4);
		__bss_end = .;
	} > aon
	/DISCARD/ : { *(.ARM.*) *(.comment) }
}
