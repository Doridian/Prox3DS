/* Patch SRAM image: entry pointer word first, code, then a params block the host patches
   at the very end. Load address = (entry & ~1) - 4, like the stock B5 patch (0x3B80C).
   Code must start right after the entry word (see NOTES.md). */
ENTRY(init)
MEMORY {
	sram (rwx) : ORIGIN = 0x3B80C, LENGTH = 0x3C530 - 0x3B80C
	/* The AON patch RAM: our AON segment (mkpatch.py) takes its first 14 bytes, the stock patch's
	   AON code (not loaded) the rest. Zeroed variables live here, outside the downloaded image;
	   init() clears them. */
	aon (rw) : ORIGIN = 0x68100, LENGTH = 0x68600 - 0x68100
}
SECTIONS
{
	.image : {
		KEEP(*(.entry))
		*(.text.init) *(.text*) *(.rodata*) *(.data*)
		. = ALIGN(4);
		KEEP(*(.params))
	} > sram
	.bss (NOLOAD) : {
		__bss_start = .;
		*(.bss*) *(COMMON)
		. = ALIGN(4);
		__bss_end = .;
	} > aon
	/DISCARD/ : { *(.ARM.*) *(.comment) }
}
