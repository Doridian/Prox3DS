/* Patch SRAM image: entry pointer word first, code, then a params block the host patches
   at the very end. Load address = (entry & ~1) - 4, like the stock B5 patch (0x3B80C).
   Code must start right after the entry word (see NOTES.md). */
ENTRY(init)
MEMORY { sram (rwx) : ORIGIN = 0x3B80C, LENGTH = 0x3C530 - 0x3B80C }
SECTIONS
{
	.image : {
		KEEP(*(.entry))
		*(.text.init) *(.text*) *(.rodata*) *(.data*) *(.bss*) *(COMMON)
		. = ALIGN(4);
		KEEP(*(.params))
	} > sram
	/DISCARD/ : { *(.ARM.*) *(.comment) }
}
