# Chip-side patch code for the BCM20791B5 (Cortex-M; the stock patch is plain Thumb, so build for M0), built with devkitARM's gcc.
PREFIX  := /opt/devkitpro/devkitARM/bin/arm-none-eabi-
CFLAGS  := -mcpu=cortex-m0 -mthumb -Os -ffreestanding -nostdlib -fno-builtin \
           -fno-tree-loop-distribute-patterns -fno-jump-tables -Wall -Wl,--no-warn-rwx-segments
TARGETS := null dumper1 dumper2 dumper3 dumper4 memrw lmon emu_mfu emu_mfc

all: $(TARGETS:=.bin) ../nfcprobe/data/memrw_ncd.bin ../nfcprobe/data/emu_mfu_ncd.bin ../nfcprobe/data/emu_mfc_ncd.bin

# The monitor as an SPD patch, embedded in the app.
../nfcprobe/data/memrw_ncd.bin: memrw.bin ../tools/mkpatch.py
	python3 ../tools/mkpatch.py $< $@

# The card emulation images (one per card family, emu.c built twice), loaded in its place for chip-answered
# card mode.
../nfcprobe/data/emu_%_ncd.bin: emu_%.bin ../tools/mkpatch.py
	python3 ../tools/mkpatch.py $< $@ --aon emu_$*.aon.bin

# emu: more AON code (hook, reply), its variables still end below 0x68410 (NOTES.md: not free above).
emu_mfu.elf emu_mfc.elf: CFLAGS += -Wl,--defsym=AON_SPLIT=0x68180
emu_mfu.elf: CFLAGS += -DEMU_MFU
emu_mfc.elf: CFLAGS += -DEMU_MFC
emu_%.elf: emu.c link.ld
	$(PREFIX)gcc $(CFLAGS) -T link.ld -o $@ $<

%.elf: %.c link.ld
	$(PREFIX)gcc $(CFLAGS) -T link.ld -o $@ $<

%.bin: %.elf
	$(PREFIX)objcopy -O binary -j .image $< $@
	$(PREFIX)objcopy -O binary -j .aon $< $*.aon.bin
	$(PREFIX)objdump -d $< > $*.s

clean:
	rm -f *.elf *.bin *.s
