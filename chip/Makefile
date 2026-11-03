# Chip-side patch code for the BCM20791B5 (Cortex-M; the stock patch is plain Thumb, so build for M0), built with devkitARM's gcc.
PREFIX  := /opt/devkitpro/devkitARM/bin/arm-none-eabi-
CFLAGS  := -mcpu=cortex-m0 -mthumb -Os -ffreestanding -nostdlib -fno-builtin \
           -fno-tree-loop-distribute-patterns -fno-jump-tables -Wall -Wl,--no-warn-rwx-segments
TARGETS := null dumper1 dumper2 dumper3 dumper4 memrw lmon emu

all: $(TARGETS:=.bin) ../nfcprobe/data/memrw_ncd.bin ../nfcprobe/data/emu_ncd.bin

# The monitor as an SPD patch, embedded in the app.
../nfcprobe/data/memrw_ncd.bin: memrw.bin ../tools/mkpatch.py
	python3 ../tools/mkpatch.py $< $@

# The card emulation image, loaded in its place for chip-answered card mode.
../nfcprobe/data/emu_ncd.bin: emu.bin ../tools/mkpatch.py
	python3 ../tools/mkpatch.py $< $@

%.elf: %.c link.ld
	$(PREFIX)gcc $(CFLAGS) -T link.ld -o $@ $<

%.bin: %.elf
	$(PREFIX)objcopy -O binary $< $@
	$(PREFIX)objdump -d $< > $*.s

clean:
	rm -f *.elf *.bin *.s
