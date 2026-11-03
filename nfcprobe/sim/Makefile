# Host build of the nfcprobe UI with fake citro2d / libctru (see README). make run: scenes -> out/*.png
CC      := gcc
CFLAGS  := -m32 -D_FILE_OFFSET_BITS=64 -D_TIME_BITS=64 -g -O0 -Wall -Wno-unused-function -Wno-format -Iinclude -I../source -I.
SRC     := fake.c hw.c scenes.c hook_app.c hook_mfui.c hook_editor.c hook_mfuui.c hook_mfuedit.c hook_dfui.c hook_ndefui.c hook_amiiboui.c hook_scui.c hook_gpui.c hook_oathui.c hook_emvui.c hook_mfutear.c hook_iclassui.c hook_emuui.c \
           ../source/ui.c ../source/mfc.c ../source/mfu.c ../source/desfire.c ../source/isodep.c \
           ../source/crypto1.c ../source/crapto1.c ../source/par.c ../source/dfcrypto.c ../source/entry.c ../source/nxpsig.c ../source/aidnames.c ../source/mfukeys.c ../source/mfckeys.c ../source/mfcinfo.c ../source/ndef.c ../source/madnames.c \
           ../source/iso7816.c ../source/scard.c ../source/gp.c ../source/zip.c ../source/sha1.c ../source/oath.c ../source/emv.c ../source/iclass.c ../source/iclassdict.c ../source/pm3dict.c ../source/iclasskeys.c ../source/amiibodb.c ../source/emu.c ../source/dumplist.c ../source/dfemu.c
OUT     := out

uisim: $(SRC) $(wildcard *.h include/*.h ../source/*.h ../source/*.c)
	$(CC) $(CFLAGS) -o $@ $(SRC) -pthread -lm

run: uisim
	rm -rf $(OUT) && mkdir -p $(OUT)
	./uisim $(OUT)
	python3 render.py $(OUT)

clean:
	rm -rf uisim $(OUT)

.PHONY: run clean
