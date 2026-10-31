# nfcprobe

Mifare Classic tool for the New3DS NFC controller (BCM20791). Build with `make` (devkitPro, needs
citro2d), run the .3dsx from the Homebrew Launcher. NFC is handed back to the system on exit (START).

The app loads its own chip patch (chip/memrw.c, embedded as `data/memrw_ncd.bin`, rebuilt by
`make` in `chip/`) and drives the RF framer through it: raw ISO14443A with our own parity and
Mifare Classic Crypto1 (`source/mon.c`, `source/mfc.c`, `source/crypto1.c`).

`data/` is not in git; populate it before building the app by running `make` in `chip/`
(builds `data/memrw_ncd.bin`). No Nintendo or Broadcom files are needed: `tools/mkpatch.py`
generates the whole patch (header, a 4-instruction AON thunk into ROM, our SRAM image).

The UI is on the top screen and driven by buttons only: a card on the reader covers the whole
bottom screen, which just mirrors the log (`sdmc:/nfcprobe.log`; SELECT shows it on top). Card
operations ask for confirmation before writing anything and can be stopped with B.
- Scan card: type, UID, ATQA/SAK, magic generation (Gen1a, Gen4 GTU, USCUID) and the GTU / USCUID
  config. Y edits the GTU config (UID length, card type, shadow mode; guarded, see `mfc.h`).
- Read card: dictionary (defaults + `sdmc:/nfcprobe/keys.txt`, one hex key per line), magic
  backdoors, FM11RF08S static-nonce and nested key recovery. Saved as
  `sdmc:/nfcprobe/dumps/<UID>.bin` + `.keys.txt` (never overwritten: `<UID>-2.bin` and so on) and
  opened in the editor.
- Saved dumps: open, write onto a magic card, delete. Foreign `.bin` dumps work too.
- Dump editor: one sector at a time as hex + ASCII, the block under the cursor decoded (manufacturer
  block / BCC, trailer keys and access conditions, value blocks). A edits a byte nibble by nibble, or
  the access conditions when on trailer bytes 6-8 (the inverted copy is kept consistent). X: save,
  save a copy, write the block to a card (magic backdoor, else the dump's keys), write the dump to a
  magic card, copy/paste/revert, add the dump's keys to `keys.txt`.
- Chip info: reset / init / patch version.

Card jobs keep the chip, so the network side can carry on with the loaded monitor.

Network: with wifi up, the app listens on TCP 8020 (address shown on the top screen) and
exposes raw takeover / power / I2C / GPIO primitives, plus the app's card operations
(`scan`, `mfread`, `mfdump`, `gen1awrite`, `mfwrite` in `tools/nfcnet.py`; ops 0x10-0x16 in
`source/netsrv.c`; `mfwrite` is an encrypted Mifare Classic write, WRITES THE CARD).
`nfcnet.py HOST shot [OUT.png]` grabs the top screen and `nfcnet.py HOST keys a down ...` presses
buttons (ops 0x20/0x21, served even while a job holds the chip). Drive it from the PC with
`tools/nfcnet.py HOST probe|spd FILE.ncd|send HEX...|release`, or import `Nfc` from it.
