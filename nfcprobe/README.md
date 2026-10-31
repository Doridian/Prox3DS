# nfcprobe

Probe of the New3DS NFC controller (BCM20791). Build with `make` (devkitPro), run the .3dsx from the Homebrew Launcher. Reboot afterwards to restore NFC.

The app loads its own chip patch (chip/memrw.c, embedded as `data/memrw_ncd.bin`, rebuilt by
`make` in `chip/`) and drives the RF framer through it: raw ISO14443A with our own parity and
Mifare Classic Crypto1 (`source/mon.c`, `source/mfc.c`, `source/crypto1.c`).

`data/` is not in git; populate it before building the app:
- `data/memrw_ncd.bin`: run `make` in `chip/`.
- `data/patch_20791B5.bin`: the stock Broadcom patch (for L+B/X/Y), cut from your own decrypted
  NFC sysmodule (title 0004013020004002, v21):
  ```
  python3 tools/ncch.py "0004013020004002.00000015 (0201builder).cxi" extracted/0004013020004002
  python3 -c "import sys; d=open(sys.argv[1],'rb').read(); open(sys.argv[2],'wb').write(d[0x37360:0x38805])" \
      extracted/0004013020004002/code.bin nfcprobe/data/patch_20791B5.bin
  ```

Buttons (log goes to `sdmc:/nfcprobe.log`):
- A: scan a card (ATQA / SAK / UID); hold it to the bottom screen
- X: dump a Mifare Classic card with the default keys plus `sdmc:/nfcprobe/keys.txt` (one hex
  key per line); saved as `sdmc:/nfcprobe/dumps/<UID>.bin` and `<UID>.keys.txt`. Read only.
- L+A: chip probe (reset / init / patch version)
- L+B / L+X / L+Y: load the stock patch / with a padding byte changed / with the signature changed
- L+R: try HCI Read_RAM (not supported on B5: status 01)

Card jobs keep the chip, so the network side can carry on with the loaded monitor.

Network: with wifi up, the app listens on TCP 8020 (address shown on the top screen) and
exposes raw takeover / power / I2C / GPIO primitives, plus the app's card operations
(`scan`, `mfread`, `mfdump`, `gen1awrite`, `mfwrite` in `tools/nfcnet.py`; ops 0x10-0x16 in
`source/netsrv.c`; `mfwrite` is an encrypted Mifare Classic write, WRITES THE CARD). Drive it from the PC with
`tools/nfcnet.py HOST probe|spd FILE.ncd|send HEX...|release`, or import `Nfc` from it.
