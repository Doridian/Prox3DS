# nfcprobe

Mifare Classic and Ultralight / NTAG tool for the New3DS NFC controller (BCM20791). Build with `make` (devkitPro, needs
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

Like the Proxmark's `hf search` / `hf mf`, the root menu's Scan card identifies any ISO14443-A card
and opens it in its card type's tools; unsupported types get a generic info screen. Each card type
is a `CardFamily` (`source/app.h`: match on ATQA/SAK, probe, card screen, menu) listed in
`families[]` in `source/app.c`, with its screens in its own file. MIFARE Classic (`source/mfui.c`,
`source/editor.c`):
- Scan card (assumes Classic): type, UID, ATQA/SAK, magic generation (Gen1a, Gen4 GTU, USCUID)
  and the GTU / USCUID config. Y edits the GTU config (UID length, card type, shadow mode; guarded, see `mfc.h`).
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

MIFARE Ultralight / NTAG (`source/mfu.c`, `source/mfuui.c`, `source/mfuedit.c`), any SAK 00 card:
- Scan card: type from GET_VERSION (Ultralight EV1, NTAG210-216; without it Ultralight, Ultralight C,
  NTAG203), originality signature, counters and tearing flags, BCCs, lock bits, OTP / NDEF capability
  container, password config (AUTH0, PROT, CFGLCK, AUTHLIM) when readable.
- Read card: every readable page; a password-protected area stays unread. Saved as
  `sdmc:/nfcprobe/mfu/<UID>.bin` in pm3's `hf mfu` dump format (56-byte header: version, signature,
  counters), unread pages listed in `<UID>.txt`, and opened in the page editor.
- Saved dumps (pm3 .bin dumps work too), page editor: one page per row with its role, the page under
  the cursor decoded. X writes a page, or every user page that differs, to the card on the reader.
  Only user memory is ever written to a real card: lock bits and OTP are one-way, config can lock it.
- Clone onto magic card: a Gen4 GTU (password 00000000) is switched to Ultralight mode for the dump's
  type and becomes a full copy (UID, version, signature, password, every page), read back as a reader
  would. Writing a Classic dump onto a GTU in Ultralight mode switches it back to Classic.

Smart cards (`source/iso7816.c`, `source/scard.c`, `source/scui.c`): any ISO14443-4 card that isn't a DESFire
(the DESFire family passes it on: `FAMILY_PASS` in `source/app.h`).
- Scan card: ATS, the GlobalPlatform security domain's CPLC and card recognition data, and every applet from
  `scApplets[]` (`source/scard.c`) or `sdmc:/nfcprobe/smartcard/aids.txt` ("AID name" per line) that answers SELECT.
  An applet with a tool opens it; the others show their SELECT answer.
- APDU console: APDUs typed in hex (system keyboard), 61xx collected, the session kept between commands.
- GlobalPlatform (`source/gp.c`, `source/gpui.c`): SCP03 with C-MAC. Keys (default 404142..4F, then
  `sdmc:/nfcprobe/gp/keys.txt`) are checked against the INITIALIZE UPDATE card cryptogram first; EXTERNAL
  AUTHENTICATE (counted by the card) only goes out with a key that matched. Lists the ISD, applets / domains and
  packages, deletes them, installs CAP files from `sdmc:/nfcprobe/cap/` (zip, stored or deflated: `source/zip.c`).
- YubiKey OATH (`source/oath.c`, `source/oathui.c`): TOTP / HOTP codes, touch accounts, password (PBKDF2,
  asked when set), add / delete accounts, set / remove the password. The 3DS clock has no time zone: the UTC
  offset is a setting (`sdmc:/nfcprobe/oath.txt`). Works with ykneo-oath on a JavaCard (`ant oath` in javacard/).
- A new applet tool: a screen file, its open function in `app.h`, an entry in `scApplets[]`.

- Chip info: reset / init / patch version.

`sim/` builds the UI for the PC with fake citro2d / libctru and mock cards, renders every screen to
PNG and checks the text for overflows and overlaps (`make -C sim run`, see `sim/README.md`).

Card jobs keep the chip, so the network side can carry on with the loaded monitor.

Network: with wifi up, the app listens on TCP 8020 (address shown on the top screen) and
exposes raw takeover / power / I2C / GPIO primitives, plus the app's card operations
(`scan`, `mfread`, `mfdump`, `gen1awrite`, `mfwrite`, `mfudump`, `mfuwrite`, `mfuclone` in `tools/nfcnet.py`;
ops 0x10-0x1F and 0x22 in `source/netsrv.c`; `mfwrite` is an encrypted Mifare Classic write, `mfuwrite` an Ultralight
user page write, both WRITE THE CARD).
`nfcnet.py HOST put LOCAL [sdmc:/nfcprobe/...]` copies a file onto the SD card (CAP files go to `cap/`).
`nfcnet.py HOST shot [OUT.png]` grabs the top screen and `nfcnet.py HOST keys a down ...` presses
buttons (ops 0x20/0x21, served even while a job holds the chip). Drive it from the PC with
`tools/nfcnet.py HOST probe|spd FILE.ncd|send HEX...|release`, or import `Nfc` from it.
