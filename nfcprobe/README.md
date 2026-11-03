# nfcprobe

Mifare Classic and Ultralight / NTAG tool for the New3DS NFC controller (BCM20791). Build with `make` (devkitPro, needs
citro2d), run the .3dsx from the Homebrew Launcher. NFC is handed back to the system on exit (START).

Two builds: `make` is the debug build (`nfcprobe.3dsx`: the network server below, the log appended to
`sdmc:/nfcprobe.log`). `make release` builds `nfcprobe-release.3dsx` (in `build-release/`) without the
network server and without the log file: the log stays in RAM (the last 2000 lines) and Y on the Log
screen saves it to `sdmc:/nfcprobe/logs/<console time>.log`, as it does in the debug build.

The app loads its own chip patch (chip/reader.c, embedded as `data/reader_ncd.bin`, rebuilt by
`make` in `chip/`) and drives the RF framer through it: raw ISO14443A with our own parity and
Mifare Classic Crypto1 (`source/mon.c`, `source/mfc.c`, `source/crypto1.c`).

`data/` is not in git; populate it before building the app by running `make` in `chip/`
(builds `data/reader_ncd.bin`). No Nintendo or Broadcom files are needed: `tools/mkpatch.py`
generates the whole patch (header, a 4-instruction AON thunk into ROM, our SRAM image).

The UI is on the top screen and driven by buttons only: a card on the reader covers the whole
bottom screen, which just mirrors the log (SELECT shows it on top). Card
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
- Saved dumps: open in the editor, delete; X has the dump's card actions (card info, write onto a magic card,
  emulate the card or its UID, add its keys to the dictionary), the same as in the editor. Foreign `.bin` dumps work too.
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
  the cursor decoded. X writes a page, or every user page that differs, to the card on the reader, and has the
  same card actions as the saved dumps list (clone, emulate the card or its NDEF message, Amiibo).
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

Card emulation (`source/emu.c`, `source/emuui.c`): the 3DS as an ISO14443-A card through the ROM's NCI
listen mode (anticollision, RATS / ATS and ISO-DEP in the chip; each APDU answered by the app as NCI DATA).
- NDEF tag: an NFC Forum Type 4 tag (T4T 2.0: NDEF application, CC file E103, NDEF file E104) with a URL,
  a text or an empty message, the message of a saved Ultralight / NTAG dump, or the one on the NDEF screen.
  Writable: what a reader writes with UPDATE BINARY shows up on the screen.
- UID: any 4, 7 or 10-byte UID with its ATQA and SAK, typed, copied from a scanned card or from a saved
  Classic dump. Anticollision only (readers that check nothing but the UID).
- Ultralight / NTAG: a saved dump as the card itself ("Emulate this card" in the saved dumps), answered by
  our own chip image (`chip/emu.c`, loaded instead of the reader image: no WTX outside ISO-DEP, the host is far too
  slow for a READ). READ, FAST_READ, GET_VERSION (made up from the page count for dumps without one),
  READ_SIG, READ_CNT, PWD_AUTH (the dump's password if it has one, else any), WRITE / COMPATIBILITY WRITE.
  Ultralight C: its 3DES AUTH with the dump's key (or the factory key). What readers wrote can be saved as a
  new dump afterwards. No AUTH0 protection.
- MIFARE Classic Mini / 1K / 2K / 4K: a saved dump the same way, Crypto1 on the chip (AUTH, nested AUTH, READ,
  WRITE, HALT). The encrypted answers go out with their encrypted parity, as raw 9-bit frames (NOTES.md:
  listen-mode parity). Classic and Ultralight each have their own chip image (chip/emu.c built twice); a 2K /
  4K's blocks past 63 live in chip RAM the ROM leaves alone while listening.
- DESFire: a saved info file (DESFire > Saved cards; `Save info` on the card screen writes them), answered by
  the host (`dfemu.c`): GetVersion, application / file IDs, key settings and versions, file settings, the file
  contents the scan read (standard, backup, value, records), free memory, signature, DF names, GetCardUID.
  Authentication with the keys the file has, all three kinds: legacy D40 (DES / 2K3DES), EV1 (AES, ISO 2K3DES /
  3K3DES) and EV2 (AES, First and NonFirst), then MAC'd or encrypted answers as a real card. Readers may write
  (data, records, credit / debit, with the file's keys and comm mode; transactions commit as on a card); on stop
  the app offers to save the result as a new info file. pm3's `hf mfdes info`, `lsapp`, `read`, `auth` work.
- After a reader drops its field the chip listens again by itself 1 ms later (`chip/rearm.h`, in every chip
  image), so readers that reselect quickly (pm3 command chains, `hf mfdes info`) find the card again.
- APDU log: an empty ISO-DEP card answering from `sdmc:/nfcprobe/emu/apdu.txt` ("<command prefix>
  <response>" in hex per line, first match wins, else 6A82 for a SELECT / 6D00), every APDU appended to
  `sdmc:/nfcprobe/emu/apdu.log`.
- A phone reads it with a quick tap on the bottom screen. A Proxmark only gets it with the 3DS lying on it,
  bottom screen down. A new APDU card type is an `EmuApdu` handler passed to `emuRun`; one that needs
  answers within the frame delay goes into `chip/emu.c` (the ROM's listen-A RX hook, see NOTES.md).

- Chip info: reset / init / patch version.

The saved dump lists (`source/dumplist.c`) read the directory in batches and cache each file's date: a stat or a
date costs ~20 ms per file on the SD card. Both are scanned in the background at start.

`sim/` builds the UI for the PC with fake citro2d / libctru and mock cards, renders every screen to
PNG and checks the text for overflows and overlaps (`make -C sim run`, see `sim/README.md`).

Card jobs keep the chip, so the network side can carry on with the loaded monitor.

Network (debug build only): with wifi up, the app listens on TCP 8020 (address shown on the top screen) and
exposes raw takeover / power / I2C / GPIO primitives, plus the app's card operations
(`scan`, `mfread`, `mfdump`, `gen1awrite`, `mfwrite`, `mfudump`, `mfuwrite`, `mfuclone` in `tools/nfcnet.py`;
ops 0x10-0x1F and 0x22 in `source/netsrv.c`; `mfwrite` is an encrypted Mifare Classic write, `mfuwrite` an Ultralight
user page write, both WRITE THE CARD).
`nfcnet.py HOST put LOCAL [sdmc:/nfcprobe/...]` copies a file onto the SD card (CAP files go to `cap/`).
`nfcnet.py HOST shot [OUT.png]` grabs the top screen and `nfcnet.py HOST keys a down ...` presses
buttons (ops 0x20/0x21, served even while a job holds the chip, as is the ping every client starts with). Drive it from the PC with
`tools/nfcnet.py HOST probe|spd FILE.ncd|send HEX...|release`, or import `Nfc` from it.
