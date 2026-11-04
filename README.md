# Prox3DS

A Proxmark-style NFC tool for the **New Nintendo 3DS**: it reads, attacks, clones and emulates HF
(13.56 MHz) cards with the console's built-in NFC reader. You don't need to open the console or add any hardware.

Prox3DS loads its own firmware patch into the 3DS's NFC controller (a Broadcom BCM20791) and drives the
radio directly. That gives it raw ISO14443-A frames, Crypto1, card emulation and ISO15693, none of which the
system's NFC service offers.

## Download

**[Latest release](https://github.com/Doridian/Prox3DS/releases/latest)**: get `Prox3DS.3dsx`.

Every version is listed on the [releases page](https://github.com/Doridian/Prox3DS/releases).
CI builds them from the repository's tags. Each release has two files:

| File | For |
| --- | --- |
| `Prox3DS.3dsx` | Everyone. The normal build. |
| `Prox3DS-debug.3dsx` | Development: also runs a TCP debug server on port 8020 and writes a log file to the SD card. |

## Requirements

- A **New 3DS, New 3DS XL or New 2DS XL**. These models have the NFC reader built in (under the bottom
  screen). The original 3DS / 3DS XL / 2DS used an external NFC adapter, which isn't supported.
- **Luma3DS** custom firmware and the **Homebrew Launcher**. Prox3DS stops the system's NFC service
  while it runs and gives the reader back when you exit.
- Optional: Wi-Fi, used to download key dictionaries and the Amiibo figure list.

## Install

1. Copy `Prox3DS.3dsx` to `sdmc:/3ds/` on the SD card.
2. Start it from the Homebrew Launcher.
3. Put a card on the bottom screen, roughly in the middle of the touch screen, where the reader is.

Prox3DS creates `sdmc:/prox3ds/` on first start and keeps everything there (see [Files](#files-on-the-sd-card)).

## Controls

| Button | Action |
| --- | --- |
| D-Pad | Move through menus and editors |
| A | Select / edit |
| B | Back, or stop a running card operation |
| X | Actions for the current dump or card |
| Y | Extra actions where the screen shows them (e.g. save the log) |
| SELECT | Show the log on the top screen |
| HOME | Touch lock: the bottom screen shows only the log and ignores touches (a card on the reader can register as taps) |
| START | Give NFC back to the system and quit |

The whole UI is on the top screen and works with buttons only. The bottom screen holds the card, so it just
mirrors the log. Every menu entry has a help line. **Anything that writes to a card asks for
confirmation first.**

## Features

**Scan card** identifies any ISO14443-A card and opens the right tools for it, like the Proxmark's `hf search`.

### MIFARE Classic (Mini / 1K / 2K / 4K)
- Card info: UID, ATQA/SAK, magic card type (Gen1a, Gen2 / CUID, Gen4 GTU, USCUID) and the GTU / USCUID config.
- Read card with key recovery:
  - the key dictionary (built-in defaults, your own `mfc/keys.txt`, or pm3's ~2500-key list downloaded over Wi-Fi)
  - magic-card backdoors
  - **nested** and **static nested** attacks, and the **FM11RF08S** static encrypted nonce (backdoor) attack
  - **darkside** for cards with no known key
- Dump editor: hex + ASCII per sector. The block under the cursor is decoded (manufacturer block, BCC, keys,
  access conditions, value blocks), and access conditions are edited bit by bit.
- Write single blocks to a card, or write whole dumps onto magic cards. Gen4 GTU config editing and
  password are guarded.
- Opens foreign `.bin` dumps (pm3 and others) too.

### MIFARE Ultralight / NTAG
- Ultralight, Ultralight EV1, Ultralight C, NTAG203, NTAG210-216 and other Type 2 tags.
- Card info: type, NXP originality signature check, counters, tearing flags, lock bits, OTP, NDEF capability
  container, password configuration.
- Read with a password (PWD_AUTH), or with the 3DES key on an Ultralight C. Dumps use pm3's `hf mfu` format.
- Page editor. Write user memory back to a card. Clone onto a Gen4 GTU as a full copy (UID, version,
  signature, password, every page).
- Tear-off: cuts the field N µs into a write (like pm3's `hw tearoff`).

### MIFARE DESFire (EV1-EV3, Light)
- Everything the card shows without a key: version, storage, free memory, originality signature, key settings,
  applications and files (like pm3's `hf mfdes info` / `lsapp`).
- Authentication (legacy DES/2K3DES, EV1 AES/3DES, EV2) with a key dictionary. Protected files are read
  with secure messaging.
- Save the card's info to emulate it later.

### HID iClass / PicoPass
- Key search with the standard and elite dictionaries (pm3's, downloadable), or one key you type.
- Full dump and the decrypted Wiegand credential (with `iclass/iclass_decryptionkey.bin`).

### Smart cards (any other ISO14443-4 card)
- ATS, GlobalPlatform card data (CPLC), and which known applets the card has (OpenPGP, PIV, FIDO, EMV,
  passports, YubiKey, ...; add your own AIDs in `smartcard/aids.txt`).
- **APDU console**: type APDUs in hex. The session stays open between commands.
- **GlobalPlatform**: SCP03 authentication (the key is checked against the card cryptogram before the
  counted EXTERNAL AUTHENTICATE), list / delete applets and packages, install `.cap` files.
- **YubiKey OATH**: TOTP / HOTP codes, touch-required accounts, password, add / delete accounts.
- **FIDO U2F / FIDO2** security keys: versions, options, AAGUID, PIN retries (read only).
- **EMV payment cards**: card number, expiry, counters and the transaction log. Read only: nothing is paid
  or signed.

### Card emulation: the 3DS as a card
- **NDEF tag**: a URL, a text or an empty writable tag. A phone held to the 3DS opens it, or writes to it.
- **UID**: answer with any 4/7/10-byte UID, ATQA and SAK, typed in or copied from a card or dump.
- **MIFARE Classic** (Mini-4K) from a saved dump, with Crypto1 running on the NFC chip.
- **Ultralight / NTAG / Ultralight C** from a saved dump. What a reader writes can be saved afterwards.
- **DESFire** from a saved info file, including authentication (D40, EV1, EV2) and writes by the reader.
- **Java Card applets**: a Java Card VM on the 3DS runs `.cap` applets and emulates the card.
- **APDU log**: an empty smart card that logs every APDU a reader sends and answers from a rule file.

A phone reads the emulated card with a quick tap on the bottom screen. A Proxmark needs the 3DS lying on
it, bottom screen down.

### Amiibo
- Read and decrypt Amiibo (figure, owner, nickname, game data) with **this console's own keys**: no key
  files to find.
- Copy an Amiibo onto a blank NTAG215, or create a new one from the figure list (downloaded from
  AmiiboAPI over Wi-Fi).

## Files on the SD card

Everything lives under `sdmc:/prox3ds/`:

| Path | Contents |
| --- | --- |
| `mfc/` | MIFARE Classic dumps in `dumps/` (`<UID>.bin` + `<UID>.keys.txt`, never overwritten); `mfc/keys.txt`: your keys, one per line |
| `mfu/` | Ultralight / NTAG dumps (pm3 `hf mfu` format); `mfu/keys.txt`: your passwords / UL-C keys |
| `iclass/` | iClass dumps, dictionaries, `iclass_decryptionkey.bin` |
| `smartcard/aids.txt` | Extra applets to look for: `AID name` per line |
| `gp/keys.txt` | Extra GlobalPlatform keys |
| `cap/` | `.cap` files to install onto cards or run in the Java Card VM |
| `oath.txt` | Your UTC offset for OATH codes (the 3DS clock has no time zone) |
| `emu/` | `apdu.txt` (APDU log answers) and `apdu.log` |
| `logs/` | Logs saved from the Log screen |

Dumps are plain files, so you can copy them to and from a PC and use them with a Proxmark.

## Notes and limits

- The 3DS's antenna is small and weak. Hold cards flat on the middle of the bottom screen and keep them
  still during long operations.
- Prox3DS only does HF (13.56 MHz). LF cards (125 kHz: EM4100, HID Prox, T5577) can't be read.
- Hardnested isn't implemented yet. Cards that are only open to it (hardened nonces and no known key) can't
  be cracked.
- Only use it on cards you own or are allowed to test.

---

## Development

### Building

You need [devkitPro](https://devkitpro.org/wiki/Getting_Started) with **devkitARM**, **libctru** and
**citro2d** (`3ds-dev`), plus Python 3.

```sh
make -C chip              # the NFC chip patches -> prox3ds/data/*_ncd.bin
make -C prox3ds           # debug build:   prox3ds/prox3ds.3dsx
make -C prox3ds release   # release build: prox3ds/prox3ds-release.3dsx
```

The chip must be built first: `prox3ds/data/` isn't in git. The build needs no Nintendo or Broadcom files.
`tools/mkpatch.py` generates the whole firmware patch from our own code in `chip/`.

The **debug build** writes its log to `sdmc:/prox3ds.log` and listens on TCP 8020 while Wi-Fi is up.
`tools/nfcnet.py HOST ...` uses that port to run card operations from a PC, copy files onto the SD card,
grab screenshots, press buttons and update the app in place. The release build has neither: its log stays
in RAM, and Log → Y saves it.

### UI simulator

`prox3ds/sim/` builds the UI for the PC with stand-ins for citro2d / libctru and mock cards. It renders
every screen to PNG and checks the text for overflows and overlaps. You don't need a 3DS:

```sh
make -C prox3ds/sim run   # -> prox3ds/sim/out/*.png + report.txt
```

### Repository layout

| Path | Contents |
| --- | --- |
| `prox3ds/` | The 3DS app (C, libctru + citro2d). [`prox3ds/README.md`](prox3ds/README.md) covers its architecture |
| `chip/` | Code that runs on the BCM20791 (Cortex-M): the reader monitor and the card emulation images |
| `tools/` | Python: patch builder, PC-side drivers, reference implementations (Crypto1, crapto1, attacks) |
| `tools/exp/` | One-off experiments from the reverse engineering |
| `javacard/` | Test applets for Java Card (built with ant-javacard) |
| `docs/` | Research notes ([`docs/NOTES.md`](docs/NOTES.md): how the chip, its ROM and the framer work), Ghidra scripts |

### Releases

Pushing a tag `v*` (e.g. `git tag v1.0.0 && git push origin v1.0.0`) makes CI build both versions and
publish them as a GitHub release, named `Prox3DS.3dsx` and `Prox3DS-debug.3dsx`. Every push to `main` also
builds both and keeps them as workflow artifacts.

## License

AGPL-3.0-or-later, see [`LICENSE`](LICENSE). Third-party work used here is credited in [`CREDITS.md`](CREDITS.md).
