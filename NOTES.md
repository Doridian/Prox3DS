# New 3DS NFC RE notes

## Inputs
- `0004013020004002` New3DS `nfc` sysmodule (v21 / "0201builder"), decrypted CXI. NOTE: at runtime it runs as
  program ID `0004013000004002` (same for gpio 1B02 / i2c 1E02), so PM calls must use that ID
- `0004013020001E02` New3DS `i2c` sysmodule (v3), decrypted CXI
- Unpack: `python3 tools/ncch.py <cxi> extracted/<tid>` (exheader + decompressed .code)

## nfc sysmodule
- .code loads at 0x100000: text 0x100000 (0x34a64), ro 0x135000 (0x41e0), data 0x13a000 (0x149c), bss 0x2cc00
- Services: cfg:s, fs:USER, gpio:NFC, hid:NFC, i2c::NFC, nwm::EXT, ps:ps, ptm:s
- Stack is Broadcom NFA/NCI (strings NFC_TASK, NFA_APP, NFC_HAL_TASK) = same codebase as
  AOSP external/libnfc-nci halimpl/bcm2079x -> use as reference for symbol recovery
- I2C framing: 1-byte HCIT prefix 0x10 + NCI packet (e.g. `10 20 00 01 01` = CORE_RESET_CMD)
- ro has amiibo key material ("unfixed infos" / "locked secret") + AES tables at ~0x355b0..0x36080

## Host <-> controller wiring (from nfc .code, Ghidra project ghidra/proj)
- I2C: i2c::NFC device 15. Write = cmd 0x14 WriteDeviceRaw(dev, size, static buf id1) (FUN_00109e88),
  Read = cmd 0x15 ReadDeviceRaw(dev, size) -> static buf id0 (FUN_00106240). Both chunked to <=0x100.
- Receive path is AOSP nfc_hal_nci_receive_msg style: read HCIT+3-byte header, then exactly payload len.
- gpio:NFC init (FUN_0011dce4): 0x2000 out, set low; 0x1000 out; 0x10000 in + interrupt (SetRegPart2,
  SetInterruptMask, BindInterrupt prio 8).
  - 0x2000 = UPIO pin 1 = REG_PU: boot (FUN_00100c84) drives high then sleeps 50 ms; shutdown (FUN_00102f14) drives low
  - 0x1000 = UPIO pin 2 = NFC_WAKE: set via nfc_hal_dm_set_nfc_wake (FUN_0011b5a0), level = active_mode != cmd
    (AOSP default active-low -> low = asserted)
  - 0x10000 = IRQ from controller
- UPIO-style setter FUN_0011d420(pin, level) -> GPIO cmd 0x8 SetGPIOData(value, mask) (FUN_0011d214)

## Controller patchram
- Chip name table at ro 0x36304: 20791B3, 20791B4, 43341B0, ... -> controller is BCM20791
- Two Secure Patch Download (SPD) sets, pre-framed as `10 2F 2E <len> <type> ...`
  (NCI GID_PROP / OID 0x2E = NCI_MSG_SECURE_PATCH_DOWNLOAD):
  - .code+0x36339 .. 0x37349 -> `extracted/patch_20791B4.ncd` (4112 B)
  - .code+0x37360 .. 0x38805 -> `extracted/patch_20791B5.ncd` (5285 B)
- Segment type = payload[0]: 00 header (chip ver string), 01 SRAM, 02 AON, 03 patch table, 04 secure patch table, 06 signature
- **Signature segment (type 06, 48 bytes = ECDSA-P192 r||s sized) is ALL ZEROS in both sets**
  -> strong hint the controller does not enforce patch signatures. Unconfirmed until tested on HW.
- Per AOSP HAL: controller verifies sig itself (SPD_ERROR_INVALID_SIG), and COMMITS the patch to its NVM.
  Host compares via GET_PATCH_VERSION (2F 2D) and only downloads on mismatch.
  => a bad patch persists across reboots; risk of bricking the NFC controller (soldered).

## Taking over from homebrew (nfcprobe/)
- PMAPP_TerminateTitle(0004013000004002) returns 0 but nfc keeps running; svcTerminateProcess on its PID works
- Killing nfc leaves its event bound to the IRQ pin in gpio -> gpio crashes (D8E007F7 @ 0x1009a8) when it fires.
  nfcprobe masks the IRQ, unbinds, and binds its own event first.
- With REG_PU held low (pins swapped in first attempt) every I2C xfer fails F9602FEF (NACK)

## Live controller (first successful probe)
- Power-up NTF `60 00 02 00 01`; CORE_RESET_RSP NCI 1.0; CORE_INIT: manuf 0x2E (Broadcom), info 00 15 0D 46,
  ifaces 00 01 02 03 81 84 83 (0x83 = ISO15693 per AOSP brcm defs, from memory), max ctrl payload 255
- GET_PATCH_VERSION after our power cycle: chip "20791B5", ver 0.0 -> the module's boot-time patch did NOT
  survive a REG_PU cycle => patch looks RAM-only (to be confirmed by loading it ourselves)
- IRQ high = packet pending; reading with nothing pending returns FF FF FF FF
- Module patch descriptors (FUN_00106c2c -> PRM download start): 16-byte AOSP patchfile header right before
  each record chain: B4 @0x136329 (proj 0x0203, ver 48.55), B5 @0x137350 (proj 4, ver 11.64 = 0x0B.0x40),
  1 FPM patch each, len 0x1010 / 0x14A5
- Stock B5 patch load (job B, 2026-10-29): all 24 records -> status 0; after the sig record
  NTF 6F 2E 01 00 (auth OK) then CORE_RESET_NTF 60 00 02 00 01. GET_PATCH_VERSION then reports
  proj 0004, ver 11.64 (0B 00 40 00), plus extra word 0x13D0 at p[30..31] (0 unpatched).
  After REG_PU cycle: back to 0.0 => CONFIRMED RAM-only, no NVM commit on this board.
- Signature-test bytes in patch_20791B5.ncd: 0xA44 = SRAM 0x3BB36 (padding after pop, never run), 0x1475 = sig[0]
- Jobs X and Y (2026-10-29): BOTH accepted -- every record status 0, auth NTF 6F 2E 01 00, ver 11.64, gone
  after power cycle. => no signature/integrity check on SPD patches on this chip. Custom RAM patches possible.
  (Not yet proven the modified byte lands in RAM -- needs a memory read.)

## Patch format details (tools/bcmpatch.py)
- SRAM (01) / AON (02) streams begin with a Thumb entry ptr; load = (entry & ~1) - 4
  - B4: SRAM 0x03b934..0x03c3c4, AON 0x068004..0x068444
  - B5: SRAM 0x03b80c..0x03c530, AON 0x068008..0x068600
- Hook table (03): N ROM *word* addresses, enable mask ((1<<N)-1), N replacement words (mostly Thumb BL
  into the patch, some raw instruction replacements). B4: 13 hooks, B5: 22 hooks.
- Implied chip map: ROM at 0x0 (hooks up to 0x1da38), RAM 0x03xxxx (patch at top ~0x3b800+), AON 0x068xxx,
  other refs to 0x05xxxx, 0x07000000, 0x07c00000, 0x0849xxxx (likely MMIO, unconfirmed)
- Ghidra project ghidra/chip (Cortex-M Thumb), one program per segment, functions seeded at entry + hook targets.
  Hook handlers are mid-function trampolines into ROM -> need a ROM dump to get much further.

## Open questions / next steps
- Disassemble patch type-01 segments (Thumb, chip addrs 0x03xxxx RAM / 0x05xxxx) -> chip memory map
- Find gpio:NFC usage (reset/power line) and the patch version compare logic in nfc .code
- Safe first HW test: nfcprobe/ (stop nfc module, power-cycle, CORE_RESET/INIT + GET_PATCH_VERSION only)
- Get a ROM dump. Attempt 1 (nfcprobe job R): BT HCI VSC Read_RAM 0xFC4D over HCIT 0x01
  (01 4D FC 05 addr32 len8 -> 04 0E .. 4D FC status data), no patch needed; dumps 0..0x40000 and AON
  to sdmc:/nfc_rom.bin / nfc_aon.bin, then validates by reading the stock patch back at 0x3B80C.
  RESULT: chip answers BT HCI over HCIT 0x01 (04 0E 04 01 4D FC 01) but Read_RAM = status 01
  (unknown command). BT HCI path exists, Read_RAM doesn't.
  Next: tiny custom SPD patch that exfiltrates memory (patch header record holds RAM ptrs 0x3B590/0x3B598,
  chipver string + version are reflected by GET_PATCH_VERSION).
- (answered: patch is RAM-only) Are there NCI_MSG_EEPROM_RW / memory read/write vendor cmds?

## Network control (nfcprobe/source/netsrv.c, tools/nfcnet.py)
TCP 8020, request op u8 + len u16 + payload, reply op u8 + result u32 + len u16 + payload.
Ops: 0 ping, 1 takeover, 2 power (0 off / 1 cycle), 3 i2c write, 4 read packet (u16 ms),
5 write+read, 6 gpio (value, mask), 7 release. Button jobs release a network-held chip first.

## Custom patches and ROM dump (chip/, tools/mkpatch.py, tools/dumpchip.py) -- 2026-10-29
- Unsigned custom patches work. Layout rules learned the hard way:
  - SRAM init is entered at load+4 (right after the entry word), NOT via the entry pointer.
  - Init must return 0; nonzero => chip goes silent after auth (no CORE_RESET_NTF).
  - Hook table may be empty (payload = 4-byte mask 0). Stock header + stock AON segment reused.
  - Header chip-version string is free-form and echoed by GET_PATCH_VERSION.
  - GET_PATCH_VERSION payload bytes 0..19 are read live from RAM 0x3B7A8 (proj, ?, chipver[16]);
    RAM global 0x38A70 -> 0x3B7A0. Last field of the response = total patch size.
- Core: Cortex-M3 vector table (MemManage/BusFault/UsageFault/DebugMon), only 8 external IRQs.
  BUT SCS (0xE000E000..) reads all zero: no DWT/FPB/SysTick regs visible. Build patches as plain Thumb (M0).
- ROM exception stubs jump via RAM table at 0x38000 (vector layout: DebugMon 0x38030, SysTick 0x3803C,
  IRQ0..7 0x38040..). SysTick/fault stubs push {lr} first, IRQ stubs don't.
- Last received NCI command sits at RAM 0x3AF05 (GKI-ish buffers, payload at addr = 1 mod 4).
  GET_PATCH_VERSION ignores extra payload; unknown proprietary OID -> status 05.
- dumper4: wraps SysTick+IRQ0..7, scans 0x3A001..0x3B590 step 4 for "2F 2D 07 sess seq16 addr32",
  fills 0x3B7A8 with [addr][16 bytes]. Fill lags one request; pipelined over TCP ~2.8 KB/s.
  Pipelining can tear a chunk -> dump reads twice and re-reads disagreements.
- ROM: 128 KB at 0x0, mirrored at 0x20000 (up to 0x38000). RAM 0x38000..; initial SP 0x3A374, reset 0x61.
  "Copyright (c) Broadcom Corp. 2011 BCM20791B0 (r) NFC Firmware", built "Dec 22 2012".
  dump/rom_20791B5.bin sha256 258ab0fc63a43a7c83da54fa66e464365a7af025c56d0b721217ad24e47f6424
  (two full passes identical). dump/ram_38000_40000_dumper4.bin = RAM with dumper4 loaded.
- BT HCI (HCIT 01) is parsed (Read_RAM 0xFC4D -> status 01 unknown cmd).

## ROM: NCI command path, debug monitor (chip/memrw.c, tools/chipmon.py) -- 2026-10-29
- NCI command dispatcher 0x189A2(msg): msg = [MT|PBF|GID][OID][len][payload].
  index = base[gid] (bytes @0x1F3EC) + oid, must be < 0x4C, gid valid flag @0x1F3DC, else reject.
  Then the patch-mode filter 0x3742 (during download only CORE_RESET/INIT, 2F/04, 2F/2D, 2F/2E pass),
  then RAM hook *(0x38718)(msg) (ROM never writes it; nonzero return = consumed),
  then handler table @0x1F3FC (u32 Thumb ptrs). 0x1898C = reject (status 05).
- Response API: 0x188C2(total_len incl. 3-byte hdr, mt) -> pkt (hdr[0] = mt<<5, hdr[2] = len-3),
  0x188E4(pkt) sends (first calls RAM hook *(0x38714)(pkt), nonzero = consumed).
  0x19F88(status, gid, oid) = status-only response. 0x1E6D6 = memcpy(dst, src, n).
- GET_PATCH_VERSION handler 0x3B56. Patch state struct at 0x38A00 (+0x6C -> 0x3B7A0 header copy).
- Implemented 2F OIDs (Broadcom names): 00 TAG_SET_MEM, 01 TAG_GET_MEM, 02, 04 GET_BUILD_INFO, 05, 06,
  08, 09 FRAME_LOG, 0C, 10, 11, 16, 17, 18, 19, 1C, 1D, 1F, 20, 21, 22, 23, 27, 29 EEPROM_RW,
  2D, 2E, 2F, 30, 31. Proprietary RF interfaces from CORE_INIT: 81 84 83 (no 0x80 MIFARE interface).
- Debug monitor memrw: hooks 0x38718, answers 2F 2C (op, addr32, ...): read8/write8/call/read32/write32,
  replies 4F 2C status + data. ~17 KB/s pipelined (vs 2.8 KB/s for dumper4), verified against the ROM.
  Build note: -fno-jump-tables (switch would pull in libgcc __gnu_thumb1_case_uqi).

## RF framer + raw ISO14443A (tools/rfpoll.py, tools/rawa.py, memrw ops 5/6) -- 2026-10-29
- RF_DISCOVER (21 03) is rejected (01) until RF_DISCOVER_MAP (21 00) sets RAM 0x3872C.
  Map T2T+ISO-DEP -> Frame: 21 00 07 02 01 01 04 01 01; poll NFC-A: 21 03 03 01 00 01.
  Frame interface: chip adds CRC_A on TX, checks/strips it on RX, data RSP ends with a status byte.
  A CRC-less answer (Mifare AUTH nonce) is dropped -> 60 08 B2 (RF timeout).
- FRAME_LOG: set RAM 0x380A0 (TX) / 0x380A1 = 1 -> every frame as NTF 6F 09:
  dir(1=TX) | timer u32 (down-counting) | RF mode (0x85 A anticoll, 0x02 A data, FE timeout) | bytes | bits | data
- Framer registers (0x5C540..): 0x5C55C TX ctrl (ROM writes 0x88 before TX), 0x5C568 length code
  (bytes << 4 | extra bits), 0x5C56C cmd (1 before TX, 2 = after-TX in byte path), 0x5C570/574 mode
  (anticollision/raw mode = 0/1; data = 0/0), 0x5C594 bit0 TX busy, 0x5C5A0 RX byte count,
  0x5C58C RX extra bits, 0x5C588 RX status (bit 1 = no/bad CRC: 0x20 ok, 0x22 for 4-bit ACK/NAK
  and CRC-less frames). TX byte port 0x5C600, RX byte port 0x5C620 (each access pops; ROM uses
  the 4 word mirrors). Timer 0x5E024 counts DOWN at 1.0 MHz (75.5 ticks = 8 bits at 106 kbps).
- ROM primitives: 0x11DE(r570, r574, len) + 0x1280(buf, len) = bit-mode TX (REQA/anticoll/SELECT);
  0x1206(buf, n) = byte TX with RAM hook *(0x380E4); 0x1372 = RX done (hook *(0x380E0)(stage)).
- Framer ISR 0x197E, status 0x5C5C0: bit2 -> 0x15F2 (sub 0x5C5C4, filter *(0x380D4)),
  bit1 -> 0x1736 (sub 0x5C5D0 TX/RX, filter *(0x380D8); bit4 RX done, bit5 = RX timeout/no answer),
  bit0 -> 0x18FE (sub 0x5C5DC, filter *(0x380DC)). Sub-status registers are write-1-clear.
- Raw mode (memrw CAPTURE + TXRAW): filter 0x380D8 returns 0 so the ROM never sees our exchanges
  (else it times out, re-polls and the chip stops answering for seconds). In r574=1 mode frames go out
  exactly as given (no CRC) EXCEPT SELECT (93 70 ..) which the hardware CRCs. A lone full byte needs a
  padding byte in the FIFO (7-bit frames must not be padded). Writing cmd 0x5C56C from the RX
  interrupt makes the next TX hang the chip; write it at TX time instead. Rare hangs remain (TX right
  after a 4-bit answer); rawa.py reloads and resumes.
- Card on the 3DS (user's): UID C1C1C1C1, ATQA 0004, SAK 88, Mifare Classic 1K, Gen1a magic
  (40/7 -> 0A, 43 -> 0A). Full dump via backdoor: dump/card_C1C1C1C1.bin. Raw AUTH (60 00 + CRC)
  returns nt; nonces vary.
- Parity off (TX and RX): 0x5C560 = 0x08 (reads back 0 normally; ROM writes other values there).
  Found by bit-flip sweep (one bit at a time over 0x5C540-5C5BC, 5C640-5C6CC, 5C780-5C7BC; only hit
  of ~600, about half the flips hang the chip). With it, hand-packed READ 0 (bytes LSB first, each
  followed by its parity bit, code 0x44) is answered, and RX comes back as the raw stream with
  parity bits: 21 bytes for an 18-byte answer; 9-bit groups starting at bit 4 decode to block 0 with
  all parity and the CRC correct. Needed for Crypto1 auth ({nr}{ar} with encrypted parity); the
  ROM has no Crypto1.
  Earlier misses: r570 0..3 x r574 {0,1,2,3,4,5,8,9,0x10,0x11,0x20,0x21}, r55c {0x80,0x08}.

## Mifare Classic Crypto1 auth WORKS (tools/mfc.py, tools/crypto1.py, memrw op 7) -- 2026-10-30
- RX alignment with parity off: the RX stream starts at bit (TX bits % 8) -- READ (36 bits) -> 4,
  9-bit frame -> 1 -- except after 7-bit short frames (WUPA/REQA), which give 0.
- (WRONG, see "Encrypted WRITE works" below) ~~TX FIFO in parity-off bit mode holds 7 bytes~~: 21
  bytes written at once go out fine, no pacing needed. (Pace N=83 was also off: the timer is 1.0 MHz.)
- Data mode (r574=0) with length code 0 appends a HW CRC; with an explicit code it does not.
  SELECT (93 70) is CRC'd by HW in both modes.
- Length codes >= 0x80 do odd things (0x90 gives a short frame). The 72-bit {nr}{ar} (9 FIFO bytes)
  goes out with code **0x78** in bit mode (r574=1), paced or not. Found by sweeping 0x78-0xFF;
  0x88/0x90/0x00/0x87 never got an answer.
- memrw op 7 AUTH does the whole 3-pass auth on-chip (host round trip ~200 ms is too slow): sends
  the AUTH frame, decodes nt (offset 4), runs Crypto1 (key, uid^nt), sends {nr}{ar} with encrypted
  parity ~0.9 ms later and returns nt + the cipher state (odd/even). addr = pace<<16 | r574<<8 |
  code for the {nr}{ar} TX (default 0x188 -- use 0x178). The host continues with tools/crypto1.py
  (crapto1 port, checked against the mfkey64 example trace and against the chip state).
- Verified on the Gen1a card (tools/exp/auth.py HOST KEY BLOCK 178): {at} decrypts to suc96(nt),
  encrypted READ answers with correct CRC: block 0 (key FF..), block 4 (sector 1 key A
  c1c1c1000001), block 8 (sector 2 key c1c1c1000002).

## "Chip stalls" were lost replies (host side) -- 2026-10-30
- The periodic "unexpected answer: (nothing)" stalls (every ~5-15 s, also with the chip idle and no RF
  traffic, framer IRQ log empty) are not chip hangs: the request is executed (a WRITE8 lands), only
  the reply never reaches the host, and the next request is answered at once. Reloading the
  monitor on every such timeout was what made dumps slow and flaky.
- The IRQ pin (gpio 0x10000) is a reliable "packet pending" signal: 0 idle, 1 once the reply is
  queued, 0 after it is read. nciRecv used to read blind (immediately, then every 20 ms); a read
  racing with the chip queueing a packet loses that packet. nfcprobe now reads only while IRQ = 1.
- Mifare wrong-key auth (card silent after {nr}{ar}) does not hang the chip by itself.
- Result with IRQ-gated reads (nfcprobe, net ops 0x10-0x14): no stalls at all. Full 1K dump with
  the 3 known keys in 3.8 s (was minutes); ~280 wrong-key auths (defaults only) in 16.7 s, ~60 ms
  each. Data blocks match the Gen1a backdoor dump; trailers differ only in key B (not readable).
- Exit path (START): release pins/IRQ, then PMAPP_LaunchTitle(nfc 0004013000004002) -> 0, HOME
  menu fine afterwards. Without the release, gpio dies on exit (HOME/sleep are blocked while running).

## Mifare Classic WRITE: backdoor works (encrypted: see next section) -- 2026-10-30
- WRITE is two-phase: `A0 block`+CRC -> 4-bit ACK (0x0a), then 16 data + CRC -> 4-bit ACK. The data
  frame is 18 bytes = 162 bits (with parity), i.e. 21 FIFO bytes in parity-off packing.
- The `A0` command ACKs fine in every mode. The 18-byte DATA frame is the problem.
- Bit-mode length register 0x5C568 is two 3-bit fields: byte count [6:4] (max 7), extra bits [2:0]
  (max 7) -- confirmed by write/readback: 0x90->0x10, 0x142->0x42, 0xABC->0x34, 0xFFFF->0x77,
  0x1F2->0x72. ROM 0x1280 splits the code the same way (r4=(code>>4)&0xF, r5=code&0xF). The known
  codes fit code=13*N+16 (READ N=4 ->0x44, {nr}{ar} N=8 ->0x78); N=18 -> 0xFA, in the ">=0x80 does
  odd things" zone. Swept code 0x00-0x1FF x prefill 1-6 x pace 68-200 ticks: the card never answers
  the 18-byte bit-mode frame (not even a NAK). The parity-off bit-mode FIFO (7 bytes) + saturating
  length field cannot send a 162-bit frame.
- (SUPERSEDED) ~~ENCRYPTED writes are blocked by the chip~~ -- they work with mixed-parity frames,
  see the next section. OP_MFWRITE and a wider length code were tried and dropped.
- Gen1a BACKDOOR write is plaintext (no crypto), so it uses DATA mode (r574=0): the HW frames whole
  bytes, adds parity+CRC (length code 0), and streams the frame through the deeper data-mode FIFO --
  no 7-byte limit. Sequence: gen1a unlock (40/43), `A0 block` data-mode (ACK 0x0a), 16 data bytes
  data-mode (ACK 0x0a). Verified on the card: wrote a test block, read it back, restored the
  original, all exact. Also note the backdoor WRITE (unlike auth) tolerates a host round-trip
  between the command ACK and the data frame, so it needs no on-chip op.
- Host/app: tools/rawa.py gen1a-write BLK HEX32 (prototype); app mfc.c mfGen1aUnlock / mfGen1aWrite,
  net op 0x15 OP_GEN1A_WRITE (block u8, data[16]; verifies by reading back), tools/nfcnet.py
  gen1awrite. Data-mode TX helper: monTxraw(data, len, 0, 0, 0 /*r574*/, 0x88, 0).

## Encrypted WRITE works: mixed-parity frames (tools/exp/mixedparity/) -- 2026-10-30
Measured with an experimental monitor op (memrw_auth.c op 8 TXTIME: TX, then timed register stores
while polling TX busy 0x5C594 bit 0; busy time = on-air bits * 9.44 ticks + ~2.4 bits SoF/EoF).
- The TX FIFO is deep (>= 21 bytes, both modes); data mode and bit mode time identically, same path.
- Frame length = FIFO contents. [2:0] of 0x5C568 = bits of the last byte, but only if that byte's
  index i == [6:4]; i < [6:4] -> sent whole, i > [6:4] -> the last byte is DROPPED. The index counter
  is wider than [6:4], so a partial last byte is only possible for frames <= 63 bits. Long frames
  are whole bytes: 0x70 sends n*8 bits. The [6:4]/[2:0] decision latches when byte [6:4] goes out.
- A FIFO underrun does not end the frame: TX stalls (busy stays 1, dead time on air) until the next
  byte; a byte written before the shifter runs dry continues the frame seamlessly. Trailing junk
  bits (168-bit frame) and stalled frames are not answered by the card.
- **0x5C560 (parity off = 8) is sampled live, per byte**, at the end of each byte's 8 data bits
  (~69.5 ticks after TX start for byte 0, then +75.5 per raw byte, +85 per HW-parity byte). Parity
  ON at TX start latches a HW CRC onto the frame; start with parity off.
- So a 162-bit frame = 20 FIFO bytes (code 0x70): 2 data bytes with HW parity (9 bits each) + 18 raw
  FIFO bytes (144 bits) = 18*9. Alignment allows HW-parity data bytes (j1, j2) in {0,8,16} x {1,9,17}.
  Toggle 0x5C560 half a byte before each decision point (mixed.py build()).
- HW parity bit = odd parity of ALL stream bits since the last inserted parity bit (raw bits
  included), not just its byte (pair (16,17) NAKed with a per-byte check, works with this model).
  For pair (0,1) both models agree. Each pair fits with p = 1/4; some pair fits ~3/4 of the time,
  else re-auth (new nt, new keystream).
- Verified on the Gen1a card, block 2, key A FF..: Gen1a backdoor write via mixed frame (all 6 pairs
  ACK, pattern lands); ENCRYPTED write: A0 ACK, data ACK (decrypts 0xA), encrypted READ returns the
  written pattern -- 12/12 data frames ACKed over pairs (0,1) (0,9) (8,9) (8,17) (16,17) ((0,17)
  never came up); 8 read back exact, the other 4 hit the parity-left-on issue below. Block restored
  to zeros after.
- Pairs ending on byte 17 leave 0x5C560 = 0 (parity on): reset it to 8 before the next raw TX.
- Experimental monitor (memrw_auth.c) = memrw + op 8 TXTIME (prototype, kept for reference).
- Implemented: chip/memrw.c op 8 TXSCHED (TX + up to n timed stores, delays from the last FIFO
  write, waits for TX busy to clear; txraw/auth pacing removed, IRQ log 32 -> 16; 3256 bytes).
  Verified from the host (chipmon.txsched): 2/2 encrypted writes read back. App: mfc.c
  mfWriteBlock / mfWrite (pair picked on a cipher copy before A0; no pair -> re-auth, up to 16),
  net op 0x16 OP_MF_WRITE, tools/nfcnet.py mfwrite BLOCK KEY HEX32 [b].
- App verified (nfcnet.py mfwrite, block 2 key A FF..): 3/3 writes VERIFIED, independent mfread
  matches, block back to zeros. Block 5 with sector 1 key A -> "A0 nak 4": access bits F0 FF 00 =
  condition 100 for data blocks (write needs key B), the card refuses correctly, nothing written.

## No stock patch needed (tools/mkpatch.py) -- 2026-10-30
- memrw .ncd used to copy the stock header (45 B) and AON segment (1528 B) from patch_20791B5.ncd.
  The AON entry only does `bl 0x11888` (ROM: [0x68C80] = 0x32E0, [0x68C84] = 0); the rest of the
  AON code is only reachable via the stock SRAM hooks, which we don't load.
- mkpatch now builds the header field by field (byte-identical to before) and an AON segment of
  14 bytes (entry ptr + push {lr}; bl 0x11888; pop {r1}; bx r1). Verified on HW: monitor answers,
  0x68C80 = 0x32E0 afterwards, Gen1a backdoor dump of all 64 blocks matches dump/card_C1C1C1C1.bin.
- App: the stock-patch jobs (L+B/X/Y signature tests, L+R Read_RAM + stock cross-check) are gone,
  so nfcprobe embeds no Broadcom/Nintendo bytes and the user needs no sysmodule dump to build it.

## Nested auth: mechanism CONFIRMED, recovery pending -- 2026-10-30
- Nested auth works: after a known-key auth (cs_A running, parity off), send `60/61 target`+CRC
  ENCRYPTED under cs_A (4 bytes, fits bit mode). The tag replies with the target nonce nt_T
  encrypted under the TARGET cipher's keystream (NOT cs_A), 4 bytes + 4 parity bits.
- Verified on sector 1 (known key c1c1c1000001), authing sector 0 first: for each nested auth there
  is a valid PRNG nonce nt_T with enc_nt_T XOR nt_T == Crypto1(key).word(uid^nt_T). i.e. the 32
  keystream bits ks = enc_nt_T ^ nt_T are exactly recoverable keystream -> lfsr_recovery32 -> key.
  (tools/exp -> scratchpad nested1.py)
- Timing: with host round-trips the distance nt0->nt_T is wildly variable (1183..63378 steps), so
  nt_T is NOT predictable this way. The real attack needs an ON-CHIP nested auth (auth1 then the
  nested command at fixed cycles) so the PRNG distance is stable and nt_T can be predicted.
- TODO: (1) crapto1 lfsr_recovery32 + lfsr_rollback_word port (Python prototype, then C on the
  ARM11), validate recovering the known key from captured (ks, uid^nt_T). (2) On-chip nested op for
  a stable distance. (3) collect 2+ nonces, intersect candidate keys. (4) app + net op + button.

## ATQA 0000 -- 2026-10-30
- The ROM's RF_INTF_ACTIVATED_NTF always reports SENS_RES 00 00 (e.g. `61 05 .. 09 00 00 04
  c1 c1 c1 c1 01 88`); a raw WUPA right after gets 04 00 = ATQA 0x0004. The app now takes the ATQA
  from the WUPA in iso14aSelect and selects once after activation. (rawa.py still prints the NTF value.)

## Nested: crapto1 recovery ported + validated (tools/crapto1.py) -- 2026-10-30
- lfsr_recovery32 + lfsr_rollback_word + crypto1_get_lfsr ported fresh from crapto1, same odd/even
  split as crypto1.py. recover_keys(uid, nt, ks) with ks = enc_nt ^ nt (32 target-keystream bits).
- Synthetic self-test: recovers each known key from one nonce (~70k candidates, ~20 s in Python);
  two nonces (same key, different nt) intersect to the UNIQUE key.
- Real card: captured 2 nested nonces to sector 1, recovered c1c1c1000001 uniquely. (scratchpad
  real_recover.py; here nt_T was brute-forced via the known key just to feed recovery.)
- REMAINING for an unknown-key attack: predict nt_T. Host timing can't (jitter). Need an on-chip
  nested op (auth1 then the nested command at fixed cycles) so the PRNG distance nt0->nt_T is stable;
  then nt_T = prng_successor(nt0, D) for a calibrated D (+/- small jitter), recover, intersect.
  Then port crapto1 recover to C on the ARM11 (Proxmark does it <1 s) + net op + app.

## Nested attack WORKS end-to-end (on-chip OP_NESTED + crapto1) -- 2026-10-30
- memrw.c OP_NESTED (op 9): auth1 with the known key on-chip, wait for {at}, advance the cipher 32
  bits, then send the nested AUTH command (4 plaintext bytes, encrypted with the session cipher) at
  fixed cycles. Returns nt0; host reads the encrypted nested nonce from the ring (RX offset 4).
  (N_FRAMES cut 16->8 to fit; power-of-two required -- % N_FRAMES must be a mask, not a divide.)
- On-chip timing makes the PRNG distance DETERMINISTIC: nt_T = prng_successor(nt0, 160), EXACTLY 160
  every time (vs 1183..63378 with host round-trips). Same distance for different target blocks.
- Full attack (tools, scratchpad nested_attack.py): auth known sector 0 (key FF), nested to target,
  predict nt_T via dist 160, ks = enc_nt ^ nt_T, crapto1 recover_keys -> ~50k candidates; a 2nd
  nested nonce intersects to the UNIQUE key. Recovered sector 1 c1c1c1000001 and sector 2
  c1c1c1000002 from ONLY the sector 0 key. ~20 s/nonce in Python (C/ARM11 will be fast).
- chipmon.py nested(); crapto1.py recover_keys(uid, nt, ks).
- TODO (native): port crapto1 recover to C on the ARM11, mfc.c mfNested + mfNestedRecover, net op,
  and a "recover keys from one known key" button; then feed recovered keys into the dump.

## Nested folded into the card dump -- 2026-10-30
- mfDumpCard (mfc.c) sweeps: dictionary per sector/type, then nested-recovers EVERY still-missing
  A/B key from the first confirmed key (pivot). Each recovered key is added to the running dictionary
  so later sectors that reuse it auth instantly instead of paying for another nested recovery. Sweeps
  repeat until a pass finds nothing new; each dict key is tried at most once per cell (tried[][]) and
  each nested attempt at most once (nestedTried[][]), so it can't spin. No new net op -- the existing
  `mfdump` drives it.
- On-device: full 1K dumped from ONLY key FF -- sector 1 B c1c1c1000003 (nested), sectors 2-14 both
  c1c1c1000002 (recovered once, then reused via the pivot dictionary), all 64 blocks read.

## FM11RF08S static encrypted nonce (hf mf sen) -- 2026-10-30
Card: Fudan FM11RF08S 0490 (dormakaba Saflok), UID 5A5A0001, SAK 08. PRNG weak, STATIC ENC NONCE.
Backdoor key A396EFA4E24F (FM11RF08: A31667A8CEC1; FM11RF32N: 518B3354E760). Ground-truth keys from
pm3 `hf mf sen` (7 s): sec0 A 5A5A5A000001, sec1 A 2A2C13CC242A, sec2 A/B FF, sec3-15 A 5A5A5A000001,
all B FF; hidden sec32 (blocks 128+) A 5A5A5A000003 B 5A5A5A000004. (saved ~/hf-mf-5A5A0001-*)

Mechanism (eprint 2024/1275, pm3 armsrc AcquireStaticEncryptedNonces + tools staticnested_1nt.c):
- The NESTED nonce is STATIC (constant per sector/key). First (non-nested) nonce is still weak-random.
- Backdoor auth command = normal auth | 0x04, i.e. 0x64 (key A) / 0x65 (key B), with the backdoor key.
- Per sector/keytype, two captures from a backdoor AUTH_FIRST session:
  1. AUTH_FIRST(0x64/65, backdoor key) then NESTED(0x64/65) -> nt_enc under BACKDOOR key; decrypt with
     the backdoor key -> CLEAR static nt:  nt = nt_enc ^ crypto1_word(key, nt_enc^uid, encrypted).
  2. re-auth, then NESTED(0x60/61 normal) -> SAME static nonce encrypted under the REAL key -> nt_enc
     + 4 raw parity bits. (par_err in the json = raw_par ^ oddparity8(nt_enc byte); raw par is what we
     read straight off the framer, so the 3DS needs no par_err step.)
- Candidate keys (staticnested_1nt): ks1 = nt ^ nt_enc; lfsr_recovery32(ks1, nt^uid); rollback_word;
  get_lfsr; keep if oddparity8(nt&0xFF) == ((last raw enc parity bit) ^ ((ks2>>24)&1)) where
  ks2 = 2nd keystream word after feeding nt^uid. ~20k-70k candidates per nonce.
- Disambiguate to the unique key by KEY REUSE across sectors + verifying candidates against the card
  (pm3 fchk); a reused key is in several sectors' candidate lists.

- Validation tools: tools/staticnested.py candidates() (port of staticnested_1nt; counts match pm3
  exactly: sec0 A 27955, sec1 A 20607, sec3 A 34994) and tools/collect_rf08s.py (3DS backdoor
  collection over the passthrough via OP_NESTED with auth cmd 0x64 -- no firmware change needed).
  The static-nonce card flakes on a cold auth: retry + reselect.

## FM11RF08S native in the dump -- 2026-10-30
- crapto1.c: crapto1_static (candidates with the parity filter; 0.15 s on the PC vs ~20 s in Python)
  and crapto1_nt_decrypt (clear nested nonce under a known key). Host-tested against pm3 vectors.
- mfc.c: mfBackdoorKey (tries A396EFA4E24F / A31667A8CEC1 / 518B3354E760 with cmd 0x64),
  mfStaticNonce (the two captures), mfStaticMatch. mfDumpCard runs staticPass first when a backdoor
  auths: collect every sector's static nonce, then solve OFFLINE -- a key fits a cell iff it decrypts
  ntEnc to nt (32-bit filter), so dictionary keys and reuse cost no RF; only matches get an auth. A
  candidate of one cell that fits another open cell is a reused key. Single-use keys stay open (tens
  of thousands of candidates, too many for RF). Remaining blocks are read through the backdoor.
  Cells covered skip the plain nested sweep (it can't work on static nonces).
- On-device: `mfdump` with no keys recovered 31/32 keys in 1:51 (5A5A5A000001 by reuse across
  sectors 0,3-15; FF by dictionary). Only sector 1 A (2A2C13CC242A, used nowhere else) is open. All 64
  blocks match the pm3 dump except block 7 (that trailer's key A field, the open key).

## Plain static nonce (Fudan, first nonce always 01200145) -- 2026-10-30
- Test card UID 4ACF2F0C (Fudan based, pm3 `hf mf info`: "Static nonce 01200145", no backdoor). All
  keys FF; sector 5 set to A0B1C2D3E4F5 / B1C2D3E4F5A6 with the pm3 for testing.
- The PRNG restarts at select and steps per AUTH EVENT, not with time: OP_NESTED gives the target
  nonce at distance 160 every time, and a delay before the nested command (tried up to 5000 TIMER
  ticks) changes nothing. One nested capture therefore always repeats the same (nt, ks) -- useless
  for intersecting, and crapto1_nested then just accepts its first candidate (a wrong key).
- Second nonce like pm3 MifareStaticNested: first auth, a COMPLETE nested auth into the known sector
  ({nr}{ar} from the host with code 0x78, check {at}), then the target's nested AUTH -> distance 320.
  Host-driven, but event-based stepping makes the round trips harmless (calibrated 320 every time).
- tools/staticnonce.py (calib / attack) proved it; native: mfNestedRecover notices the static first
  nonce (both captures share nt0), calibrates both distances on the known sector (calibrate(),
  nestedNonce2), takes the second target nonce one nested auth later, and intersects as usual.
- On-device: `nested 0 FF.. 20` / `... tb` recover A0B1C2D3E4F5 / B1C2D3E4F5A6; `mfdump` with no
  keys: 32/32 in 49 s (sector 5 via static nested, rest dictionary).

## Magic: Gen4 GTU + Gen2 (CUID) -- 2026-10-31
- Test card: Gen4 GTU, UID 11223344, MFC 1K mode, password 00000000, shadow mode 02 (off), keys FF.
  pm3 `hf mf info` calls it both "Gen 2 / CUID" and "Gen 4 GTU"; `hf mf ginfo` config (30 bytes):
  0000000000000200 0978009102DABC191010111213141516 040008004F6B.
- GTU commands are plaintext ISO14443A frames after SELECT (no auth): CF pwd[4] CE blk -> 16 + CRC;
  CF pwd[4] CD blk data[16] -> 90 00 + CRC (FD 07); CF pwd[4] C6 -> config, 30 bytes + CRC here.
  They need DATA mode (r574 = 0, HW CRC): bit-mode length codes stop at 7 bytes (0x90 = short frame).
- The write answers only after the flash write, later than the usual 4 frame polls. Missing it
  leaves a stale frame that the NEXT command then takes as its answer (a "read" of old data).
  gen4Cmd drops stale frames first and polls 25 times for CD.
- A wrong password mutes the card completely (no answer to WUPA/SELECT either) until the field
  resets; rescan (iso14aStart) to recover.
- Capture ring frames were 28 data bytes: the config read (32 incl. CRC) got cut. FRAME_DATA is now
  36 (chip/memrw.c, mon.c FRAME_SIZE 64, chipmon.py); memrw.bin 3148 of 3364 bytes. The RX FIFO
  itself delivers all 32 bytes.
- App: mfGen4Read / mfGen4Write (read-back verified) / mfGen4Config, mfMagicDetect (Gen4 config,
  Gen1a unlock, Gen2 optional: rewrites block 0 with its own data through a normal encrypted WRITE,
  key from the defaults). mfDumpCard starts with magicPass: Gen4 (default password) or Gen1a reads
  every block without keys; the trailer keys go first in the dictionary, the sweep confirms them.
- Net ops 0x18 OP_MF_MAGIC, 0x19 OP_GEN4_READ, 0x1A OP_GEN4_WRITE; nfcnet.py magic [gen2] [PWD],
  g4read BLOCK [N] [PWD], g4write BLOCK HEX32 [PWD].
- Verified on-device: config matches pm3 byte for byte; mfdump 32/32 keys + 64 blocks in 3 s,
  identical to pm3 `hf mf gview`; g4write block 1 VERIFIED (and seen by an encrypted mfread), then
  restored; `magic gen2` -> gen2, gen4; wrong password -> mute until rescan.
- Separate Gen2 (CUID) card, UID 5A11E21B (ATQA 0004, SAK 08, all keys FF): `magic` -> none (no
  Gen1a/Gen4 answer); mfdump 32/32 keys + 64 blocks in 3 s; `magic gen2` -> gen2 (block 0 rewrite
  ACKed and verified); rescan + mfread block 0 unchanged (5A11E21B B2 08 0400 6263...69).
- Gen1a card UID F5F7BF02 (keys FF): `magic` -> gen1a; mfdump 32/32 + 64 blocks in 2.4 s, identical
  to an independent backdoor dump (tools/rawa.py gen1a-dump). Screen shows "gen1a magic: reading
  without keys". Keyless key pickup proven: sector 5 re-keyed through the backdoor to 4B3A29180716 /
  7C6D5E4F3021 (in no dictionary), mfdump with no keys -> both keys in 3.3 s (no nested). Restored;
  card identical to before.
- Config write (pm3 doc/magic_cards_notes.md): CF pwd F0 config[30] -> 90 00. NEVER F1 (same, but
  fuses the config for good) or FE (new password). Layout: 0 UL protocol, 1 UID length, 2-5
  password, 6 shadow mode, 7 ATS length (0 = off), 8-23 ATS, 24-25 ATQA (swapped), 26 SAK, 27 UL
  mode, 28 max R/W sectors, 29 unknown. mfGen4SetConfig sends F0 only, refuses (unsent) any change
  outside bytes 6-26 (our SELECT is 4-byte UID only; a lost password is a lost card), reads back.
  Net op 0x1B OP_GEN4_CONFIG, nfcnet.py g4config [HEX60] [PWD] (read + decode, or write).
- TX FIFO: data-mode frames go out whole up to at least 60 bytes (TXSCHED busy = 84.4 ticks/byte,
  linear for 4..60 zero bytes), so the 36-byte F0 frame is safe.
- pm3 as sniffer between 3DS and card (3DS screen / card / pm3 on top) works: `pm3 -c "hf 14a sniff
  -i; hf 14a list"` in the background, user presses the pm3 button. Non-interactive sniff records
  nothing (the client exiting ends it). Seen on air: F0 frame complete (36 bytes + CRC ok); reply
  latency F0 6.2 ms, CD 12.3 ms, CE 0.65 ms.
- Staged config tests on the GTU, all VERIFIED: (1) identical config rewrite; (2) ATS content byte
  with ATS off, restored; (3) SAK 08 -> 18: rescan shows SAK 18, restored to 08. Guard refused
  password and UID-length changes. Card dump identical to pm3 gview afterwards.
- Dump fix: a single failed confirm auth of a trailer key sent the sector to nested ("sector 10 A:
  nested..." after the magic read, pm3 stacked on the card). magicPass now confirms the trailer keys
  itself with readSectorRetry. With the pm3 still stacked: 3 dumps, 32/32 keys each, 4.9 / 3.0 / 3.0 s.

## Self-update over the network (debugging) -- 2026-10-31
- `nfcnet.py HOST update [FILE]` (default nfcprobe/nfcprobe.3dsx): OP_UPDATE (offset u32, data; 28 KB
  chunks; request buffer now 32 KB) writes <app>.new, OP_UPDATE_DONE (size u32) checks the size,
  swaps it over the app (argv[0], default sdmc:/3ds/nfcprobe.3dsx) and asks the main loop to exit.
  The normal exit path hands the chip back, then relaunchSelf(): Rosalina hb:ldr SetTarget (cmd 2,
  SD-relative path, static buffer 0) + SetArgv (cmd 3, argc u32 + strings, static buffer 1), like
  the Homebrew Menu does, and aptSetChainloaderToSelf() -> soft reset into the new build.
- Verified: 197 KB sent in < 1 s, app back on port 8020 within ~2 s, start screen shows the new
  build stamp (the banner now carries __DATE__ __TIME__). No FTP round trip needed any more.

## Magic: USCUID / Gen4 GDM (ZUID) -- 2026-10-31
- Card UID 2A01E51E (ATQA 0004, SAK 08, Fudan based, keys FF). pm3 `hf mf info`: "Gen 1a" + "Gen 4 GDM /
  USCUID (ZUID Gen1 Magic Wakeup)". `hf mf gdmgetcfg --gen1a` -> 7AFF0000000000000000000000000008
  (gdmcfg.txt), the factory ZUID config. ZUID only honors the first 8 config bytes and the SAK (pm3
  doc/magic_cards_notes.md "MIFARE Classic USCUID"), so no 7-byte UID / static nonce modes on this one.
- Protocol (pm3 trace): 40(7) / 43 wakeup (0A each), then E0 00 + CRC -> config[16] + CRC; write: E1 00
  + CRC -> 0A, config[16] + CRC -> 0A (3.3 ms later). Hidden blocks 38xx / A8xx. NEVER F0 F1 F6 F8 F9
  FE (wipe main / hidden memory and config).
- Config bytes: 0-1 wakeup enable (7AFF / 85..), 2 wakeup style (00 = 40/43, 85 = 20/23), 6 block key B
  if readable, 7 CUID, 9 EV1 perso (7-byte UID), 10 shadow, 11 magic auth (8000), 12 static encrypted
  nonce, 13 signature sector, 15 SAK; options on = 5A.
- App: mfUscuidConfig / mfUscuidSetConfig (only bytes 6, 7, 12 as 00/5A and 15 may change: the rest
  could lock the backdoor), mfMagicDetect flag MF_MAGIC_USCUID. Net op 0x1C OP_USC_CONFIG, OP_MF_MAGIC
  reply now flags, gen4 len, gen4 cfg, usc cfg[16]. nfcnet.py uscconfig [HEX32].
- Verified on the 3DS: detect "gen1a, uscuid", config read = pm3; identical rewrite VERIFIED; CUID on
  -> `magic gen2` reports gen2, off -> gone; SAK 08 -> 18 seen on rescan, restored; guard refused bytes
  3 and 9. Config back to 7AFF...08.

## 7-byte UIDs (cascade level 2) -- 2026-10-31
- iso14aSelect: 7-byte UID = level 1 `93 70 88 u0 u1 u2 BCC` (bit mode, HW CRCs 93 70) + level 2
  `95 70 u3..u6 BCC` in DATA mode (code 0 CRCs any frame; untested whether bit mode CRCs 95 70).
  Crypto1 uses the last cascade level's 4 bytes (cardUid(): uid[len-4..]), everywhere.
- Test card: the GTU switched to 7 bytes from the 3DS. Block 0 = 04A1B2C3D4E5F6 08 4400 6263..67 (UID
  from bytes 0-6, BCC computed by the card), config byte 1 = 01 and ATQA 4400 (pm3 preset "1k S50
  7-byte"). The GTU config guard now allows UID length 00 <-> 01 (not 02: no cascade level 3 yet).
- Verified: scan ATQA 0044 UID 04A1B2C3D4E5F6; encrypted mfread (auth with uid[3..6]); mfdump 32/32
  keys in 3 s. GTU restored to 4 bytes, card identical to gview.txt.
- GTU quirk, NOT 7-byte related: nested fails on the GTU in both UID modes. The decrypted nested nonce
  into the known sector is on no PRNG distance from nt0 ("calibration: no distance"), i.e. the GTU's
  nested nonces are not LFSR successors of the first nonce. (pm3 "Prng weak" only checks the first
  nonce.) pm3 fails too: `hf mf nested --blk 0 -a -k FF.. --tblk 20 --ta` -> 3 key candidates, "No
  valid key found" (target key is FF). So it's the card. mfNestedRecover now calibrates (like pm3)
  when the fixed distance 160 finds no key, and reports the calibrated distance.

## Clone a dump onto a magic card -- 2026-10-31
- mfCloneToMagic / net op 0x1D OP_MF_CLONE (force u8, per block valid u8 + data[16]) / `nfcnet.py
  clone FILE [force]`. Target detected: Gen4 GTU (CD writes, default password), Gen1a/USCUID
  (backdoor A0 writes), else Gen2 (gen2Test, then normal encrypted writes with the target's current
  keys: mfDumpCard with the dump's own trailer keys + keys.txt + defaults, nested if needed).
- Order: sectors 1..N-1, then sector 0 (blocks 1, 2, then 0, which changes the UID -> card.uid
  updated for later SELECTs, then its trailer). Data blocks before each trailer. Every block is read
  back; a Gen2 trailer is checked by authing with the new key A (keys read back as zeros); key A
  write tried first, then key B.
- Refused unsent: dump not whole sectors / bigger than the card; broken access bits (the inverted copy
  must match); on Gen1a/Gen2 a 4-byte block 0 with a bad BCC (those send block 0 as is during
  anticollision); on Gen2 (unless force) a trailer whose own C1C2C3 is not 001/011 (keys/access bits
  no longer writable = sector frozen). NOT on the GTU: it computes its BCC and ignores block 0 byte 4
  (its original block 0 is 11223344 1C.., BCC would be 44).
- Verified: GTU test dump (UID DEADBEEF, sector 1 text, sector 2 keys 4B3A29180716 / 7C6D5E4F3021)
  in 2.9 s, key dump == file; original cloned back == gview.txt. Gen2 5A11E21B: test dump + sector 3
  trailer with ACL 0F00FF (trailer bits 011, key B writes) cloned, key dump == file; real freeze
  (778F08, trailer bits 110) refused; original cloned back in 1:49 (sector 2 keys recovered by
  nested first, sector 3 written with key B) == backup. Bad BCC and broken ACL dumps refused.
- Gen1a F5F7BF02: test dump (UID DEADBEEF, sector 1 text, sector 2 keys) cloned in 5 s, key dump ==
  file; original cloned back == backup. (The Gen2 restore's 1:49 was likely nested returning wrong
  keys at distance 160; fixed below.)

## Nested: verify the key, keep the calibrated distance -- 2026-10-31
- On the Gen2 card (5A11E21B) distance 160 is wrong, yet crapto1_nested at 160 still returned a key
  (63D70E080617 for real 4B3A29180716): a wrong distance can leave a false key in both candidate
  sets. mfNestedRecover never checked it. Now keyAuths() auths the target with the key (3 tries) before
  accepting it; on failure it calibrates and retries, and a calibrated distance that gives a working
  key is kept for the card (per UID) and used first for its next keys.
- Gen2, sector 2 keys 4B3A29180716 / 7C6D5E4F3021: A 48.8 s (160 refused, calibrated), B 28.1 s and
  A again 26.1 s (remembered distance), all correct. Card restored == backup.

## 10-byte UIDs (cascade level 3) + card sizes -- 2026-10-31
- iso14aSelect generalized: levels = uidLen / 3; every level but the last is `88` + 3 UID bytes, the
  last gets the last 4. SEL code 93/95/97 (`0x93 + 2 * level`), levels 2-3 in data mode. The chip's
  ROM activation handles triple cascade by itself (RF_INTF_ACTIVATED_NTF gives the 10-byte UID).
- GTU in 10-byte mode: block 0 = 04A1B2C3D4E5F6071829 0804 0000.., config byte 1 = 02, ATQA 8400
  (bits 7-6 = 10: triple). Scan ATQA 0084 UID 04A1B2C3D4E5F6071829, mfread + 64/64 dump OK. The
  config guard now allows UID length 00/01/02.
- Card sizes from the SAK: 09 Mini (5 sectors), 08 1K, 19 2K (32 sectors, NEW: was read as 1K), 18
  4K (40). The GTU holds 4K whatever it announces; its size follows the SAK/ATQA config bytes.
- Bug: card.sak was only set by a full activation, so after a GTU config write under an active card
  the dump/clone used the old size. iso14aSelect now stores the SAK; OP_MF_DUMP (sectors 0 = from
  SAK) and mfCloneToMagic select first.
- Verified on the GTU (ATQA/SAK set through g4config, no rescan in between): Mini 20, 2K 128, 4K 256,
  1K 64 blocks dumped. 4K dump onto the 1K-configured card refused ("dump has 40 sectors, the card
  16"); a 4K test clone (text in blocks 200 and 254, i.e. the 16-block sectors) in 10.5 s, key dump ==
  file; original 4K contents cloned back == original, config restored == ginfo.txt.
