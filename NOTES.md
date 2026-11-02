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

## MIFARE Ultralight / NTAG family -- 2026-10-31
- Test card: UID 04A0A0A0A0A001, ATQA 0044, SAK 00, GET_VERSION 0004030101000B03 = Ultralight EV1
  MF0UL11 (20 pages, user 4-15, config 16-19). Not magic (no Gen1a / GTU answer). Signature reads,
  counters 0/0/0, tearing BD x3, lock bytes 0800 (L-OTP set), OTP FA027011.
- Its config pages are read-protected (AUTH0 <= 16, PROT 1): READ 10..13 -> 4-bit NAK 0. READ 0F
  returns page 0F then pages 00-02: a READ that reaches into the protected area rolls over to page 0
  (NTAG21x/EV1 datasheet). mfuDumpCard re-reads the 3 pages before the first NAK one at a time.
- Bit-mode OP_14A_TX (host CRC) is enough for 2-byte commands, but PWD_AUTH (7 bytes with CRC) got
  no answer that way; WRITE (8) can't go in bit mode anyway. mfu.c uses data mode (iso14aDataTx: HW
  parity + CRC, stale frames dropped). OP_14A_TX code FF = data mode now.
- A NAK (or no answer) leaves the card IDLE: every failed command is followed by iso14aSelect.
- PWD_AUTH is never tried on its own: a wrong password counts towards AUTHLIM, which can lock the
  protected area for good. Only a given password (OP_MFU_DUMP pwd) is sent, once.
- Writes (A2 page data[4] -> 4-bit ACK A, polled 10x for the EEPROM write) only to user memory, read
  back. Page 10 DEADBEEF via net and 10 from the UI editor, both verified, restored to 00000000 by the
  UI's "write user pages" (1 page written, the rest skipped as equal).
- Dump file = pm3 mfu_dump_t (.bin: version[8], tbo[2], tbo1, max page, signature[32], counter +
  tearing [3][4], pages). `pm3 hf mfu view -f` reads ours with every field right.
- Net ops 0x1E OP_MFU_DUMP, 0x1F OP_MFU_WRITE; nfcnet.py mfudump [PWD] [-o OUT], mfuwrite PAGE HEX8.
- NTAG215 test card: UID 04C8E3BA064F80, version 0004040201001103, 135 pages, blank (CC E1103E00,
  empty NDEF 0300FE), AUTH0 FF, ACCESS 00 (NFC counter off: READ_CNT 02 NAKs), PWD FFFFFFFF -> PACK 0000.
- Password test on it (config written raw via OP_14A_TX FF, CFGLCK and AUTHLIM left 0): PWD 12345678,
  PACK ABCD, confirmed by PWD_AUTH before AUTH0 80 + PROT 1 went in. Then READ 80 -> NAK 0, after
  PWD_AUTH it reads. mfudump: no password 128/135 pages; wrong password "refused", 128/135; right
  password 135/135 with PWD/PACK filled in. A wrong PWD_AUTH got NO answer here (no 4-bit NAK).
  Restored (AUTH0 first, while authenticated): dump byte-identical to before, FFFFFFFF auths again.
- Bug found by it: one lost READ answer ended the dump there (taken for the protected area start: 15
  pages unread once). mfuDumpCard now retries a failed READ once (re-auth first) before stopping.

## Gen4 GTU in Ultralight mode: clone MFU dumps -- 2026-10-31
- pm3 doc/magic_cards_notes.md + client/luascripts/hf_mf_ultimatecard.lua: config byte 0 = protocol
  (01 Ultralight), 27 = UL mode (00 EV1, 01 NTAG, 02 UL-C, 03 UL), ATQA 0044 / SAK 00 for a UL. Page n
  = first 4 bytes of backdoor block n, so CF CD/CE still read/write everything. GET_VERSION answers
  from pages FA-FB, READ_SIG from F2-F9, PWD_AUTH checks E5; PACK is page 13 on versions 6666/06A0
  (E6 on others). Our GTU: CF CC -> 6666, so its PACK is page 13 (user memory on most types).
- In UL mode with a 7-byte UID the UID is block 0 bytes 0-2 + block 1 bytes 0-3 (BCCs in the pages are
  ignored for anticollision). Pages read up to FA at least, whatever config byte 28 says.
- MISTAKE (recovered): a truncated F0 (13 of 30 config bytes, meant as a dry run) was ACKed 90 00 and
  wrote bytes 0-11 + garbage into 12-27 (ATQA 7373, SAK 83). The password bytes it carried were the
  same 00000000, so the backdoor kept working and a full F0 fixed it. The app always sends 30 bytes
  (mfGen4SetConfig), but a short F0 is NOT rejected by the card.
- mfGen4SetConfig's guard now also lets byte 0 (00/01) and 27 (00-03) change; password still not.
- mfuCloneToGtu: config switch (then iso14aStart: the UID changes), pages 2.. through the backdoor,
  signature, version, PWD (E5), PACK (E6 unless page 13), pages 1 and 0 last, reactivate, mfuDumpCard
  with the clone's password and compare. Config pages missing from the dump get factory defaults
  (CFG0 000000FF, CFG1 00050000, PWD FFFFFFFF): first EV1 clone kept the GTU's zeros there = AUTH0 0.
- The GTU shows the PWD page in clear (a real tag reads 00), and answers READ_CNT 2 even when the
  copied NFC_CNT_EN is off. Verify skips PWD/PACK pages.
- Verified: NTAG215 04C8E3BA064F80 cloned (net op 0x22 mfuclone) -> dump identical to the real tag but
  for the PWD page; EV1 04A0A0A0A0A001 cloned from the UI (saved dumps) -> identical, factory config,
  FFFFFFFF auths (PACK 0000). Classic clone of the GTU's own 1K backup switched it back (config ==
  original), blocks 64-255 restored from the backup: all 256 blocks + config == before.

## NFC-V / iClass feasibility (issue #9) -- 2026-10-31
- Card: HID iClass 2k, CSN 01020304F7FF12E0, config 12FFFFFFE97FFF3C, fuses: application mode, coding
  "ISO 14443-2 B / 15693", secured page (pm3 `hf iclass info` through the 3DS/card/pm3 stack). The
  user has a full pm3 dump with Kd / Kc (~/Downloads/icls/, not in the repo).
- The ROM knows ISO15693: CORE_INIT lists interface 83; RF_DISCOVER_MAP `83 01 83` (Broadcom 15693
  protocol -> 15693 interface) is accepted (`83 01 01` = frame interface is rejected, status 01), and so
  is `06 01 xx`. RF_DISCOVER poll types 76 (Broadcom) and 06 (NCI 2.0 V) are both accepted.
- Frame log (0x380A0/1 = 1) during a 76 or 06 poll: TX `24 01 00` (ISO15693 INVENTORY, low data rate,
  1 slot) in RF mode 0x89. A poll = mode 0x85 (`26` REQA), B poll = mode 0x86 (`05 00 08` REQB). The
  iClass answers neither (it needs its own ACTALL / IDENTIFY), as expected.
- ROM: 0x1116 maps 0x5C584 bits 0-2 to the frame-log mode: 0 -> 85 (A), 1/2 -> 87 (F), 3 -> 86 (B),
  4 -> 89 (V), else 8C. 0x1140(slot, val) sets 3-bit fields in 0x5C548 / 0x5C54C. Frame log NTF
  builder 0x4D22 (callers 0x44C0, 0x4780 RX, 0x6368 TX; TX mode from 0x5618 or 0x1116).
- Register snapshots during polls read all zeros (field only on for ms per ~1.4 s cycle). Capture on
  BEFORE RF_DISCOVER stalls the ROM, but 0x5C540-0x5C5BC are then identical for A, B and V polls
  (08 10 0 23 ... 11 ... 10 ... 1C 3): the stall happens before the tech setup, so no V config seen yet.
- pm3 `hf 15 sim` stacked under the card: no activation from a 76/06 poll (sim may not hear / answer
  through the stack; unclear which side fails). The sim then kept running with the client gone and
  ignored USB until the pm3 button was pressed.
- pm3 `hf 15 sniff` during 76 polls: a reader frame every ~1.4 s, ~4.9 ms per byte = 1-out-of-256
  coding (the slow ISO15693 reader mode), decoded with bit errors (`25 02`, `25 25 25 ..`, bad CRCs).
  iClass readers use 1-out-of-4. So the TX path exists, but iClass needs (1) the coding switched to
  1-of-4, (2) raw V-mode TX / RX through our monitor, (3) the RX side shown to work at all.
- Next: find the ROM's per-tech framer setup (likely table-driven, e.g. the store sequence around
  0xE62C writing 0x5C550 / 0x5C674 from a struct), hook it or call it from the monitor with tech 4, then
  sniff our own frames with pm3 `hf iclass sniff` and look for the card's SOF answer to ACTALL (0A).
- memrw OP_SNAP (10, addr = frame-log RF mode [, base u32, words u8 <= 128]): the NCI send hook
  0x38714 snapshots 0x5C540-5BC, 0x5C640-6CC, 0x5C780-7BC (or the given range) into the capture ring on the next frame-log TX NTF of that mode (FRAME_LOG
  on). memrw.bin 3356 of 3364 bytes. At TX time A / B / V differ only in: 0x5C554 16 / 13 / 18,
  0x5C570 0 / 0 / 1, 0x5C574 1 / 2 / 5 (0x5C568 length code 7 / 0 / 0). The rest is the same: 0x5C550
  8, 0x5C55C 22 (post-TX), 0x5C5B8 1C (idle: C), 0x5C5BC 3, 0x5C640 42, 0x5C64C 9, 0x5C674 4, 0x5C678 3,
  0x5C6AC 80, 0x5C6C4 2, 0x5C7A8 1C, 0x5C7AC 8 (all 0 when idle).
- Stall (capture on before RF_DISCOVER 76): RF block configured like V TX (same 0x5C640+ values,
  0x5C5B8 1C), only 0x5C554 10 / 0x5C574 11 / 0x5C55C 23 differ. A few 1-byte "frames" (0x5C588 50/51)
  land in the ring right after the ROM's poll.
- Raw V TX from the stall: txraw(r570 1, r574 5, code 0x10) + 0x5C554 = 18 -> IRQ log: our TX start,
  then TX/RX status 0x20 (RX timeout), no answer to ACTALL 0A / IDENTIFY 0C. Sweep 0x5C554 10-1F x
  r570 0/1 x r574 4-7: no answer anywhere, no chip hang.
- pm3 `hf sniff` (raw HF envelope, waits for a field > 180, cancellable over USB, no button needed):
  started after the stall, it triggered (field present) but the 32700 averaged samples (avg of 32) are
  flat: no visible modulation from our raw V TX in that window (the stall had reset 0x5C554, see below).
- pm3 `hf sniff` reading: the trigger (> 180) is a modulation edge, not field presence (the samples are
  an AC-coupled peak-detector envelope, idle -16). Raw mode (no --smode) = 0.59 us/sample, 32700 samples
  (19 ms); `--smode avg --sratio 2` = 3.54 us/sample (the ARM loop is slower than the SSC), 116 ms.
  The ROM's V poll decodes from it: SOF, one +-127 pulse per byte at (value + 1) 18.88 us slots after
  the SOF, EOF = `24 01 00 4E BF` (INVENTORY + CRC), 1366 avg samples per byte (4.83 ms).
- Snapshots of 0x5C000-0x5C7FF at TX time (OP_SNAP with a range), A vs B vs V twice: stable V-only
  values 0x5C440-44C 08 D5 1C 9A (A 07 C3 0A C8, B 0; a per-tech table, ROM 0xD728), 0x5C48C 18,
  0x5C53C 1, plus the framer trio above. 0x5C04C, 0x5C424/42C, 0x5C454/458, 0x5C510-518 vary per
  snapshot (measurements). None of them is needed for V TX.
- Framer coder / rate: ROM 0x11C8(tech, rate) writes 0x5C554 = 0x10 | tech, 0x5C558 = 0x10 | rate
  (callers: tech 0 = A, 3 = B, 6/7 = F, rate = 106/212/424/848). V is tech 8 (0x5C554 = 18, set
  elsewhere). TX busy time (txsched, 1 MHz) from the stall, 1 data byte:
  - 0x5C554 low nibble 8 (18, 38, 08): 1-of-256, 4832 us/byte + 115 us SOF/EOF; CRC appended by HW
    (1 byte = 3 on air). 9-E: ~75 us/byte, ~20 us overhead, but NO modulation on the pm3 (not 1-of-4,
    or not wired to the modulator). Others: no TX.
  - 0x5C558 bits 2-3 scale the slot: 0 = 18.88 us, 1 = 1/16 (302 us/byte), 2 = x4; bits 0-1 don't
    change TX timing (RX rate?).
  - 0x5C560 = 4 (or 0C): no TX CRC (1 byte = SOF + 4.83 ms + EOF). 8 = default (A: parity off).
  - r570 / r574 / 0x5C550 / 0x5C564 / length code: no effect on V TX timing.
- So raw V TX works: stall (capture on, RF_DISCOVER 76), 0x5C554 = 18, txsched(data, r570 1, r574 5)
  puts SOF `0A 22 5F` EOF on air (pm3-decoded, CRC by HW); with 0x5C560 = 0C, iClass ACTALL `0A` /
  IDENTIFY `0C` go out plain. Only in 1-of-256 though (iClass readers use 1-of-4; ISO15693-2 VICCs
  must accept both, PicoPass probably does).
- RX: no answer to ACTALL / IDENTIFY. Sweeping 0x5C558 0-3 x r570 0-7 x r574 0-F: no RX-done, the IRQ
  log only shows TX done (group 1 0x20, group 2 0x10). The pm3's peak-detector sniff can't see card
  load modulation (no 423.75 kHz energy after our frames, but none expected either), so it is unknown
  whether the card answers 1-of-256 at all. ROM 0x1206 (data TX) skips writing 0x5C56C = 2 after TX
  only in mode 0x89, so V RX is armed differently from A/B. ROM V module (NCI side): 0x1B000-0x1B400,
  state 0x39EAC, RAM hooks 0x38770.
- pm3 `hf iclass sniff` (stopped with the button) while the 3DS sent ACTALL / IDENTIFY in 1-of-256:
  pm3 decodes every byte as value + 1 (`0A` -> `0B`, `0C` -> `0D`; the ROM's INVENTORY `24 01` showed
  as `25 02` in `hf 15 sniff` too): the BCM coder puts the pulse one slot late against the pm3 decoder.
  Sending value - 1 (`09` / `0B`) decodes as clean ACTALL / IDENTIFY frames. Still no Tag frame in the
  trace. Back-to-back frames are sometimes merged by the decoder (`0A 0A 0A ...`).
- pm3 as a 1-of-256 reader can't settle it either: `hf 15 raw -2` exists, but it takes `0C` for a
  16-slot inventory (flags bit 2), and ACTALL answers only an SOF ("command failed" in both codings).
  So it is still open whether this PicoPass accepts 1-of-256 at all; if it doesn't, iClass needs a
  1-of-4 modulator path we haven't found (0x5C554 9-E time like one but don't modulate).
- Settled with a patched pm3 (local, uncommitted in ~/Programming/RE/proxmark3: `hf iclass reader --256`
  sends the iClass reader frames in 1-of-256; `hf 15 raw --noinv` sends `0C` as one frame): the card
  answers the normal 1-of-4 ACTALL / IDENTIFY / SELECT / READ, but NOT ACTALL in 1-of-256. So this
  PicoPass needs 1-of-4. (`hf 15 raw` can't talk to iClass even in 1-of-4: the card answers ~274 us
  after the reader EOF, before the 15693 reader starts listening.)
- `hf iclass sniff` (decodes 1-of-4, sensitive) while the 3DS sent ACTALL / IDENTIFY with 0x5C554 =
  19, 1A, 1B, 1C, 1D, 1E, 09: trace empty. Those coder modes don't put a V frame on air.
- Correction: a 1-of-4 byte is 302 us (4 symbols x 75.52 us); the ~75 us/byte modes above are not 1-of-4.
- B coder idea (synthesize 1-of-4 from 106 kbps NRZ cells, a 1-of-4 pulse = one 9.44 us cell):
  - From a stalled B poll (RF_DISCOVER 01; the stall registers are the same as for V, before the tech
    setup): 0x5C554 13 = normal B, ~103 us/byte (11 etu) + SOF/EOF, CRC (0x5C560 = 4 drops it).
    0x5C554 1B (and 0B) = 8 cells per byte (74.5 us) with ~20 us overhead: a raw NRZ stream.
  - Normal B frames only modulate after copying the ROM's B TX-time analog registers into the stall:
    0x5C44C C8, 0x5C48C 09, 0x5C490-4B8 16 58 08 42 33 CD F9 09 04 (4B4 0) FD, 0x5C504 14, 0x5C50C 10,
    0x5C53C 1 (pm3 `hf sniff` raw then shows SOF + bits on the 9.44 us grid, like the ROM's REQB).
  - The raw 1B / 0B mode never modulates (with or without those registers, 0x5C55C 48 / 88 / 89 / 8C /
    98 / A8 / C8; 08 and 28 break TX). `hf iclass sniff` saw none of the 1-of-4 frames built from it
    (both bit orders, both polarities), but did decode the 1-of-256 control frames in the same run.
  - Normal B framing can't carry 1-of-4: the start bit forces a pulse every 10-11 cells at even
    positions, 1-of-4 needs exactly one pulse per 8 cells at odd positions. Miller (A) can't either (no
    two empty cells in a row). F is Manchester.
  - Remaining TX idea: CPU bit-banging, toggling a register that directly gates the modulator, timed
    from the monitor (1 MHz timer; pulses 9.44 us on an 18.88 us grid). No such register known yet.
- RX is a separate open problem (iClass answers in 15693 format: 423.75 kHz subcarrier, Manchester).
- pm3 (local patches, uncommitted): `hf iclass sniff -t <ms>` stops by itself (firmware timeout in
  SniffIso15693, checked per DMA buffer); no button needed for unattended sniffs.

## DESFire without keys (issue #8) -- 2026-10-31
- Test card: UID 04B1B1B1B1B1B1, ATQA 0344, SAK 20, ATS 0675778102 80 (FSCI 5 = 64, FWI 8, CID ok).
  GetVersion 04010212001A05 / 04010102011A05 = DESFire EV2, 8192 bytes, 3584 free, batch B0B0B0B0B0,
  week 37/2021. PICC key settings 0B, 1 AES key (version 00). 7 apps (LEAF F51CDE/DB/D8/DC, F532F1,
  42494F, Schlage F532F0), every one key settings EB, AES. Signature reads (pm3: verifies, EV2 key).
- The ROM does RATS itself even with ISO-DEP mapped to the Frame interface: RF_INTF_ACTIVATED_NTF says
  interface 02 (ISO-DEP) and carries the ATS. Its FSD is unknown, and a card frame over 36 bytes would
  not fit a capture ring slot, so isodep.c sends S(DESELECT) (C2, answered C2), reselects (WUPA +
  CL1/CL2) and does its own RATS E0 20 (FSD 32, CID 0). Card frames are then <= 32 bytes; longer
  answers come chained (PCB bit 4) and get R(ACK) A2|bn. The 56-byte signature arrives in 2 blocks.
- Single-byte frames (C2, R(ACK)) go out fine in data mode (no FIFO padding byte as in bit mode).
- isoDepTx: R(NAK) on no answer (twice), S(WTX) echoed, block numbers per ISO14443-4 (toggle on
  every I-block received). DESFire native commands (status byte first, AF frames joined).
- Read without keys: GetVersion, FreeMemory, PICC GetKeySettings / GetKeyVersion(0), Read_Sig (3C 00,
  status 90), GetApplicationIDs, GetDFNames (one app per frame: AID, ISO FID LSB first, name), per app
  SelectApplication, GetKeySettings, GetKeyVersion for each key, GetFileIDs, GetFileSettings; and
  files with free read access (read or r/w key E): ReadData / GetValue / ReadRecords, up to 256 bytes.
  On this card F532F0 file 01 (plain, read free, 32 bytes) = "WAVELYNX TECH 01" + 16 bytes.
- Checked against pm3 hf mfdes info / lsapp --no-auth / getfilesettings --no-auth: same version,
  storage, free memory, key settings, key types and counts, key versions, ISO FIDs, file types, comm
  modes, access rights and sizes.
- Not done: signature verification (secp224r1, needs ECC on the ARM11), AID names (pm3's
  aid_desfire.json), anything behind a key, TX chaining (commands fit one frame).
- App: DESFire family (dfui.c) for any SAK with bit 5 and not bit 3; a non-DESFire ISO14443-4 card shows
  its ATS. Card screen, application screen (D-pad left/right between apps, A shows a read file), Y saves sdmc:/nfcprobe/desfire/<UID>.txt.
- Non-DESFire path checked with a JavaCard (NXP J3H145, JCOP3): UID 046D45528C5080, ATQA 0048, SAK 20,
  ATS 0578777102 (FSC 256, FWI 7, CID ok, no historical bytes). Native GetVersion 60 -> 67 00 (ISO7816
  wrong length): screen shows the ATS + "status 67". pm3: CPLC fabricator 4790 / type 0503 / OS 8211
  (release date 6351), Card Recognition Data GP 2.2.1, SCP03, ISD AID A000000151000000.

## JavaCard test applet, ISO-DEP TX chaining + WTX (javacard/) -- 2026-10-31
- The J3H145's GP keys are the default 404142..4F (key version FF, SCP03 i=00): checked offline from
  the INITIALIZE UPDATE card cryptogram before any EXTERNAL AUTHENTICATE (the counted step). ISD state
  07 (INITIALIZED), no applets; ROM packages A0000001515350 + D276000098... (NXP eID/eSign/PKI/EAC).
- No PC/SC reader here, so javacard/gpload.py does GlobalPlatform through the pm3's embedded Python
  (`proxmark3 -y gpload.py -- list|install CAP|delete AID`): SCP03 C-MAC, INSTALL [for load], LOAD
  240-byte blocks, INSTALL [for install]. EXTERNAL AUTHENTICATE only after the card cryptogram matches.
- Build: javacard/build.xml, ant-javacard + the JC 3.2 SDK on JDK 17 targeting its bundled 3.0.4 API
  (the old jc304_kit needs javac 8; only a JRE 8 is installed, and the 3.2 verifier rejects the
  jc304_kit export files). `JAVACMD=/usr/lib/jvm/java-17-openjdk/bin/java ant`.
- TestApplet F0334453504D01: 00 01 echo, 00 02 Le bytes 00.., 00 03 P1 busy (~4.4 s per P1 on the
  J3H145, not the 100 ms planned), 00 04 name. pm3 and 3DS agree on all.
- isodep.c now chains commands too (29-byte pieces, PCB bit 4, the card's R(ACK) per piece) and
  listens WTXM x longer after an S(WTX). From the 3DS (nfcnet.py apdu): 256-byte answer (9 blocks),
  200-byte echo (7 pieces out, 7 blocks back), 4.4 s command (~110 S(WTX) F2 01 echoed) all exact.
  The WTX cap was 50 at first: legitimate WTX every FWT (39 ms) exceeds that in 2 s; now 2000.
- Net op 0x23 OP_ISODEP (activate u8, APDU) -> [ATS] + answer; nfcnet.py HOST apdu [-a] HEX...

## Gen2 (CUID) detection on every scan, pm3 style -- 2026-10-31
- Replaces the block 0 rewrite test; nothing is written. As pm3 MifareCIdent: (1) RATS whatever the
  SAK says, ATS compared with pm3's known Gen2 ones (incl. the GTU's 0978009102DABC1910), then
  S(DESELECT); (2) else auth sector 0 with a default key (first that works for A, then for B) and
  send the encrypted WRITE 0: ACK = Gen2. The data never follows: iso14aSelect's 4-byte HLTA ends the
  write (pm3 drops the field instead; we can't without reloading the monitor).
- mfcProbe (Scan card, MIFARE Classic scan) runs it; card screen shows "Gen2 / CUID". Clone's Gen2
  check uses the same two tests. `nfcnet.py magic` now tests Gen2 by default (`nogen2` skips).
- Verified: CUID card 9BB2092B (SAK 08, key A not a default, key B FF): no ATS; key B WRITE 0 ACK ->
  Gen2 / CUID; `magic` 1.3 s. Block 0 afterwards intact (9BB2092B 0B 08 0400 ..., BCC ok).
- ATS path verified on the GTU (11223344): as shipped, config byte 7 = 00 -> no ATS, Gen2 via key A
  WRITE 0 ACK. GTU config byte 7 is the ATS LENGTH, not an on/off flag: 01 -> the GTU sends just
  "09" + CRC (093FCC). With 09: RATS -> 0978009102DABC1910 F005 = pm3's first entry -> "known Gen2",
  ACK test skipped; reselect + mfread fine afterwards. Config restored to ...0200 0978..., read back.
- Net op 0x24 OP_LOG (lines u32 -> last log lines, no hwLock); `nfcnet.py HOST log [N]` (net client
  lines cut). Remote keys don't scroll the on-screen log, so use this for remote tests.
- Gen1a card C1C1C1C1 (SAK 88, keys FF): no ATS, block 0 WRITE NAK 4 with key A and B -> "Gen1a"
  only on the card screen (no false Gen2); `magic` 0.6 s; block 0 intact.

## Keyed DESFire: EV1 secure messaging, key dictionary (issue #8) -- 2026-11-01
- Blank EV3 (one of 10): UID 040C686A9F2390, ATS 067577810280, GetVersion 04010133001805 / 04010103001805
  (EV3, 4096 bytes), batch 2143763030, week 45/2025, 5120 bytes free. PICC key settings 0F, 1 DES key
  version 00 = all-zero DES (EV1 ISO auth 1A with 00*8 works).
- dfcrypto.c: DES / 2K3DES / 3K3DES (EDE) / AES-128, CBC with a running IV, CMAC (Rb 1B / 87), CRC32
  (init FFFFFFFF, no final xor). 400 random vectors against Python cryptography (CBC both ways, CMAC, CRC).
- desfire.c, as pm3's EV1 channel (desfiresecurechan.c): auth 1A (DES/2K3DES/3K3DES) or AA (AES), RndB
  decrypted with IV 0, RndA||rol(RndB) encrypted with the IV running on, rol(RndA) checked. Session key
  pm3 DesfireGenSessionKeyEV1 (2K3DES with equal halves: single DES). Then every command: CMAC over
  cmd+data updates the IV (our MAC only sent for the writes 3D 3B DB 0C DC 1C C8 in MAC mode); full mode
  with data: data + CRC32(cmd+hdr+data), zero padded, encrypted; answers: data + 8-byte CMAC over
  data||status, or (full, no data sent) encrypted data + CRC32(data||00) + padding. Errors and 5A end it.
  Native TX chaining at 54 bytes (AF). ChangeKey: new key (xor old for another key), AES version,
  CRC32 over C4+keyNo+cryptogram, + CRC32(new key) for another key; encrypted without our CRC; changing the
  session's own key ends the session with a bare 00.
- Verified on the EV3, all from the 3DS (net op 0x25 OP_DF, `nfcnet.py HOST df ...`): created
  A1A1A1 (3 AES keys; files std plain/MAC/full, value full, linear record MAC, backup plain), B2B2B2
  (2 3K3DES keys, key settings 09: file list needs key 0), C3C3C3 (2 DES keys, key 1 -> 2K3DES). ChangeKey
  of other keys and of key 0 itself; writes in all modes incl. a 64-byte full write (chained), commits;
  reads back identical. GetCardUID (51, full) decrypts to the real UID. A DES key 1 changed to
  0011..EEFF reads back as key version 55: DES key versions live in the key bytes' LSBs.
- Test layout keys: PICC DES 00*8; A1A1A1 key 0 AES 00*16, key 1 AES 00112233445566778899AABBCCDDEEFF
  (v1), key 2 AES 5EC12E7A5EC12E7A0123456789ABCDEF (v2, NOT in the dictionary); B2B2B2 key 0 3K3DES FF*24,
  key 1 3K3DES 00112233445566778899AABBCCDDEEFF0102030405060708; C3C3C3 key 0 DES 00*8, key 1 2K3DES
  00112233445566778899AABBCCDDEEFF.
- Scan with keys (DESFire menu, or R on the card screen): built-in dictionary (16 keys, pm3's commonest)
  + sdmc:/nfcprobe/desfire/keys.txt (8 / 16 / 24-byte hex lines) on the PICC master key and every app key
  (by the key type from GetKeySettings; unknown type: AES, 2K3DES, 3K3DES); AE = wrong key, 40 / 9D stop.
  Key 0 re-reads what was refused (key settings, file list, file settings); every file whose read /
  read-write (value: also write) key is known is read after a fresh select + auth, in its comm mode.
  Whole test card: 3.3 s; finds everything but A1A1A1 key 2, its two files show "no key".
- Not done: legacy D40 auth (0A, MF3ICD40 only), LRP, key entry on
  the 3DS (keys.txt only; untested from the SD so far), write / format / create from the UI (net op only).
- File contents (A on a read file): its own screen now, a monospace hex + ASCII grid on the Classic dump
  editor's layout (16 per row, 13 rows, scrolls), the whole file instead of a message box's first 96 bytes.
- Sim: the UI simulator didn't build at 3978172 (C2D_DrawLine / C2D_DrawTriangle, prog* missing from
  the fakes); fixed, and it now rebuilds when a ../source/*.c changes (hook_*.c include them).

## EV2 authentication + secure messaging -- 2026-11-01
- AuthenticateEV2First 71 keyNo 00 (AES only): AF + E(K, RndB) (IV 0); AF + E(K, RndA || rol(RndB)) (IV 0
  again, not chained as in EV1); 00 + E(K, TI || rol(RndA) || PDcap2 || PCDcap2) (IV 0). Session keys
  CMAC(K, A55A / 5AA5 || 0001 0080 || RndA[0..1] || RndA[2..7]^RndB[0..5] || RndB[6..15] || RndA[8..15]).
- Every command afterwards: MACt = odd bytes (1, 3 .. 15) of CMAC(SesMAC, cmd || CmdCtr LE16 || TI ||
  hdr || data); answers MACt(SesMAC, status || CmdCtr+1 || TI || data); the counter steps on every good
  answer, plain ones too. Full mode: data || 80 00.. (no CRC), CBC with IV = E(SesENC, A55A || TI || ctr
  || 0..) (answers 5AA5, counter after the step), then the MAC over the ciphertext. Management commands
  (45 64 6F F5 6A 6E CA CD C1 CC CB C7 ...) must be MAC'd once authenticated; data commands follow the
  file's comm mode (plain: no MAC either way). ChangeKey: no CRC over the command, only CRC32(new key)
  for another key; encrypted like full mode.
- dfAuth(k, key, ev2): EV2 for AES keys; Scan with keys uses it on EV2 / EV2 XL / EV3 (GetVersion major
  >= 12, not Light). Net op OP_DF action 4, `nfcnet.py df ev2:K:aes:KEY`.
- Verified on the EV3: EV2 reads of A1A1A1 (plain / MAC / full std, value, record, 64-byte full), GetCardUID
  full. New app D4D4D4 (2 AES keys) built over EV2: files (std full 64, std MAC 32, linear record full,
  value full), ChangeKey of key 1 (v7) and of key 0 itself (v9, 404142..4F), full write 64 bytes
  (chained), MAC write, record write, Credit 1000 + Commit; read back over EV2 and over EV1 alike (value
  100 + 1000 = 0x44C). Keyed scan of the whole card 4.8 s. Key 1 of D4D4D4 (0F1E2D3C4B5A69788796A5B4C3D2E1F0)
  is not in the dictionary.

## LRP: not on the EV3 -- 2026-11-01
- NXP MF3D(H)x3 (EV3) datasheet: secure messaging D40 native, EV1, EV2; logins Authenticate (0A),
  AuthenticateISO (1A), AuthenticateAES (AA), AuthenticateEV2First / NonFirst (71 / 77). No LRP.
  AN12752 (EV3 vs EV1/EV2): SetConfiguration option 05 on the EV3 = VCTID override, PDCap1.2, PDCap2.2
  (transaction timer), PDCap2.5, PDCap2.6; no PDCap2.1 (the DESFire Light's LRP switch). So pm3's Light
  recipe (setconfig --param 05 --data 0000000001/02...) must NOT be sent to an EV3: it would land in
  another capability field.
- Probe on a spare EV3 (044D426A9F2390): AuthenticateEV2First with PCDcap2.1 = 02 (71 00 01 02, also LenCap
  6) answers a normal EV2 challenge (AF + 16 bytes; LRP would be AF 01 + 16 plain bytes). Probe app deleted,
  PICC formatted (FC with the DES PICC key): blank again, 5120 bytes free.
- LRP needs a DESFire Light (MF2DL(H)x0) or an NTAG 424 DNA (or newer NXP parts with LRP).

## Touch UI, key entry, DESFire create / write / format -- 2026-11-01
- Bottom screen: citro2d now (the text console is gone). Default: the log's last lines, a D-pad and one
  touch button per footer hint (uiFooter / dialogs / jobs record their hints; "<glyph> label" pieces,
  cut at a 3-space gap). A screen may draw its own (Screen.bottom). Taps become key presses next frame
  (appPress), so everything still works with the buttons alone when a card covers the screen; held
  D-pad / digit buttons repeat (uiButtonRep), OK / Cancel never do.
- entry.c: hex (keys, passwords, data up to 256 bytes on a 16-wide grid) and decimal entry. Top screen:
  left/right digit, up/down value, L/R a byte, X clear, A done, B cancel. Bottom: keypad (hex: types at
  the cursor and moves on; decimal: calculator style from the right, Del).
- DESFire (dfui.c): card screen Y = Save / Create application / Enter or change the PICC master key /
  Format; application screen Y = Write file (std/backup data, add record, credit/debit/limited credit)
  / Create file (all 5 types, comm mode, access keys) / Delete file / Enter or change a key / Delete
  application / Save. Each is a job: same UID as scanned, ISO-DEP, select, auth (EV2 for AES on EV2+),
  command (+ commit), then a scan with keys. Keys it needs and doesn't know are asked for first; keys
  that worked or were set are appended to desfire/keys.txt. Value files show their value in decimal.
- Verified on the EV3 (040C686A9F2390) through the UI over nfcnet keys: create app 112233 (2 AES keys),
  create std file + write it (key 0), create value file + credit 250 with commit (reads FA000000),
  change key 1 (new key found by the rescan via keys.txt), enter A1A1A1 key 2 (a zero key was refused
  and forgotten; the right one opened files 03 / 06), delete file, delete application.
- On the spare EV3 (044D426A9F2390), through the UI: create app, change the PICC master key DES 00*8 ->
  AES 00*16 (type bits in the key number; the rescan finds it over EV2), Format with the AES key over EV2
  (5120 bytes free again, no apps), PICC master key back to DES 00*8. Card checked afterwards: key
  settings 0F, 1 DES key version 00, no apps, 5120 free: as it came.
- Classic: menu "Enter a key" (6 bytes into keys.txt, then offers Read card) and "GTU password" (mfGen4Pwd,
  used by every UI GTU op and the dump / clone backdoors; net ops keep their explicit password). Verified
  on the GTU 11223344: wrong password -> GTU not found, and the card goes MUTE until the field drops (so
  Gen1a / Gen2 tests find nothing): the card screen now says so (MfMagic.mute). Right password -> GTU +
  Gen2 again. Entered key FFFFFFFFFFFF -> "already in the dictionary", read 64/64 blocks.
- Ultralight / NTAG: menu "Read with password" (PWD_AUTH, remembers the last one; the result says
  accepted / refused). Verified on the NTAG215 (04C8E3BA064F80, AUTHLIM 0) with PWD 12345678 / PACK ABCD
  and AUTH0 80 + PROT set raw: FFFFFFFF -> "Password refused", 128/135; 12345678 typed on the entry
  screen -> "Password accepted", 135/135. Restored afterwards (AUTH0 FF first while authenticated, ACCESS
  00, PWD FFFFFFFF -> PACK 0000; every page reads). The EV1 04A0A0A0A0A001 was NOT used: its password and
  AUTHLIM are unknown. UL-C 3DES auth isn't implemented, so no
  key entry for it.
- Sim: shots carry both screens (S 0 / S 1 in the draw list; PNGs are top over bottom), TOUCH(x, y)
  steps (one frame held; put KEYS(0) between taps), D-pad glyphs E079-E07C drawn as arrows.

## Originality signature checks -- 2026-11-01
- nxpsig.c: ECDSA verify without a hash (e = UID as a big-endian number, as pm3 originality.c with hash
  off), r || s, on secp128r1 (Ultralight EV1 / NTAG21x, 32-byte signatures) and secp224r1 (DESFire, 56
  bytes). Montgomery limbs, Jacobian points (a = -3), Shamir's u1 G + u2 Q, Fermat inverses. NXP keys
  from pm3 (UL EV1, NTAG21x, TagInfo key; DESFire EV3, EV2 / 424 DNA x2, EV2 XL, EV1 / 413 DNA, Light).
- Checked on the PC: 300 random signatures (both curves, half tampered) agree with a plain-python
  reference; the cards' own signatures pick the right key: EV3 040C686A9F2390 -> "DESFire EV3",
  NTAG215 04C8E3BA064F80 -> "NXP NTAG21x", UL EV1 04A0A0A0A0A001 -> "NXP Ultralight EV1"; one UID bit
  changed -> none.
- DESFire checks over GetVersion's UID (the anticollision one may be random); card screen shows valid /
  invalid under "Signature", the log and the saved info name the key. On the 3DS: EV3 -> valid, DESFire EV3.
- Ultralight / NTAG: checked in mfuIdentify (MfuInfo.sigKey), card screen "verified" + key name /
  "NOT verified". Hardware check pending (no MFU card on the reader at the time).

## DESFire extras: AID names, EV2 NonFirst, ISO IDs, key settings, key versions -- 2026-11-01
- AID names: nfcprobe/source/aidnames.c is generated by tools/gen_aidnames.py from pm3's
  client/resources/aid_desfire.json (244 AIDs, same byte order as our display: LEAF F51CDE etc. match).
  Application screen line 1 and the saved info show "name (vendor)".
- AuthenticateEV2NonFirst (77 keyNo, no LenCap): AF + E(K, RndB); AF + E(K, RndA || rol(RndB)); 00 + E(K,
  rol(RndA)) (16 bytes, no TI), IV 0 throughout; new session keys the same way, TI and CmdCtr carry on.
  Verified: EV2First key 0 -> NonFirst key 1 -> MAC'd ReadData and MAC'd GetFileIDs check with the
  running counter. A refused NonFirst (AE) logs the card out, but another NonFirst still works in the same
  transaction (the card keeps the TI). Net op OP_DF action 5, `nfcnet.py df ev2n:K:aes:KEY`.
- ISO IDs: CreateApplication with bit 5 of the key count byte, then ISO FID (LSB first) and the DF name
  (1-16 bytes); CreateStd/Backup/Record file with the ISO FID right after the file number (not value
  files). GetISOFileIDs (61) lists them. ChangeKeySettings (54 ks): full mode with the master key (EV1:
  CRC32 + padding; EV2: 80-padding + MAC), works in both.
- UI: create application has ISO FID / DF name fields, create file an ISO FID field (applications with
  ISO IDs), "Key settings" in the card and application menus (warns when bit 3 / bit 0 / keys F would
  freeze something), change key asks AES keys for a version (offers current + 1). Verified on the EV3
  through the UI: key settings 0F -> 0B, key 1 changed with version 02, file with ISO FID E104 created
  (needed the master key then), application 112233 with ISO FID + DF name; scratch apps deleted again.
- Left out on purpose: SetConfiguration (random UID can never be turned off on DESFire), the transaction
  MAC file, ISO 7816 wrapped commands / READ BINARY.

## DESFire: ISO 7816 reads, transaction MAC, SetConfiguration, random ID -- 2026-11-01
On the spare EV3 (real UID 044D426A9F2390, the user's "touchy" test card).
- ISO 7816 (plain, over ISO-DEP): SELECT application by DF name (00 A4 04 0C) or ISO FID (00 A4 00 0C),
  EF by ISO FID (00 A4 02 0C, FID MSB first; create commands take it LSB first), READ BINARY 00 B0 00 00 00
  (whole file up to 256), READ RECORD 00 B2 n 04 00. On a record file DESFire answers READ BINARY with
  6985 (not 6981): then READ RECORD 1.. until it fails. Unknown EF: 6A82. dfIsoRead + "ISO 7816 read" in the
  application menu (EF list, SW in words, A = contents). Verified: binary EF E104 (32 bytes), record EF E105.
- Transaction MAC file: CE fid comm ar0 ar1 02 key[16] keyver (hdr 5 plain, key + version encrypted).
  Its access nibbles: read = reading TMC||TMV (12 bytes), read/write = CommitReaderID key (F: none), write
  RFU. With CommitReaderID enabled, a commit without C8 + 16-byte reader ID (MAC'd) gets 9D and the
  transaction is lost; with it, C7 01 returns TMC (4, LE) || TMV (8). Commit option 01 also works without
  a reader ID (CommitReaderID never). A commit ends the authentication in such an application. Standard
  file writes still need no commit (pm3 the same). pm3 doesn't verify TMVs either.
  UI: create file type "transaction MAC" (TM key + version); writes in such an application send
  CommitReaderID ("nfcprobe") when the file wants it (free, or the write's key; else it says which key)
  and commit with option 01: the toast shows TMC / TMV; the contents screen decodes them. Verified: credit
  with reader ID (TMC 2 -> 4), TMAC created through the form with CommitReaderID never, credit -> TMC 1.
- SetConfiguration (5C option data, PICC master key, full): option 02 = the ATS (TL first), which pm3 sends
  with 80-padding after EV1's CRC (DF_FULL80; plain full mode gets 1E). 0875778102637264 and back to
  067577810280: ATS on activation changes at once. Option 00 data 02 = random ID (01 = format disable,
  NOT tried: permanent and would end this card's usefulness).
- Random ID turned ON for good on the spare (through the UI, two confirmations). Afterwards: anticollision
  UID 08 + 3 random bytes, new on every activation (only after the field drops, not on the same session's
  reselect), ATQA 0304; GetVersion's UID bytes are zeros; unauthenticated Read_Sig answers 0B. In a session
  with the PICC master key: GetCardUID (51, full) = 044D426A9F2390, Read_Sig (3C 00) answers status 90 with
  the signature encrypted: 56 bytes + CRC32 over data || 90 + padding (dfCmd now takes 90 as Read_Sig's ok;
  a 65-byte native answer needed a bigger frame buffer). Signature checks against the real UID: DESFire EV3.
  App: card screen shows the random UID and the real one on the same row; operations don't match a random
  ID card by UID (Format verified with UID 0821D0D6 after a scan with 08301910); saved info is named after
  the real UID.
- Spare left formatted: no applications, PICC master key DES 00*8, random ID on.

## Ultralight passwords (issue #7), Ultralight C on the GTU (issues #4, #5) -- 2026-11-01
- Ultralight EV1 04A0A0A0A0A001 on the 3DS: signature verified (NXP Ultralight EV1 key) on the card screen.
  Its password is still unknown; nothing was sent to it.
- mfukeys.c: pm3 `hf mfu pwdgen` (common/generator.c) A-G, with its own SHA-1 / MD5 / CRC-16; all 7 of
  pm3's self-test vectors match. pm3's fingerprints with a derived password (Amiibo, Amiibo Power Up band,
  Lego Dimensions) put that one first. MFU_KEYS = sdmc:/nfcprobe/mfu_keys.txt (8 hex = password, 32 hex =
  UL-C key, text after it = label), MFU_KNOWN = sdmc:/nfcprobe/mfu/known.txt (UID + key that worked,
  written on every successful auth).
- "Read with password" (menu, or Y on the card screen) scans, then opens a picker: type one, remembered,
  file, derived, defaults. It shows AUTHLIM from CFG1 (unknown when the config pages are protected) and
  confirms before a PWD_AUTH unless AUTHLIM is 0. The read re-identifies the card first and sends nothing
  unless UID AND type match what the picker was opened for: a GTU switched from EV1 to UL-C under the
  same UID once got the first 4 bytes of a 3DES key as PWD_AUTH (fixed, verified: "nothing sent").
  Result shows the PACK and whether it is the algorithm's. Verified on the GTU as an EV1 with PWD =
  Amiibo(UID) 8833CC77: picked from the list, "PACK 8080 (as expected)", remembered and preselected next time.
- GTU in UL-C mode (config byte 27 = 02): GET_VERSION answers zeros (pages FA-FB, so whatever version a
  previous clone left there!), 1A 00 -> AF ek(RndB), the 3DES exchange works with the key from pages
  2C-2F (each 8-byte half byte-reversed: memory "BREAKMEIFYOUCAN!" = key 49454D4B41455242214E4143554F5946).
  BUT: it answers the second step for ANY key (only the reader's RndA' check catches a wrong one), does
  not enforce AUTH0, and reads the key pages in clear. A real UL-C NAKs GET_VERSION and the key pages.
  RndB repeated once in a row. GTU in plain UL mode (03): version zeros, no answer to 1A, NAK on page
  0x29 -> "MIFARE Ultralight"; reads past page 15 anyway.
- mfuIdentify: an all-zero version counts as none. mfuUlcAuth (dfcrypto 2K3DES, RndA' checked),
  mfuUlcFindKey (known, mfu_keys.txt, pm3 mfulc_default_keys.dic + zeros / FF: safe, the UL-C has no
  lockout), run by the scan, by Read card and by mfuDumpCard without a key. Key pages are filled from
  the key after an auth. DES parity bits: a key differing in a LSB is the same key (EEFF vs EEFE).
- UL-C clone onto the GTU: key pages from the dump (pm3 dumps may stop at 44 pages: factory key then),
  config pages 28-2B factory if missing, verified by authenticating the clone with that key. Verified with
  a 48-page dump (custom key A0A1..B7, AUTH0 08) and a 44-page one (factory key found by the dictionary).
- UL-C key change (card screen Y -> popup): auth with the dictionary's key, WRITE 2C-2F, reselect, auth
  with the new one; remembered. GTU: factory -> 1000..00, new key authenticates, old refused, pages hold
  it byte-reversed.
- GTU as types we have no card of, synthetic dumps cloned and read back with the password: UL EV1
  MF0UL21 (41 pages), NTAG210 (20), NTAG212 (41), NTAG213 (45), NTAG216 (231): type, page count and
  PWD_AUTH right. (PACK = GTU page 13 on this version, as before.) NTAG203 can't be emulated (no mode).
- GTU restored afterwards from a full backup: config + all 256 blocks identical, UID 11223344, Classic 1K.
- pm3 `hf mfu sim -t 13` (RDV4 on the 3DS, dump via `hf mfu eload`) as a closer stand-in: NO answer to
  GET_VERSION (the real detection path: 1A -> UL-C), a wrong key NAKed in step 2 ("wrong 3DES key
  (refused)"), key pages read as zeros, AUTH0 not enforced either (pm3 TODO). Custom key: not in the
  dictionary, right key reads, wrong one refused. Key change from the UI on it: new key works, old refused.
- Fix from that: key pages that read as zeros were saved as a valid all-zero key (and a clone would have
  got that key). Without an auth they are now unread; a clone treats an all-zero key (pm3 dumps) as
  unknown -> factory key, and its verify skips the key pages (the auth checks them).
- Darkside (#2): the user tested every magic card we have for the NACK bug on the pm3: none has it.

## FM11RF08S: single-use keys (2x1nt seeds) + on-chip key checks (pm3 fchk) -- 2026-11-01
- New card: FM11RF08S UID 5A5A0002 (Saflok-style data). Before: 31/32 keys, sector 1 A "used only here".
- pm3 tools/mfc/card_only/staticnested_2x1nt_rf08s(_1key).c: a sector's key A and key B static nonces
  come from one 16-bit seed, and seed16(nt, key) gives it back (prev14/prev8 LFSR16 tables, two nibble
  S-boxes). mfc.c staticSeed(). Known sister key: 40918 candidates for sector 1 A -> 1 fits the seed ->
  2A2C13CC242A (same as the other Saflok card). Both keys open: pair the two lists by seed (keeps ~half:
  35315 A x 41355 B -> 16634 A), auth those, key B then by the 1-key filter.
- Test: sector 10 (all-zero data) re-keyed to A 5A5A1234ABCD / B C3C3E0F01122, found, then restored to
  5A5A5A000002 / FF..FF (verified by auth; full dump 32/32 in 71 s afterwards).
- Speed. Host-driven auth was 11 keys/s: per attempt select 30 ms, parity + drain 9, monAuth 5, {at}
  wait 40 ms -- every monitor request is an I2C write + IRQ + 2 reads through the i2c sysmodule,
  ~6-8 ms. Also iso14aSelect waited 4 polls for an answer to HLTA (it has none): fixed (fire and forget).
- OP_CHKKEYS (chip/memrw.c, mfChkKeys, net op 0x26 / nfcnet mfchk): host packs HLTA / WUPA / SELECT
  frames + the AUTH frame + up to ~34 keys per request; the chip does per key: parity on, the select
  steps (wait for each answer), parity off, auth() ({nr}{ar}), waits MF_AT_WAIT (1800 ticks; the
  right key's {at} came 1.16 ms after) and checks {at} == suc96(nt) with its own Crypto1 state.
  152 keys/s (pm3 fchk: 147). Brute-force phase 274 s -> 21 s. Also used by the dictionary sweep
  (32 per request, the hit read by the normal path; no chip answer -> one by one as before).
- Bug on the way: after the wait loop the compiler reused capture.count from before it (non-volatile
  read) and decoded the nt frame as {at}: never matched. Volatile reads in chkkeys and auth().
- The patch no longer fit (3924 of 3364 B). .bss (capture ring, reply buffer, irq log, ~900 B) now
  lives in AON RAM 0x68100-0x68600 (NOLOAD, zeroed by init); the AON segment we load is 14 bytes at
  0x68008, the stock AON code that used the rest isn't loaded. Image 3212 B.
- Candidate lists cached per cell (malloc, ~320 KB each, freed after the pass): each crapto1_static is
  ~20 s on the 3DS and phases recomputed them up to 8x. Whole dump with sector 10 both unknown:
  10:09 -> 2:31.

## Classic: keys from the UID (pm3 `hf mf keygen`), value blocks -- 2026-11-01
- nfcprobe/source/mfckeys.c ports pm3 common/generator.c KDFTable: Saflok / Maid, MIZIP (Mini),
  Disney Infinity (7-byte UID, SHA-1), Skylanders, Bambu Lab + Snapmaker spools (HKDF-SHA256, own small
  SHA-256), Vanderbilt ACT (pm3's "+3" trailer quirk kept for 4K big sectors). Every sector of every
  KDF matches `hf mf keygen -u 11223344 -k N` (Disney with 04112233445566).
- mfDumpCard: kdfPass right after the magic pass: per sector / key type, one on-chip check (mfChkKeys)
  of the <= 7 derived keys, hits go into the dictionary; MfDump.kdf names the KDF that opened the most
  (shown in the read result). staticPass now skips cells already found (and the whole backdoor attack
  when nothing is open).
- Both RF08S cards are Saflok: 5A5A0002 sector 0 A 5A5A5A000002, 5A5A0001 5A5A5A000001 (14 of its 32
  keys) are the KDF's. 5A5A0002 dump: 71 s -> 7.5 s, Saflok opens 29/32, the static nonce pass gets the
  3 others (sector 3 A, 14 A/B) from the dictionary.
- Value blocks: mfValue = auth, C1 INC / C0 DEC / C2 RESTORE + block (4-bit ACK), then value LE + CRC
  (6 bytes, 54 bits: plain parity-off ptx, no mixed frame needed; the card answers only with a NAK,
  silence = taken), then B0 TRANSFER dest (ACK), read back. Net op 0x27 OP_MF_VALUE, `nfcnet.py
  mfvalue inc|dec|restore BLOCK DELTA KEY [b] [-t DEST]`. Editor actions: add / subtract (positive
  delta, INC or DEC), copy to another block (RESTORE + TRANSFER), "Make a value block" (local edit).
- Verified on the GTU (sector 1, transport ACL): 100 +25 = 125, -7 = 118, RESTORE 5 -> TRANSFER 6 =
  118, key B -1000 = -882; INC on a non-value block -> NAK 4; INC 0xFFFFFFFD (overflow) -> refused, value
  unchanged. GTU restored, all 64 blocks + config identical to the backup.
- The extra backdoor keys (A31667A8CEC1 FM11RF08, 518B3354E760 FM11RF32N) were already in mfBackdoorKeys.

## Classic: card info (Saflok, MAD, signature, Fudan ID) -- 2026-11-01
- nfcprobe/source/mfcinfo.c, editor action "Card info (MAD, Saflok, signature)" + a summary in the read
  result. Offline checks:
  - Saflok (pm3 client/src/cmdhfsaflok.c): 17 bytes = block 1 + block 2 byte 0, byte table + bit rotation
    (safDecrypt), bit fields, creation date + interval = expiry. All 3 pm3 self-test vectors match field
    for field. Expiry: months are carried before days here; pm3 carries days first, which lands an
    interval whose months run past December a month late (no test vector covers it). Detected by sector 1
    key A 2A2C13CC242A or the Saflok KDF.
  - MAD (pm3 mifare/mad.c, AN10787): GPB DA bit + version, CRC8 poly 1D init C7 over info + AIDs, MAD2 in
    sector 16 on 4K. Names: tools/gen_madnames.py -> madnames.c from pm3's mad.json (1958 AIDs). A synthetic
    dump decodes the same as `hf mf mad -f`.
  - Signature: blocks 69-70 with key B 4B791BEA7BCC (NXP) / 707B11FC1481 (QL88), as pm3
    read_mfc_ev1_signature; secp128r1 keys added to nxpsig.c (SIG_MFC). pm3 recover_pk.py samples verify
    (3 NXP incl. a 7-byte UID, 1 QL88; a changed UID fails). Kept in the dump's keys file
    ("# signature <uidlen> <hex>"). No card here has one: untested on hardware.
  - Fudan ID (pm3 fm11rf08s_full.py): block 0 bytes 8/15 (0390 = FM11RF08S), bytes 9-14 a "Fudan Sig"
    only Fudan's online service checks. RF08S has no ECDSA signature (a backdoor read of 69 fails).
- 4th backdoor key 73B9836CF168 (FM11RF32N, pm3 hf mf info) added.
- 5A5A0002 on the 3DS (UI read + card info screen): Saflok Guest Key, card ID 12, lock 1234, property 100,
  opening key 2, deadbolt override, made 2020-01-01 10:00, expires 2020-01-05 01:00, checksum ok:
  identical to `hf saflok decode`. GPB 69: no MAD. Fudan FM11RF08S 0390.

## FM11RF32N: backdoor without static nonces -- 2026-11-01
- FM11RF32N (UID 7991086F, ATQA 0002 SAK 18, block 0 ..18 02 00 "FDS70V01"): answers backdoor key
  518B3354E760, but its nested nonces are not static. staticPass took any backdoor card for an RF08S,
  so no dictionary key ever matched the (unrelated) nonce pair and it sat in crapto1_static per cell
  for ~20 s x 80 cells before the dictionary sweep could run.
- mfStaticNonce now captures the backdoor nonce twice and drops the cell ("nonce not static") unless
  both decrypt to the same nt. RF32N: all 40 sectors, default keys, 256/256 blocks in ~27 s
  (`nfcnet.py mfdump`). RF08S path not re-run since (the extra capture repeats step 1).
- Dictionary first for every card: mfDumpCard runs dictPass (mfChkKeys over every open cell until
  nothing new) before staticPass, then the sweep (dictionary with the keys found since + nested). The
  nested pivot is now seeded from any key already found (before, only from keys the sweep itself found,
  so keys from magic / KDF / static passes never enabled nested). RF32N: 27 s -> 14 s, same dump.
  Worst case on an RF08S with no dictionary hits: 256 keys x cells / ~150 keys/s extra (~55 s 1K)
  before the static attack.
- Regression found on 5A5A0002: with the dictionary first, key B of a sector is already known, so
  staticPass skipped its nonce and the "key from the other key" seed filter had nothing to seed from.
  Now a found key's nonce is still captured when the other key of its sector is open. Test: sector 2
  key A set to 5A1B2C3D4E5F (not in the dictionary), dump -> "81056 candidates, 1 fit key B's seed:
  found", 37 s total; key put back to FFFFFFFFFFFF after. Untouched 5A5A0002: 6 s (was 7.5 s).
- The pivot change ran there too: before the fix, sector 2 A fell through to nested from a known key
  (as expected it fails on a static card: "no key at distance 160").
- Nested on the FM11RF32N (sector 2 A set to 5A1B2C3D4E5F): the pivot change made nested run, but it
  failed. The nonce distance jitters: 839..850 from one calibration to the next (NXP-like PRNG ticking
  with time, not the fixed 160 of the on-chip op on other cards). mfNestedRecover now captures both
  nonces with parity; after the calibration, every distance within +-16 whose nt_T fits the 3 leaked
  parity bits (oddpar(nt byte i) == raw par bit i ^ ks bit 16-8i; pm3's valid_nonce XORs in the
  encrypted byte's parity because its par[] is stored that way, ours are raw wire bits -- checked
  against crypto1.py, 200/200) is solved, nearest first, against all of the 2nd capture's survivors
  (crapto1_nested_any). ~5 survivors each. `nfcnet.py nested`: 3/3 recovered, 52-89 s; full dump with
  that key unknown 74 s, all 40 sectors. Key put back to FFFFFFFFFFFF after. nfcnet's nested timeout
  60 -> 600 s.
- Once a card has been calibrated (nestedDist != 160), nested goes straight to the window (it tries the
  calibrated distance first anyway): ~25-35 s instead of ~50 s. Winning distances, 7 runs: all within 4
  of that run's calibration. 1 run in ~11 came up empty (likely a bad capture), so a window that finds
  nothing retries once with fresh captures (mfNestedRecover -> nestedOnce x2, only when the window ran).
  Since: 11/11 recovered, dump 69 s.

## Darkside / NACK-bug on the FM11RF32N batch (issue #2) -- 2026-11-01
- This RF32N batch has the NACK bug: `hf mf darkside` on the pm3 (sister card E928096F, same batch/
  hardware as the 3DS card 7991086F) recovers FFFFFFFFFFFF in ~4 s. pm3 prints "Parity is all zero.
  Most likely this card sends NACK on every authentication." -> the always-leak (par_list == 0) path.
- Recovery math proven in Python (tools/darkside.py): a port of pm3 lfsr_common_prefix + nonce2key.
  Exact convention, verified against pm3's own crapto1 in C (a known key must come back): feed uid^nt,
  then the fixed ON-WIRE nr bytes (the keyless reader's bytes) with is_encrypted=1, then ar (input 0),
  then the 4-bit NACK keystream; ks[c] = NACK ^ 0x05, nibble bit i = i-th keystream bit. Pass the
  on-wire nr to nonce2key. First try (plaintext nr, enc=0) recovered nothing -- the enc=1 feedback on
  the on-wire bytes is the whole trick.
- Always-leak path: nonce2key with par_info=0 returns a large list (~74k-185k candidates per run); the
  key is the one common to every run. Two synthetic runs (different nt) intersected to exactly the one
  correct key. So per run the collector must deliver: uid, the locked nt, the on-wire nr, ks[8].
- On-chip collector (OP_DARKSIDE in chip/memrw.c). The card does NOT reseed its PRNG on HLTA/wake: it
  free-runs, so the nonce is set by WHEN the AUTH arrives. Mechanism:
  - Fire each AUTH on an ABSOLUTE timer grid `sync` ticks apart (NOW() = -TIMER counts up; busy-wait to
    the grid point after the re-select, skipping a grid point if the re-select overran). HLTA is needed
    in the re-select (without it the card doesn't answer AUTH).
  - BUT the nonce is not a pure function of absolute time: the card's clock stops during the reader's
    modulation pauses, so every frame the reader sends costs PRNG steps (~180 for one {nr}{ar}). The per-
    fire advance only stays constant if every iteration sends the same frames: {nr}{ar} goes out after
    EVERY nonce, on target or not (a version that skipped it off-target saw the advance jump from ~4 to
    ~178 steps per fire and never re-locked).
  - Host calibrates (mfDarkside in mfc.c; prototype tools/darkside_hw.py): a short-spacing call returns
    two nonces -> ticks per step (1.573 here), then a closed loop drives the per-fire advance to within
    8 steps, so sync == one PRNG period (65535 steps, ~78830 ticks). ~2.3 s.
  - On-chip steering, like pm3: lock onto the first nonce; a nonce within DS_WIN (48) steps of it moves
    the next fire by that many steps (tq = ticks/step * 256) and a quarter of it goes into the per-fire
    fractional correction (sfr/256 ticks, learns the drift the integer grid leaves). Off by more for 4
    fires: re-lock where the nonce is. On target, record the NACK for the next missing nt_diff. A run
    completes all 8 in ~10-12 fires (~1 s); every run completes, all ks verified against the known key.
  - Recovery (crapto1_darkside): the common-prefix list misses the key ~1 run in 10 (synthetic: 4/40; pm3's
    algorithm, same behaviour), so like pm3, an empty intersection restarts from the new run's list. Runs
    after the first only keep candidates in the previous list (binary search, no big buffer, no sort);
    linear rollback stretches (3 bits + {ar}, and uid^nt + get_lfsr) are byte lookup tables, filter() is a
    128 KB bitmap in the hot loops (1.67x on the PC, bit-identical lists). The app now also enables the
    New3DS speedup (804 MHz + L2; osSetSpeedupEnable), which helps every crapto1 recovery.
  - Result: 16/16 recoveries on the 3DS card 7991086F, 8.5-20 s (typically 11-13 s, 2 runs) vs pm3's ~4 s;
    the rest is ARM11 crapto1 time. A run with a huge list (>1M candidates) that runs out of memory is
    skipped like an incomplete one.
- App: mfDumpCard runs darkside on sector 0 key A when the dictionary and the static nonce pass found no
  key at all; the key becomes the nested pivot. Net op 0x2A OP_MF_DARKSIDE, `nfcnet.py HOST darkside
  BLOCK [b]`. Verified: 7991086F (4K) with every trailer changed to non-dictionary keys (sector 0 A/B
  3D5B1FA9E4C7, sectors 1-39 A/B 7E2C94D1B8A3, access bits still FF078069): keyless dump in 63 s --
  darkside 8 s -> nested (sector 1) -> dictionary for the rest, 40/40 sectors. THE CARD KEEPS THESE KEYS.
- Chip SRAM for the patch is full (3356/3364 bytes). To fit OP_DARKSIDE: removed the debug IRQ logging
  (log_irq, rf_filter/tmr_filter -> a single identity pass_filter) and OP_SNAP (the one-time NFC-V
  framer snapshot, used only by rfpoll.py/chipmon.py, re-addable from git).

## NDEF on Ultralight / NTAG (Type 2) -- 2026-11-01
- nfcprobe/source/ndef.c: T2T TLVs (00 / 01 / 02 / 03 / FD / FE, 1- or 3-byte lengths), NDEF record
  parser (SR / long, IL, chunk flag), descriptions for URI (prefix codes), Text (lang, UTF-8 / UTF-16),
  Smart Poster (its URI), MIME, absolute URI, external (Android AAR); builders for URI / Text records (SR
  under 256 bytes, else the 4-byte length) and the 03 .. FE TLV. Records built here decode the same in
  pm3 `nfc decode`.
- mfu.c mfuNdefWrite: refused unsent without CC E1 / with a read-only CC / when it doesn't fit the CC
  size; writes an empty message (03 00 FE) into page 4 first, then pages 5.., page 4 last, so a write cut
  short leaves an empty tag. Every page read back (mfuWritePage).
- ndefui.c: card screen R (and the touch button) -> NDEF screen (records, CC); X: write a URL / text (the
  system keyboard, swkbd) or erase. Writes only onto the card (UID) and type the screen was read from.
- Net op 0x28 OP_MFU_NDEF, `nfcnet.py HOST ndef [url URL | text TEXT | raw HEX | empty]`.
- Verified on the NTAG215 04C8E3BA064F80: URI, text, a 2-record raw message, a 420-char URL (long record,
  FF-length TLV) written and read back; 625 bytes refused unsent; 3/3 erases through the UI. Left empty
  (03 00 FE), as found. The keyboard path itself needs someone at the 3DS (swkbd is an applet).
- Bugs found on the way: a builder failure (record too long) was wrapped as an EMPTY message and erased
  the tag -> now refused. The NDEF screen drew nd while the job's mfuDumpCard cleared it (NULL type ->
  data abort, PC in ndefDraw): jobs now fill a copy the UI thread takes over; the Ultralight card screen
  had the same race (scan again) and got the same fix. One lost GET_VERSION answer made the NTAG215 an
  NTAG203: mfuIdentify retries GET_VERSION once before the fallbacks.

## Amiibo with the console's own keys -- 2026-11-01
- No key file: the NFC sysmodule (.code at 0x100000) has the amiibo key table in ro at 0x135584: two 106-byte
  sets, each "unfixed infos\0" magic[14] hmacKey[16] "locked secret\0" magic[16] hmacKey[16] ctr[16]. FUN 0x114660
  picks a set by a flag ([0x161FF8+0x14] bit 0 -> set 1 = .code+0x355EE), copies the 64-byte base seed, runs
  ps:ps EncryptDecryptAes (0x00040204) over seed[0x20..0x40] in place with algo 2 (CTR) and key type 9
  (PS_KEYSLOT_39_NFC), the set's ctr as IV (wrapper 0x1207EC -> 0x120858), then the HMAC-SHA256 DRBG
  (0x128B78) with the type string. So amiitool's xorPad = the keyslot 0x39 CTR keystream at ctr, one pad
  for both keys; the rest of key_retail.bin is the module's own table.
- amiibo.c: reads the module's ExeFS .code from NAND (FSUSER_OpenFileDirectly, ARCHIVE_SAVEDATA_AND_CONTENT,
  title 0004013020004002, then 0004013000004002), BLZ-decompresses it (same bytes as tools/ncch.py), finds
  both sets (CRCs 90B0ADB3 / 7355512E, same as extracted/), gets the pad from ps:ps, then amiitool (socram8888,
  MIT): unpack (decrypt + both HMACs), pack, and a fresh unregistered copy (settings + app data zeroed,
  UID / model info / salt kept). Checked offline against a transcription of amiitool's pack with made-up keys.
- THIS console's set is set 1. Proof: a fresh set-1 copy (character 0642 0000 035F 1102, from the Flipper's
  image) written onto the NTAG215 04C8E3BA064F80 -> System Settings: "successfully read amiibo", asks for owner
  info. The set-0 copy gave "this is an invalid amiibo" (037-0524); the Flipper's own image is invalid too.
- mfuAmiiboWrite (net op 0x29 sub 2, `nfcnet.py amiibo write|lock DUMP`): stage 1 (CC F1 10 FF EE, pages
  4-129, PWD, PACK; data still rewritable), stage 2 PERMANENT (dynamic lock 01 00 0F BD, CFG0 00 00 00 04,
  CFG1 5F 00 00 00, static lock 0F E0), Tagmo's order; pages retried on a lost ACK. The 3DS accepted the
  tag UNLOCKED (stage 1 only). NTAG215 04C8E3BA064F80 is now a locked Amiibo for good (user's choice, ~100
  spares): PWD D8B05FD3 (pm3 pwdgen B) -> PACK 8080.
- `nfcnet.py amiibo` decrypts the tag on the reader; `amiibo fresh SET OUT [DUMP]` makes OUT.bin (pm3) +
  OUT.nfc (Flipper v4 text format). The GTU in NTAG215 mode with a fresh copy got no reaction at all from
  System Settings (not even an error). Likely why: this GTU answers PWD_AUTH A11D72B0 with PACK 4883 (page
  0x13's bytes, the 06A0 quirk), not the 8080 a real Amiibo gives.
- GTU detection after an Ultralight op: `clone` / `magic` said "not a magic card" twice. Not the MFU op:
  the card had been swapped (NTAG215 out, GTU in) and netsrv still had the old card active, so its SELECT
  of the cached UID got silence and so did CF C6. Fixed: card ops (not ISO-DEP / DESFire, whose session
  a SELECT ends) SELECT first and reactivate on silence (cardReady). Checked by changing the GTU's UID
  with a block 0 write, then `magic`.
- Generated images live in the gitignored dump/amiibo/ (Flipper .nfc + pm3 .bin), the GTU backup in dump/gtu/.
  GTU restored to Classic 1K afterwards: config and all 64 blocks identical to the backup.
- App UI (amiiboui.c): L on the Ultralight card screen of an NTAG215, or "Amiibo" on a saved 135-page
  dump: the figure decrypted (model info, nickname, owner Mii name at plain 0x4C+0x1A UTF-16LE, dates,
  write count, app ID, lock state). X copies it onto a blank NTAG215: amiiboImage re-signs the plain data
  (kept, or zeroed for a new figure) for the blank's pages 0-2 with the set that verified it, sets the
  Amiibo lock bytes / CC / config / PWD (pwdgen B) / PACK 8080, then mfuAmiiboWrite, optionally the lock
  stage, then reads back and verifies. Refused on the source card itself. Checked: amiiboImage of the set-1
  Flipper image for 04C8E3BA064F80 is byte-identical to the image the 3DS accepted (`nfcnet amiibo image`).
- Locking an unlocked copy later (X, "Lock this tag", two confirms; only for a card just read, not a dump):
  same UID as shown, the image rebuilt and rewritten (PWD / PACK surely from the UID, as AUTH0 04 turns the
  password on), PWD_AUTH must give PACK 8080, then the lock stage. Can't be undone: the tag can't take
  another Amiibo after it.
