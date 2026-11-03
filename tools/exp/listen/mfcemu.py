#!/usr/bin/env python3
"""MIFARE Classic emulation with the chip image chip/emu.c (MODE_MFC): load it, put a dump (1K / Mini,
keys in the trailers; 2K / 4K too) into its memory, listen as the dump's card for SECS (4-byte UID from block 0,
ATQA / SAK from block 0), then print the chip's frame log and the blocks readers wrote.

    mfcemu.py HOST SECS DUMP
"""
import struct
import sys
import time

sys.path.insert(0, __file__.rsplit("/", 3)[0])
import chipmon
import nfcnet

OP_EMU, MODE_MFC = 5, 3
O_FRAMES = 60  # struct emu: ... frames, writes, nlog


def main():
    host, secs, path = sys.argv[1], float(sys.argv[2]), sys.argv[3]
    mem = open(path, "rb").read()
    nblocks = len(mem) // 16
    uid = mem[:4]
    nfc = nfcnet.Nfc(host)
    mon = chipmon.Mon(nfc, on_other=lambda p: None)
    mon.load("emu_mfc.bin")
    base, logp, memp, blk2, blk3 = struct.unpack("<IIIII", mon._do(OP_EMU, 0))

    def addr(b):  # chip/emu.c blk()
        return memp + 16 * b if b < 64 else blk2 + 16 * (b - 64) if b < 173 else blk3 + 16 * (b - 173)
    print(f"struct emu {base:05X}, log {logp:05X}, mem {memp:05X}; {nblocks} blocks, UID {uid.hex()}")
    mon.write(base + 1, bytes([nblocks & 0xFF, 0, 0]) + uid)
    for b in range(0, nblocks, 4):
        mon.write(addr(b), mem[16 * b:16 * b + 64])
    mon.write(base, bytes([MODE_MFC]))
    tl = bytes([0x30, 1, mem[6] & 0x1F, 0x31, 1, mem[7] & 0x0F, 0x32, 1, mem[5], 0x33, 4]) + uid
    for c in (bytes([0x20, 0x02, len(tl) + 1, 4]) + tl, bytes.fromhex("2100040104" "0202"),
              bytes.fromhex("200204018001" "01"), bytes.fromhex("2103030180" "01")):
        nfc.cmd(b"\x10" + c)
    end = time.time() + secs
    while time.time() < end:
        for p in nfc.drain(100):
            if p[:3] == b"\x10\x61\x06" and p[4] == 0:
                time.sleep(0.1)
                nfc.write(bytes.fromhex("10" "2103030180" "01"))
    nfc.cmd(bytes.fromhex("1021060100"))
    frames, writes, nlog = struct.unpack("<III", mon._do(chipmon.OP_READ8, base + O_FRAMES, bytes([12])))
    log = mon._do(chipmon.OP_READ8, logp, bytes([128]))
    print(f"frames {frames} writes {writes} log {nlog}")
    for i in range(max(0, nlog - 16), nlog):
        e = log[(i % 16) * 8:(i % 16) * 8 + 8]
        print(f"  state {e[0]} len {e[1]:2} {e[2:2 + min(e[1], 6)].hex(' ')}")
    if writes:
        after = b"".join(mon._do(chipmon.OP_READ8, addr(b), bytes([64])) for b in range(0, nblocks, 4))
        for b in range(nblocks):
            if after[16 * b:16 * b + 16] != mem[16 * b:16 * b + 16]:
                print(f"  block {b}: {after[16 * b:16 * b + 16].hex()}")


if __name__ == "__main__":
    main()
