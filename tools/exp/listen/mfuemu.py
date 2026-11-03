#!/usr/bin/env python3
"""Ultralight / NTAG emulation with the chip image chip/emu.c: load it, put a dump into its struct emu,
listen as the dump's card (7-byte UID, ATQA 0044, SAK 00) for SECS, then print the chip's frame log.

    mfuemu.py HOST SECS DUMP [VERSIONHEX]
DUMP: raw pages or a pm3 .bin (56-byte header: version, tbo, pages, signature, counters).
"""
import struct
import sys
import time

sys.path.insert(0, __file__.rsplit("/", 3)[0])
import chipmon
import nfcnet

OP_EMU = 5
O_MODE, O_FRAMES = 0, 60  # struct emu; the frame log and the pages are elsewhere (op 5)


def main():
    host, secs, path = sys.argv[1], float(sys.argv[2]), sys.argv[3]
    raw = open(path, "rb").read()
    version, sig, cnt = bytes.fromhex("0004040201000F03"), bytes(32), bytes(9)
    if len(raw) >= 56 + 64 and (len(raw) - 56) % 4 == 0 and raw[56] == 4:  # pm3 header
        version, sig = raw[:8], raw[12:44]
        cnt = b"".join(raw[44 + 4 * i:47 + 4 * i] for i in range(3))
        raw = raw[56:]
    if len(sys.argv) > 4:
        version = bytes.fromhex(sys.argv[4])
    mem = bytearray(raw)
    mem[8] = mem[4] ^ mem[5] ^ mem[6] ^ mem[7]  # BCC1
    npages = len(mem) // 4
    nfc = nfcnet.Nfc(host)
    mon = chipmon.Mon(nfc, on_other=lambda p: None)
    mon.load("emu.bin")
    base, logp, memp = struct.unpack("<III", mon._do(OP_EMU, 0))
    print(f"struct emu at {base:05X}, {npages} pages")
    hdr = bytes([0, npages, 3, 0]) + version + sig + cnt + bytes(2)
    mon.write(base, hdr)
    for i in range(0, len(mem), chipmon.CHUNK):
        mon.write(memp + i, bytes(mem[i:i + chipmon.CHUNK]))
    mon.write(base + O_MODE, b"\1")
    uid = bytes(mem[0:3] + mem[4:8])
    tl = bytes.fromhex("300104" "310100" "320100") + bytes([0x33, 7]) + uid
    cmds = [bytes([0x20, 0x02, len(tl) + 1, 4]) + tl, bytes.fromhex("2100040104" "0202"),
            bytes.fromhex("200204018001" "01"), bytes.fromhex("2103030180" "01")]
    for c in cmds:
        for p in nfc.cmd(b"\x10" + c):
            print("  " + nfcnet.describe(p))
    end = time.time() + secs
    poll = time.time() + 2
    while time.time() < end:
        if time.time() > poll:  # live counters while listening
            poll = time.time() + 2
            print("  live frames/writes/nlog", struct.unpack("<III", mon._do(chipmon.OP_READ8, base + O_FRAMES, bytes([12]))))
        for p in nfc.drain(100):
            print(f"{time.time() % 100:6.2f} " + nfcnet.describe(p))
            if p[:3] == b"\x10\x61\x06" and p[4] == 0:
                time.sleep(0.1)
                nfc.write(bytes.fromhex("10" "2103030180" "01"))
    for p in nfc.cmd(bytes.fromhex("1021060100")):
        print("  " + nfcnet.describe(p))
    frames, writes, nlog = struct.unpack("<III", mon._do(chipmon.OP_READ8, base + O_FRAMES, bytes([12])))
    log = mon._do(chipmon.OP_READ8, logp, bytes([128]))
    print(f"frames {frames} writes {writes} log {nlog}")
    for i in range(max(0, nlog - 16), nlog):
        e = log[(i % 16) * 8:(i % 16) * 8 + 8]
        print(f"  state {e[0]} len {e[1]:2} {e[2:2 + min(e[1], 6)].hex(' ')}")
    after = mon._do(chipmon.OP_READ8, memp, bytes([min(len(mem), chipmon.CHUNK)]))
    if after != bytes(mem[:len(after)]):
        print("mem changed:", after.hex())


if __name__ == "__main__":
    main()
