#!/usr/bin/env python3
"""Repeated 0x5C000-0x5C7FF dumps while listening; print what changes between dumps.
    seq.py HOST [SECONDS]"""
import sys
import time

sys.path.insert(0, __file__.rsplit("/", 3)[0])
import chipmon
import nfcnet

SKIP = {0x5C600, 0x5C620}  # FIFO ports (reads pop)


def dump(mon):
    out = {}
    for base in range(0x5C000, 0x5C800, 0xF0):
        n = min(60, (0x5C800 - base) // 4)
        for i, v in enumerate(mon.read32(base, n)):
            if base + 4 * i not in SKIP:
                out[base + 4 * i] = v
    return out


def main():
    nfc = nfcnet.Nfc(sys.argv[1])
    secs = float(sys.argv[2]) if len(sys.argv) > 2 else 20
    t0 = time.time()
    mon = chipmon.Mon(nfc, on_other=lambda p: print(f"{time.time() - t0:7.3f} (ntf) " + nfcnet.describe(p)))
    mon.load("lmon.bin")
    for c in ["20021004" "300104" "310100" "320120" "330401020304",
              "21000401040202", "200204018001" "01", "2103030180" "01"]:
        nfc.cmd(bytes.fromhex("10" + c))
    prev = dump(mon)
    t0 = time.time()
    while time.time() - t0 < secs:
        cur = dump(mon)
        ch = [a for a in sorted(cur) if cur[a] != prev[a]]
        if ch:
            print(f"{time.time() - t0:7.3f} " + " ".join(f"{a:05X}:{prev[a]:X}>{cur[a]:X}" for a in ch))
        prev = cur
    nfc.cmd(bytes.fromhex("1021060100"))


if __name__ == "__main__":
    main()
