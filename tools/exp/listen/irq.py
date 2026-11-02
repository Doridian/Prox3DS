#!/usr/bin/env python3
"""Listen-A through the ROM with chip/lmon.bin's IRQ log (all IRQ0..7, five watched registers).
    irq.py HOST [SECONDS]
env: CFG = NCI commands (hex, no 10 prefix), MASK = IRQ mask (default FF), CHG = 1 log changes
only, WATCH = 5 register addresses (hex)."""
import os
import struct
import sys
import time

sys.path.insert(0, __file__.rsplit("/", 3)[0])
import chipmon
import nfcnet

N_LOG, ENT = 128, 16
CFG = os.environ.get("CFG", "").split() or [
    "20021004" "300104" "310100" "320120" "330401020304",
    "21000401040202", "200204018001" "01", "2103030180" "01"]
WATCH = [int(a, 16) for a in os.environ.get("WATCH", "5C5C0 5C580 5C554 5C5C8 5C588").split()]


def main():
    nfc = nfcnet.Nfc(sys.argv[1])
    secs = float(sys.argv[2]) if len(sys.argv) > 2 else 20
    mon = chipmon.Mon(nfc, on_other=lambda p: print(f"{time.time() % 100:6.2f} (ntf) " + nfcnet.describe(p)))
    mon.read = lambda addr, n: b"".join(mon._do(chipmon.OP_READ8, a, bytes([min(200, addr + n - a)]))
                                        for a in range(addr, addr + n, 200))
    mon.load(os.environ.get("IMG", "lmon.bin"))
    arg = bytes([int(os.environ.get("MASK", "FF"), 16), int(os.environ.get("CHG", "0"))])
    sup = bytes([int(os.environ.get("SUP", "0"), 16)])
    ring = struct.unpack("<I", mon._do(5, 0, arg + struct.pack("<5I", *WATCH) + sup))[0]
    for c in CFG:
        for p in nfc.cmd(bytes.fromhex("10" + c)):
            print("  " + nfcnet.describe(p))
    print("watch: " + " ".join(f"{a:05X}" for a in WATCH))
    seen, last_t = 0, None
    end = time.time() + secs
    while time.time() < end:
        raw = mon.read(ring, 4 + N_LOG * ENT)
        count = struct.unpack_from("<I", raw)[0]
        if count - seen > N_LOG:
            print(f"  ({count - seen - N_LOG} lost)")
            seen = count - N_LOG
        for i in range(seen, count):
            o = 4 + (i % N_LOG) * ENT
            t, irq, sup_, *vals = struct.unpack_from("<IBB5H", raw, o)
            dt = "" if last_t is None else f"+{(last_t - t) & 0xFFFFFFFF}"
            last_t = t
            print(f"{time.time() % 100:6.2f} #{i} irq{irq}{"S" if sup_ else " "} {' '.join(f'{v:4X}' for v in vals)} {dt}")
        seen = count
        for p in nfc.drain(30):
            print(f"{time.time() % 100:6.2f} " + nfcnet.describe(p))
    for p in nfc.cmd(bytes.fromhex("1021060100")):
        print("  " + nfcnet.describe(p))


if __name__ == "__main__":
    main()
