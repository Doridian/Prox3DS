#!/usr/bin/env python3
"""Listen-A with lmon swallow 2: framer registers (0x5C540-5FF, 0x5C640-6FF) at idle, at the
field-on interrupt and at the field-lost interrupt, no ROM handling in between.
    snapdiff.py HOST [SECONDS]"""
import struct
import sys
import time

sys.path.insert(0, __file__.rsplit("/", 3)[0])
import chipmon
import nfcnet

ADDRS = [0x5C540 + 4 * i for i in range(48)] + [0x5C640 + 4 * i for i in range(48)]


def main():
    nfc = nfcnet.Nfc(sys.argv[1])
    secs = float(sys.argv[2]) if len(sys.argv) > 2 else 5
    mon = chipmon.Mon(nfc, on_other=lambda p: print("  (ntf) " + nfcnet.describe(p)))
    mon.read = lambda addr, n: b"".join(mon._do(chipmon.OP_READ8, a, bytes([min(200, addr + n - a)]))
                                        for a in range(addr, addr + n, 200))
    mon.load("lmon.bin")
    for c in ["20021004" "300104" "310100" "320120" "330401020304",
              "21000401040202", "200204018001" "01", "2103030180" "01"]:
        nfc.cmd(bytes.fromhex("10" + c))
    time.sleep(0.2)
    idle = [v for base in (0x5C540, 0x5C640) for v in mon.read32(base, 48)]
    ring = struct.unpack("<I", mon._do(5, 0, bytes([0, 0]) + bytes(20) + bytes([0, 2])))[0]
    print("listening", flush=True)
    time.sleep(secs)
    raw = mon.read(ring + 4, 2 * 96 * 4)
    on = struct.unpack_from("<96I", raw, 0)
    lost = struct.unpack_from("<96I", raw, 384)
    print(" addr      idle    fieldon  fieldlost")
    for a, i, o, l in zip(ADDRS, idle, on, lost):
        if a in (0x5C600, 0x5C620):
            continue
        if not (i == o == l):
            print(f"{a:05X} {i:9X} {o:9X} {l:9X}")
    nfc.cmd(bytes.fromhex("1021060100"))


if __name__ == "__main__":
    main()
