#!/usr/bin/env python3
"""Listen-A through the ROM with the monitor's RX capture on: snapshot framer registers while
listening, print captured frames + NTFs while a reader runs.   cap.py HOST [SECONDS]"""
import sys
import time

sys.path.insert(0, __file__.rsplit("/", 3)[0])
import chipmon
import nfcnet

REGS = [(0x5C540, 32), (0x5C5C0, 12), (0x5C640, 36), (0x5C780, 16), (0x5C400, 32), (0x5C480, 32)]


def snap(mon):
    out = {}
    for base, words in REGS:
        for i, v in enumerate(mon.read32(base, words)):
            out[base + 4 * i] = v
    return out


def main():
    nfc = nfcnet.Nfc(sys.argv[1])
    secs = float(sys.argv[2]) if len(sys.argv) > 2 else 20
    mon = chipmon.Mon(nfc, on_other=lambda p: print("  (ntf) " + nfcnet.describe(p)))
    mon.load()
    # NTFs arrive between monitor answers: no pipelining (that path can't skip them)
    mon.read = lambda addr, n: b"".join(mon._do(chipmon.OP_READ8, a, bytes([min(200, addr + n - a)]))
                                        for a in range(addr, addr + n, 200))
    idle = snap(mon)
    for c in ["20021004" "300104" "310100" "320120" "330401020304",
              "21000401040202", "200204018001" "01", "2103030180" "01"]:
        for p in nfc.cmd(bytes.fromhex("10" + c)):
            print("  " + nfcnet.describe(p))
    time.sleep(0.5)
    lis = snap(mon)
    print("listen vs idle:")
    for a in sorted(lis):
        if lis[a] != idle[a]:
            print(f"  {a:05X} {idle[a]:08X} -> {lis[a]:08X}")
    print("listen nonzero:", " ".join(f"{a:05X}={v:X}" for a, v in sorted(lis.items()) if v))
    mon.capture(True)
    end = time.time() + secs
    while time.time() < end:
        for regs, data in mon.frames():
            print(f"{time.time() % 100:6.2f} frame regs {' '.join(f'{r:X}' for r in regs)} data {data.hex()}")
        for p in nfc.drain(50):
            print(f"{time.time() % 100:6.2f} " + nfcnet.describe(p))
    mon.capture(False)
    for p in nfc.cmd(bytes.fromhex("1021060100")):
        print("  " + nfcnet.describe(p))


if __name__ == "__main__":
    main()
