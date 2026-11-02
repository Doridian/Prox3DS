#!/usr/bin/env python3
"""Listen-A, then sample a register on-chip (lmon OP_SAMPLE) while a reader field is applied;
print the run-length encoded trace.   sample.py HOST REG INTERVAL_US COUNT [DELAY_S]
env PRE: NCI commands (hex, no 10 prefix) sent before the listen setup.
Starts sampling DELAY_S (default 3) after the listen setup. SWALLOW (6th arg) 1 = lmon acks the
framer interrupts and the ROM's handler never runs."""
import struct
import sys
import time

sys.path.insert(0, __file__.rsplit("/", 3)[0])
import chipmon
import nfcnet


def main():
    nfc = nfcnet.Nfc(sys.argv[1])
    reg, iv, cnt = int(sys.argv[2], 16), int(sys.argv[3]), int(sys.argv[4])
    delay = float(sys.argv[5]) if len(sys.argv) > 5 else 3
    mon = chipmon.Mon(nfc, on_other=lambda p: print("  (ntf) " + nfcnet.describe(p)))
    mon.read = lambda addr, n: b"".join(mon._do(chipmon.OP_READ8, a, bytes([min(200, addr + n - a)]))
                                        for a in range(addr, addr + n, 200))
    mon.load("lmon.bin")
    for c in __import__("os").environ.get("PRE", "").split() + ["20021004" "300104" "310100" "320120" "330401020304",
              "21000401040202", "200204018001" "01", "2103030180" "01"]:
        nfc.cmd(bytes.fromhex("10" + c))
    if len(sys.argv) > 6:  # swallow mode: lmon acks framer IRQs itself, the ROM never sees them
        mon._do(5, 0, bytes([1, 0]) + struct.pack("<5I", 0x5C5C4, 0x5C5D0, 0x5C580, 0x5C5A0, 0x5C588)
                + bytes([0, int(sys.argv[6])]))
    print("listening", flush=True)
    time.sleep(delay)
    for poke in __import__("os").environ.get("POKE", "").split():  # addr=val[,val...] 32-bit writes
        a, vs = poke.split("=")
        for v in vs.split(","):
            mon.write32(int(a, 16), [int(v, 16)])
    buf = struct.unpack("<I", mon._do(6, reg, struct.pack("<HH", iv, cnt), timeout_ms=5000))[0]
    s = struct.unpack(f"<{cnt}H", mon.read(buf, 2 * cnt))
    runs, start = [], 0
    for i in range(1, cnt + 1):
        if i == cnt or s[i] != s[start]:
            runs.append(f"{s[start]:X}x{i - start}")
            start = i
    print(f"{reg:05X} every {iv} us: " + " ".join(runs))
    for p in nfc.drain(100):
        print("  " + nfcnet.describe(p))
    nfc.cmd(bytes.fromhex("1021060100"))


if __name__ == "__main__":
    main()
