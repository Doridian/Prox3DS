#!/usr/bin/env python3
"""Re-arm timing after a listen session ends (deactivation to idle): listen A as stock.py (ISO-DEP,
echo + 9000), and after each deactivation to idle send RF_DISCOVER again DELAY ms later. Every packet
is printed with a ms timestamp. Env SNAP=1: 32-bit dump of the RF block registers SNAPMS ms after each
re-arm (for diffing a good re-arm against a bad one).

    rearm.py HOST DELAY_MS [SECONDS]
"""
import os
import sys
import time

sys.path.insert(0, __file__.rsplit("/", 3)[0])
import chipmon
import nfcnet

LISTEN = bytes.fromhex("10" "2103030180" "01")
REGS = [(0x5C000, 0x80), (0x5C400, 0x100), (0x5C540, 0x30), (0x5C640, 0x30)]  # (addr, words)


def main():
    host, delay = sys.argv[1], float(sys.argv[2]) / 1000
    secs = float(sys.argv[3]) if len(sys.argv) > 3 else 30
    snap = os.environ.get("SNAP") == "1"
    snap_after = float(os.environ.get("SNAPMS", "300")) / 1000
    nfc = nfcnet.Nfc(host)
    mon = chipmon.Mon(nfc)
    mon.load()
    for c in ["20021004" "300104" "310100" "320120" "330401020304",
              "21000401" "040202",
              "200204018001" "01",
              "2103030180" "01"]:
        for p in nfc.cmd(bytes.fromhex("10" + c)):
            print("  " + nfcnet.describe(p))
    t0 = time.time()
    ms = lambda: f"{(time.time() - t0) * 1000:8.1f}"
    rearm_at = snap_at = None
    n = 0
    end = t0 + secs
    while time.time() < end:
        now = time.time()
        if rearm_at and now >= rearm_at:
            if os.environ.get("MODE") == "call":  # the RF state machine's discovery event, no RF_DISCOVER
                st = mon.read(0x39E92, 1)[0]
                r = mon.call(0x1AB6A, 5)
                print(f"{ms()} re-arm: state {st:X}, event 5 -> {r:X}, state {mon.read(0x39E92, 1)[0]:X}")
            else:
                nfc.write(LISTEN)
                print(f"{ms()} re-arm")
            rearm_at, snap_at = None, (time.time() + snap_after if snap else None)
        if snap_at and now >= snap_at:
            snap_at = None
            n += 1
            for a, w in REGS:
                v = mon.read32(a, w)
                print(f"{ms()} snap{n} {a:05X}: " + " ".join(f"{x:X}" for x in v))
        for p in nfc.drain(int(os.environ.get("DRAIN", "2"))):
            print(f"{ms()} " + nfcnet.describe(p))
            if p[0] == 0x10 and p[1] >> 5 == 0 and len(p) > 4:
                ans = p[4:] + b"\x90\x00"
                nfc.write(bytes([0x10, 0x00, 0x00, len(ans)]) + ans)
            if p[:3] == b"\x10\x61\x06" and p[4] == 0:
                rearm_at = time.time() + delay
    for p in nfc.cmd(bytes.fromhex("1021060100")):
        print("  " + nfcnet.describe(p))


if __name__ == "__main__":
    main()
