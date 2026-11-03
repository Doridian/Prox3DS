#!/usr/bin/env python3
"""Raw ISO15693-coded TX for iClass: stall the ROM in a V poll (capture on before RF_DISCOVER 76,
I93_DATARATE B7 = 2), set the V coder (0x5C554 = 18) at high rate (0x5C558), no CRC (0x5C560 = 0C),
then send the given frames through reader.c's txsched; check with pm3 `hf iclass sniff -t`.

    vtx.py HOST FRAME_HEX... (default 0A = ACTALL, 0C = IDENTIFY)
env: R558 (default 5), R560 (default C), R55C (default 88), REPEAT (default 5), GAP (s, default 0.3),
POKE = "addr=val ..." register writes before each round, SCHED = "ticks:addr=val ..." timed stores
after the FIFO write (txsched)."""
import os
import sys
import time

sys.path.insert(0, __file__.rsplit("/", 3)[0])
import chipmon
import nfcnet


def env(name, default):
    return int(os.environ.get(name, default), 16)


def main():
    nfc = nfcnet.Nfc(sys.argv[1])
    frames = [bytes.fromhex(f) for f in sys.argv[2:]] or [b"\x0a", b"\x0c"]
    mon = chipmon.Mon(nfc, on_other=lambda p: print("  (ntf) " + nfcnet.describe(p)))
    mon.load()
    for c in ["20020401B70102", "21000401830183"]:
        nfc.cmd(bytes.fromhex("10" + c))
    mon.capture(True)
    nfc.write(bytes.fromhex("10210303017601"))  # stalls with capture on: the answer may not come
    time.sleep(0.5)
    print("ready", flush=True)
    time.sleep(float(os.environ.get("DELAY", "1.5")))
    sched = []
    for e in os.environ.get("SCHED", "").split():
        t, av = e.split(":")
        a, v = av.split("=")
        sched.append((int(t), int(a, 16), int(v, 16)))
    for _ in range(int(os.environ.get("REPEAT", "5"))):
        mon.write32(0x5C554, [0x18])
        mon.write32(0x5C558, [env("R558", "5")])
        mon.write32(0x5C560, [env("R560", "C")])
        for poke in os.environ.get("POKE", "").split():
            a, v = poke.split("=")
            mon.write32(int(a, 16), [int(v, 16)])
        for f in frames:
            busy = mon.txsched(f, len(f) << 4, sched, r570=1, r574=5, r55c=env("R55C", "88"))
            print(f"tx {f.hex()} busy {busy} us", flush=True)
            time.sleep(0.02)
        for regs, data in mon.frames():
            print(f"rx {data.hex()} regs {' '.join(f'{r:X}' for r in regs)}", flush=True)
        time.sleep(float(os.environ.get("GAP", "0.3")))
    mon.capture(False)
    nfc.cmd(bytes.fromhex("1021060100"))


if __name__ == "__main__":
    main()
