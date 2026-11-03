"""Bit sweep with parity off held (0x5C000 bit 2) and a 40-bit raw frame (A1 B2 C3 D4 + parity, 4 pad bits):
flip each bit of each register in the ranges during the TX, log time + pm3 decode to OUT. A test after which
the session breaks (time 0 from there on) is logged as a break and the rest requeued.
    sweep2.py OUT START-END[,START-END...] [SKIP,...]   (hex, END exclusive)"""
import json
import sys
import time

import pack
import pt

out = open(sys.argv[1], "a")
regs = []
for r in sys.argv[2].split(","):
    a, b = (int(x, 16) for x in r.split("-"))
    regs += range(a, b, 4)
skip = {int(x, 16) for x in sys.argv[3].split(",")} if len(sys.argv) > 3 else set()
regs = [a for a in regs if a not in skip]
DATA, _ = pack.pack(bytes([0xA1, 0xB2, 0xC3, 0xD4]))
FIX = [(0x5C000, 4, 1)]


def connect():
    while True:
        try:
            p = pt.PT()
            time.sleep(0.5)
            return p
        except Exception as e:
            print("  connect failed", e, flush=True)
            time.sleep(5)


p = connect()
queue = []
for a in regs:
    try:
        v = p.mon.read32(a, 1)[0]
    except Exception as e:
        print(f"{a:05X} read failed {e!r}", flush=True)
        p = connect()
        continue
    queue += [(a, 1 << b, 2 if v >> b & 1 else 1) for b in range(32)]
print(len(queue), "tests", flush=True)
fails = 0
while queue:
    batch, queue = queue[:63], queue[63:]
    tests = [None] + batch
    try:
        times, ans = pt.session(p, tests, data=DATA, fixed=FIX)
        fails = 0
    except Exception as e:
        print("session failed", repr(e), flush=True)
        queue = batch + queue
        fails += 1
        try:
            p.nfc.sock.close()
        except Exception:
            pass
        p = connect()
        if fails > 3:
            print("giving up on", batch[0], flush=True)
            out.write(json.dumps({"stuck": batch[0]}) + "\n")
            queue = batch[1:] + queue[len(batch):]
            fails = 0
        continue
    base = times[0]
    n = len(tests)
    while n > 1 and times[n - 1] == 0:
        n -= 1
    for i in range(1, n):
        out.write(json.dumps({"t": tests[i], "time": times[i], "base": base, "ans": ans[i] if i < len(ans) else ""}) + "\n")
        if abs(times[i] - base) > 8:
            print(f"  {tests[i][0]:05X} bit {tests[i][1].bit_length() - 1} {'set' if tests[i][2] == 1 else 'clr'}: "
                  f"{times[i]} (base {base}) {ans[i] if i < len(ans) else ''}", flush=True)
    if n < len(tests):
        brk = tests[n]
        print(f"  break after {brk[0]:05X} bit {brk[1].bit_length() - 1}", flush=True)
        out.write(json.dumps({"break": brk}) + "\n")
        queue = list(tests[n + 1:]) + queue
    out.flush()
    print(f"left {len(queue)}", flush=True)
p.stop()
print("done", flush=True)
