"""Reader-mode length sweep (memrw, a card activated on the 3DS): flip each bit of each register in the ranges
around a 21-byte parity-off bit-mode TX with length code 0x42 (160 bits: the last byte is dropped, its index
20 doesn't fit [6:4]) and log the TX busy time; looking for 162 bits (~1539 ticks), i.e. a register holding
the index's upper bits.   rsweep.py OUT START-END[,...] [SKIP,...]"""
import json
import sys
import time

sys.path.insert(0, __file__.rsplit("/", 3)[0])
import chipmon
import mfc
import nfcnet

out = open(sys.argv[1], "a")
regs = []
for r in sys.argv[2].split(","):
    a, b = (int(x, 16) for x in r.split("-"))
    regs += range(a, b, 4)
skip = {int(x, 16) for x in sys.argv[3].split(",")} if len(sys.argv) > 3 else set()
DATA, CODE = bytes([0x55] * 21), 0x42
s = mfc.Session("192.0.2.6")
s.recover()
m = s.mon


def base():
    s.parity(False)
    try:
        return m.txsched(DATA, CODE, [], r574=1)
    finally:
        s.parity(True)


b0 = base()
print("base", b0, flush=True)
for a in regs:
    if a in skip:
        continue
    try:
        v = m.read32(a, 1)[0]
    except (chipmon.MonError, nfcnet.NfcError, OSError) as e:
        print(f"{a:05X} read failed {e}", flush=True)
        s.reconnect(); s.recover(); m = s.mon
        continue
    for bit in range(32):
        nv = v ^ (1 << bit)
        try:
            s.parity(False)
            m.write32(a, [nv])
            t = m.txsched(DATA, CODE, [], r574=1)
            m.write32(a, [v])
            s.parity(True)
        except (chipmon.MonError, nfcnet.NfcError, OSError) as e:
            print(f"  {a:05X} bit {bit}: hang ({e})", flush=True)
            out.write(json.dumps({"a": a, "bit": bit, "hang": True}) + "\n")
            s.reconnect(); s.recover(); m = s.mon
            continue
        out.write(json.dumps({"a": a, "bit": bit, "v": v, "t": t}) + "\n")
        if abs(t - b0) > 6:
            print(f"  {a:05X} bit {bit} ({'set' if nv >> bit & 1 else 'clr'}): {t}", flush=True)
    out.flush()
    try:
        ok = base() == b0
    except (chipmon.MonError, nfcnet.NfcError, OSError):
        ok = False
    if not ok:
        print(f"{a:05X} left the framer broken: reload", flush=True)
        out.write(json.dumps({"a": a, "broken": True}) + "\n")
        s.reconnect(); s.recover(); m = s.mon
    print(f"{a:05X} done", flush=True)
print("done", flush=True)
