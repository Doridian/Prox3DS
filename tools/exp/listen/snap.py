#!/usr/bin/env python3
"""Listen-A with a distinctive UID DE AD BE EF / ATQA 0344 / SAK 28: dump 0x5C000-0x5C7FF while
listening, then again once the reader's field is on; diff and grep for the config values.
    snap.py HOST          env PRE: NCI commands (hex, no 10 prefix) sent first"""
import sys
import time

sys.path.insert(0, __file__.rsplit("/", 3)[0])
import chipmon
import nfcnet

field = []


def other(p):
    print("  (ntf) " + nfcnet.describe(p))
    if p[1:4] == b"\x61\x07\x01":
        field.append(p[4])


def dump(mon):
    out = {}
    for base in range(0x5C000, 0x5C800, 0xF0):
        n = min(60, (0x5C800 - base) // 4)
        for i, v in enumerate(mon.read32(base, n)):
            out[base + 4 * i] = v
    return out


def main():
    nfc = nfcnet.Nfc(sys.argv[1])
    mon = chipmon.Mon(nfc, on_other=other)
    mon.load()
    for c in __import__("os").environ.get("PRE", "").split() + ["20021004" "300144" "310103" "320128" "3304DEADBEEF",
              "21000401040202", "200204018001" "01", "2103030180" "01"]:
        for p in nfc.cmd(bytes.fromhex("10" + c)):
            other(p)
    time.sleep(0.3)
    a = dump(mon)
    print("waiting for field...")
    while not field or field[-1] != 1:
        for p in nfc.drain(50):
            other(p)
    b = dump(mon)
    print("diff listen -> field on:")
    for k in sorted(a):
        if a[k] != b[k]:
            print(f"  {k:05X} {a[k]:08X} -> {b[k]:08X}")
    print("field-on nonzero:")
    print(" ".join(f"{k:05X}={v:X}" for k, v in sorted(b.items()) if v))
    for c in ["1021060100"]:
        for p in nfc.cmd(bytes.fromhex(c)):
            other(p)


if __name__ == "__main__":
    main()
