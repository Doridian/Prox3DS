#!/usr/bin/env python3
"""NFC-A polling through the ROM's normal NCI path, with the debug monitor loaded, plus framer
register snapshots (tools/chipmon.py) to learn the register semantics.

    rfpoll.py HOST [SECONDS]    load monitor, discover NFC-A, print activation + register diffs
"""
import struct
import sys
import time

import chipmon
import nfcnet

# Framer registers worth snapshotting; 0x5C600 (TX port) and 0x5C620 (RX port) are left out
# because reading the RX port pops the FIFO.
REGS = [(0x5C540, 32), (0x5C5C0, 12), (0x5C640, 16), (0x5C680, 16), (0x5C6C0, 4), (0x5C780, 16)]


def snapshot(mon):
    regs = {}
    for base, words in REGS:
        for i, v in enumerate(mon.read32(base, words)):
            regs[base + 4 * i] = v
    return regs


def show(label, regs, prev=None):
    changed = [a for a in sorted(regs) if prev is None or prev.get(a) != regs[a]]
    print(f"--- {label}: {len(changed)} regs" + (" changed" if prev else ""))
    for a in changed:
        was = f"  (was {prev[a]:08X})" if prev else ""
        print(f"  {a:05X} = {regs[a]:08X}{was}")


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    secs = float(sys.argv[2]) if len(sys.argv) > 2 else 10
    nfc = nfcnet.Nfc(sys.argv[1])
    mon = chipmon.Mon(nfc)
    mon.load()
    idle = snapshot(mon)
    show("idle after init", idle)
    # RF_DISCOVER_MAP (required before RF_DISCOVER, sets RAM 0x3872C): T2T and ISO-DEP -> Frame
    # interface in poll mode; then RF_DISCOVER: NFC-A passive poll, every period.
    for pkt in ("1021000701020101040101", "10210303010001"):
        for p in nfc.cmd(bytes.fromhex(pkt)):
            print("  " + nfcnet.describe(p))
    end = time.time() + secs
    prev, activated = idle, False
    while time.time() < end:
        for p in nfc.drain(100):
            print("  " + nfcnet.describe(p))
            if p[1:3] == b"\x61\x05":
                activated = True
        cur = snapshot(mon)
        show("discovering" if not activated else "activated", cur, prev)
        prev = cur
        if activated:
            break
    for p in nfc.cmd(bytes.fromhex("1021060100")):  # RF_DEACTIVATE idle
        print("  " + nfcnet.describe(p))


if __name__ == "__main__":
    main()
