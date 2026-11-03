"""ISO 9796-2 scheme 1 with SHA-1 and trailer BC, the way Bouncy Castle's ISO9796d2Signer lays it out: the
reference for Signature.ALG_RSA_SHA_ISO9796 (gen.py, check.py)."""
import hashlib


def encode(m, mod_bits):
    k = (mod_bits + 7) // 8
    h = hashlib.sha1(m).digest()
    x = (20 + len(m)) * 8 + 8 + 4 - mod_bits
    mr = len(m) - (x + 7) // 8 if x > 0 else len(m)
    header = 0x60 if x > 0 else 0x40
    em = bytearray(k)
    em[-1] = 0xBC
    em[k - 21:k - 1] = h
    delta = k - 21 - mr
    em[delta:delta + mr] = m[:mr]
    if delta > 1:
        em[1:delta] = b"\xBB" * (delta - 1)
        em[delta - 1] ^= 1
        em[0] = 0x0B | header
    else:
        em[0] = 0x0A | header
    return bytes(em)


def sign(d, n, m):
    k = (n.bit_length() + 7) // 8
    return pow(int.from_bytes(encode(m, n.bit_length()), "big"), d, n).to_bytes(k, "big")
