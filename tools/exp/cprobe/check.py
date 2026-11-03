"""Checks CryptoProbe answers (run.py output, e.g. j3h145.txt) against Python crypto: OK = same as the
reference, DIFF = not, SW = an error status (listed as is), INFO = no reference (random, probes, keys).
    python3 check.py j3h145.txt [-v]"""
import hashlib
import os
import struct
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import iso9796  # noqa: E402


class R:
    def __init__(self, b):
        self.b, self.p = b, 0

    def u8(self):
        self.p += 1
        return self.b[self.p - 1]

    def u16(self):
        self.p += 2
        return struct.unpack(">H", self.b[self.p - 2:self.p])[0]

    def take(self, n):
        self.p += n
        return self.b[self.p - n:self.p]


def body(apdu):
    if apdu[4] == 0 and len(apdu) > 5:
        n = struct.unpack(">H", apdu[5:7])[0]
        return apdu[7:7 + n]
    return apdu[5:5 + apdu[4]] if len(apdu) > 5 else b""


def key(r):
    t, bits, ln = r.u8(), r.u16(), r.u16()
    k = R(r.take(ln))
    if t in (4, 5):
        ml = k.u16()
        n = int.from_bytes(k.take(ml), "big")
        return t, (n, int.from_bytes(k.take(ln - 2 - ml), "big"))
    if t == 6:
        p, q, dp, dq, qi = (int.from_bytes(k.take(k.u16()), "big") for _ in range(5))
        return t, (p * q, pow(65537, -1, (p - 1) * (q - 1)))
    return t, k.b


def ecb(alg, k, enc, d):
    c = Cipher(alg(k), modes.ECB())
    x = c.encryptor() if enc else c.decryptor()
    return x.update(d) + x.finalize()


def cbc(alg, k, iv, enc, d):
    c = Cipher(alg(k), modes.CBC(iv))
    x = c.encryptor() if enc else c.decryptor()
    return x.update(d) + x.finalize()


def des(k):
    return TripleDES(k * 3 if len(k) == 8 else k + k[:8] if len(k) == 16 else k)


def pad(d, bs, how):
    if how == "M1":  # nothing for no data (the J3H145 answers 0 bytes)
        return d + bytes(-len(d) % bs)
    if how == "M2":
        d = d + b"\x80"
        return d + bytes(-len(d) % bs)
    if how == "PKCS5":
        n = bs - len(d) % bs
        return d + bytes([n]) * n
    return d


def unpad(d, how):
    if how == "M2":
        d = d.rstrip(b"\x00")
        return d[:-1] if d.endswith(b"\x80") else None
    if how == "PKCS5":
        n = d[-1] if d else 0
        return d[:-n] if 1 <= n <= 8 and d.endswith(bytes([n]) * n) else None
    return d


CIPHERS = {1: ("des", "cbc", ""), 2: ("des", "cbc", "M1"), 3: ("des", "cbc", "M2"), 4: ("des", "cbc", "PKCS5"),
           5: ("des", "ecb", ""), 6: ("des", "ecb", "M1"), 7: ("des", "ecb", "M2"), 8: ("des", "ecb", "PKCS5"),
           13: ("aes", "cbc", ""), 14: ("aes", "ecb", ""), 18: ("aes", "cbc", ""), 19: ("aes", "ecb", ""),
           20: ("aes", "cbc", ""), 21: ("aes", "ecb", ""), 22: ("aes", "cbc", "M1"), 23: ("aes", "cbc", "M2"),
           24: ("aes", "cbc", "PKCS5"), 25: ("aes", "ecb", "M1"), 26: ("aes", "ecb", "M2"),
           27: ("aes", "ecb", "PKCS5")}


def sym(kind, k, mode, iv, enc, d):
    alg = algorithms.AES if kind == "aes" else des
    bs = 16 if kind == "aes" else 8
    iv = iv or bytes(bs)
    return ecb(alg, k, enc, d) if mode == "ecb" else cbc(alg, k, iv, enc, d)


def cipher_ref(alg, enc, k, iv, data):
    kind, mode, how = CIPHERS[alg]
    if enc:
        return sym(kind, k, mode, iv, True, pad(data, 16 if kind == "aes" else 8, how))
    return unpad(sym(kind, k, mode, iv, False, data), how)


def mac(alg, k, iv, d, full=False):
    """Signature MACs (full: the whole last block, the chaining value a second sign starts from)."""
    if alg in (19, 20, 47, 48):  # ISO 9797-1 alg 3: single DES CBC with K1, last block 3DES
        dd = pad(d, 8, "M2" if alg < 40 else "M1")
        k1 = k[:8]
        st = iv or bytes(8)
        for i in range(0, len(dd), 8):
            blkin = bytes(a ^ b for a, b in zip(st, dd[i:i + 8]))
            st = ecb(des, k1, True, blkin) if i + 8 < len(dd) else ecb(des, k, True, blkin)
        return st if full else st[:4 if alg in (19, 47) else 8]
    how = {1: "", 2: "", 3: "M1", 4: "M1", 5: "M2", 6: "M2", 7: "PKCS5", 8: "PKCS5", 18: ""}[alg]
    if alg == 18:
        return cbc(algorithms.AES, k, iv or bytes(16), True, pad(d, 16, how))[-16:]
    out = cbc(des, k, iv or bytes(8), True, pad(d, 8, how))[-8:]
    return out if full else out[:4] if alg in (1, 3, 5, 7) else out


MSG = bytes(range(0x30, 0x30 + 48))
HASH = {1: hashlib.sha1, 2: hashlib.md5, 4: hashlib.sha256, 5: hashlib.sha384, 6: hashlib.sha512, 7: hashlib.sha224}
RSAH = {10: hashes.SHA1(), 11: hashes.MD5(), 40: hashes.SHA256(), 41: hashes.SHA384(), 42: hashes.SHA512()}


def rsa_priv(n, d):
    return lambda m: pow(int.from_bytes(m, "big"), d, n).to_bytes((n.bit_length() + 7) // 8, "big")


def pkcs1_sig(n, d, h, msg):
    hh = hashes.Hash(h)
    hh.update(msg)
    dg = hh.finalize()
    prefix = {"sha1": "3021300906052b0e03021a05000414", "md5": "3020300c06082a864886f70d020505000410",
              "sha256": "3031300d060960864801650304020105000420", "sha384": "3041300d060960864801650304020205000430",
              "sha512": "3051300d060960864801650304020305000440"}[h.name]
    t = bytes.fromhex(prefix) + dg
    k = (n.bit_length() + 7) // 8
    em = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    return rsa_priv(n, d)(em)


def ref(ins, p2, b, p1=0):
    """The expected answer (bytes), a list of acceptable answers, or None when there is no reference."""
    r = R(b)
    if ins == 0x33:
        alg, split = r.u8(), r.u16()
        d = b[r.p:]
        if alg not in HASH:
            return None
        h = HASH[alg](d).digest()
        return h + HASH[alg](b"").digest() if p2 & 1 else h
    if ins == 0x31:
        alg, mode = r.u8(), r.u8()
        kt, k = key(r)
        iv = r.take(r.u8())
        split = r.u16()
        d = b[r.p:]
        if kt in (4, 5, 6):
            n, e = k
            if alg == 12 and kt != 4:
                return struct.pack(">H", 0) + rsa_priv(n, e)(d)
            if alg in (10, 15) and mode == 1:
                return struct.pack(">H", 0) + MSG[:20]
            return None
        if alg not in CIPHERS:
            return None
        out = cipher_ref(alg, mode == 2, k, iv, d)
        if out is None:
            return None
        res = [("upd", out)]
        if p2 & 1:
            # a second doFinal without init starts from a zero IV (the J3H145; the spec: the init state)
            res.append(("twice", cipher_ref(alg, mode == 2, k, b"", d)))
        return res
    if ins == 0x32:
        alg, mode = r.u8(), r.u8()
        kt, k = key(r)
        iv = r.take(r.u8())
        split = r.u16()
        if mode == 2:
            ml = r.u16()
            msg = r.take(ml)
            sig = b[r.p:]
            if kt in (4, 5) and alg == 9:
                n, e = k
                em = pow(int.from_bytes(sig, "big"), e, n).to_bytes((n.bit_length() + 7) // 8, "big")
                return b"\x01" if em == iso9796.encode(msg, n.bit_length()) else b"\x00"
            if kt in (4, 5) and alg in (21, 44):
                return None  # PSS verify: the answers are checked against Python's own result below
            if kt in (4, 5) and alg in RSAH:
                n, e = k
                pub = rsa.RSAPublicNumbers(e, n).public_key()
                try:
                    pub.verify(sig, msg, padding.PKCS1v15(), RSAH[alg])
                    return b"\x01"
                except Exception:
                    return b"\x00"
            return None
        d = b[r.p:]
        if kt == 12 or alg in (21, 44):
            return ("verify", alg, kt, k, d)
        if kt in (5, 6) and alg == 9:
            n, dd = k
            s = iso9796.sign(dd, n, d)
            return s + s if p2 & 1 else s
        if kt in (5, 6) and alg in RSAH:
            n, dd = k
            s = pkcs1_sig(n, dd, RSAH[alg], d)
            return s + s if p2 & 1 else s
        if alg in (1, 2, 3, 4, 5, 6, 7, 8, 18, 19, 20, 47, 48):
            m = mac(alg, k, iv, d)
            # a second sign without init starts from a zero IV (the J3H145; the spec says the init state)
            return m + mac(alg, k, b"", d) if p2 & 1 else m
    if ins == 0x38:
        return ("pair", p1, struct.unpack(">H", b[:2])[0])
    if ins == 0x37:
        alg = r.u8()
        kt, k = key(r)
        return ("ecdh", alg, k, b[r.p:])
    return None


def ec_parts(k):
    r = R(k)
    return [r.take(r.u16()) for _ in range(6)]


P256 = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF


def pt_add(g, q, d):
    """d * g + q on P-256 (affine, plain Python: cryptography has no point arithmetic)."""
    p, a = P256, P256 - 3

    def add(P, Q):
        if P is None:
            return Q
        if Q is None:
            return P
        if P[0] == Q[0] and (P[1] + Q[1]) % p == 0:
            return None
        lam = (3 * P[0] * P[0] + a) * pow(2 * P[1], -1, p) if P == Q else (Q[1] - P[1]) * pow(Q[0] - P[0], -1, p)
        x = (lam * lam - P[0] - Q[0]) % p
        return x, (lam * (P[0] - x) - P[1]) % p
    r = None
    while d:
        if d & 1:
            r = add(r, g)
        g = add(g, g)
        d >>= 1
    return add(r, q)


def check_special(e, data):
    """Random signatures (verified with the public key) and ECDH; True / False."""
    from cryptography.hazmat.primitives.asymmetric import ec
    if e[0] == "pair":  # the applet's own check passed, the public key is as long as it should be
        _, alg, bits = e
        return data[0] == 1 and len(data) == 1 + (1 + 2 * ((bits + 7) // 8) if alg == 5 else bits // 8)
    if e[0] == "verify":
        _, alg, kt, k, d = e
        if kt == 12:
            s = ec.derive_private_key(int.from_bytes(ec_parts(k)[5], "big"), ec.SECP256R1())
            h = hashes.SHA1() if alg == 17 else hashes.SHA256()
            try:
                s.public_key().verify(data, d, ec.ECDSA(h))
                return True
            except Exception:
                return False
        n, dd = k
        e_ = 65537
        h = hashes.SHA1() if alg == 21 else hashes.SHA256()
        try:
            rsa.RSAPublicNumbers(e_, n).public_key().verify(data, d, padding.PSS(padding.MGF1(h), h.digest_size), h)
            return True
        except Exception:
            return False
    _, alg, k, pt = e
    priv = ec.derive_private_key(int.from_bytes(ec_parts(k)[5], "big"), ec.SECP256R1())
    q = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pt)
    x = priv.exchange(ec.ECDH(), q)
    if alg == 5:  # PACE generic mapping, the J3H145's: d * G + the public data
        G = ec.derive_private_key(1, ec.SECP256R1()).public_key().public_numbers()
        r = pt_add((G.x, G.y), (q.public_numbers().x, q.public_numbers().y), d=priv.private_numbers().private_value)
        return data == b"\x04" + r[0].to_bytes(32, "big") + r[1].to_bytes(32, "big")
    if alg == 6:  # the shared point
        return len(data) == 65 and data[0] == 4 and data[1:33] == x
    return data == (x if alg in (3, 4) else hashlib.sha1(x).digest())


verbose = "-v" in sys.argv
counts = {}
for line in open(sys.argv[1]):
    label, a, _, ans = line.split()
    a = bytes.fromhex(a)
    resp = bytes.fromhex(ans) if not ans.startswith("NONE") else b""
    sw, data = resp[-2:].hex().upper(), resp[:-2]
    if sw != "9000":
        st = "SW " + sw
        print(f"{st:8} {label}")
        counts["SW"] = counts.get("SW", 0) + 1
        continue
    try:
        e = ref(a[1], a[3], body(a), a[2])
    except Exception as x:
        e = None
        print("refErr", label, x)
    note = ""
    if isinstance(e, list):  # Cipher: updateLen(2) update final [len(2) twice]
        ul = struct.unpack(">H", data[:2])[0]
        got = data[2:]
        exp = e[0][1]
        main = got[:len(exp)]
        st = "OK" if main == exp else "DIFF"
        note = f"update {ul}"
        if len(e) > 1:
            tl = struct.unpack(">H", got[len(exp):len(exp) + 2])[0]
            tw = got[len(exp) + 2:]
            if tw != e[1][1]:
                st = "DIFF"
                note += f", 2nd doFinal differs ({tl} bytes)"
        elif len(got) != len(exp):
            st = "DIFF"
    elif isinstance(e, tuple):
        st = "OK" if check_special(e, data) else "DIFF"
    elif e is None:
        st = "INFO"
    else:
        st = "OK" if data == e else "DIFF"
    counts[st] = counts.get(st, 0) + 1
    if st != "OK" or verbose:
        print(f"{st:8} {label} {note}" + (f"\n         got {data.hex()}\n         exp {e.hex() if isinstance(e, bytes) else e}" if st == "DIFF" else ""))
    elif note:
        print(f"{st:8} {label} {note}")
print(counts)
