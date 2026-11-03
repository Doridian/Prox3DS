"""APDUs for javacard/cprobe (CryptoProbe): writes cases.txt, one `label apdu` per line. The RSA keys and
the random values (Python's RSA encryptions, PSS / ECDSA signatures) are made once and kept in rsa.json /
fixed.json so the cases stay the same between runs."""
import json
import os
import struct

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

D = os.path.dirname(os.path.abspath(__file__))
SEL = "00A4040007F0334453504D03"


def apdu(ins, p1, p2, data=b""):
    h = bytes([0x80, ins, p1, p2])
    if len(data) > 255:
        return h + b"\x00" + struct.pack(">H", len(data)) + data + b"\x00\x00"
    return h + (bytes([len(data)]) + data if data else b"") + b"\x00"


def key(t, bits, k):
    return bytes([t]) + struct.pack(">HH", bits, len(k)) + k


def rsakey(t, bits, mod, exp):
    m = mod.to_bytes(bits // 8, "big")
    e = exp.to_bytes((exp.bit_length() + 7) // 8, "big")
    return key(t, bits, struct.pack(">H", len(m)) + m + e)


def rsa_keys():
    f = os.path.join(D, "rsa.json")
    if not os.path.exists(f):
        ks = {}
        for b in (1024, 2048):
            k = rsa.generate_private_key(65537, b)
            ks[b] = k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption()).decode()
        json.dump(ks, open(f, "w"), indent=1)
    return {int(b): serialization.load_pem_private_key(v.encode(), None) for b, v in json.load(open(f)).items()}


cases = []
FIXED = os.path.join(D, "fixed.json")
fixed = json.load(open(FIXED)) if os.path.exists(FIXED) else {}


def once(name, fn):
    if name not in fixed:
        fixed[name] = fn().hex()
    return bytes.fromhex(fixed[name])


def add(label, ins, p1, p2, data=b""):
    cases.append((label, apdu(ins, p1, p2, data)))


DES8 = bytes.fromhex("0123456789ABCDEF")
DES16 = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
DES24 = DES16 + bytes.fromhex("89ABCDEF01234567")
AES = bytes(range(32))
IV8 = bytes.fromhex("1122334455667788")
IV16 = bytes(range(0xA0, 0xB0))
MSG = bytes(range(0x30, 0x30 + 48))

add("probe Cipher 1..40", 0x30, 0, 40)
add("probe Signature 1..64", 0x30, 1, 64)
add("probe MessageDigest 1..10", 0x30, 2, 10)
add("probe RandomData 1..6", 0x30, 3, 6)

for t, bits in [(3, 64), (3, 128), (3, 192), (3, 100), (1, 128), (2, 192), (15, 128), (15, 192), (15, 256),
                (15, 64), (13, 128), (14, 256), (19, 64), (19, 128), (19, 256), (20, 64), (4, 1024), (5, 2048),
                (6, 1024)]:
    add(f"key type {t} {bits} bits", 0x36, t, 0, struct.pack(">H", bits))

# DES with bad parity bytes: does setKey / getKey change them?
add("key DES no parity getKey", 0x31, 0, 0, bytes([5, 2]) + key(3, 64, bytes(range(8))) + b"\x00"
    + struct.pack(">H", 0) + bytes(8))


def ciph(label, alg, mode, k, iv, data, split=0, flags=0):
    add(label, 0x31, 0, flags, bytes([alg, mode]) + k + bytes([len(iv)]) + iv + struct.pack(">H", split) + data)


DESK = [("DES", key(3, 64, DES8)), ("3DES2", key(3, 128, DES16)), ("3DES3", key(3, 192, DES24))]
for alg, name in [(1, "DES_CBC_NOPAD"), (2, "DES_CBC_M1"), (3, "DES_CBC_M2"), (4, "DES_CBC_PKCS5"),
                  (5, "DES_ECB_NOPAD"), (6, "DES_ECB_M1"), (7, "DES_ECB_M2"), (8, "DES_ECB_PKCS5")]:
    for kn, k in DESK:
        for ln in (16, 13, 0):
            ciph(f"{name} {kn} enc {ln}", alg, 2, k, b"", MSG[:ln])
    ciph(f"{name} 3DES2 enc 16 iv", alg, 2, DESK[1][1], IV8, MSG[:16])
    ciph(f"{name} 3DES2 enc 24 split 5 twice", alg, 2, DESK[1][1], IV8, MSG[:24], 5, 1)
    ciph(f"{name} 3DES2 enc 24 split 8", alg, 2, DESK[1][1], b"", MSG[:24], 8)
    ciph(f"{name} 3DES2 enc 24 split 11", alg, 2, DESK[1][1], b"", MSG[:24], 11)
    ciph(f"{name} 3DES2 dec 16", alg, 1, DESK[1][1], b"", MSG[:16])
    ciph(f"{name} 3DES2 dec 16 split 3 twice", alg, 1, DESK[1][1], IV8, MSG[:16], 3, 1)
    ciph(f"{name} 3DES2 dec 13", alg, 1, DESK[1][1], b"", MSG[:13])
    ciph(f"{name} 3DES2 bad iv 4", alg, 2, DESK[1][1], IV8[:4], MSG[:16])
# decrypt valid padding: ciphertext of 13 bytes padded M2 / PKCS5 with 3DES2 ECB is checked against Python later
AESK = [("AES128", key(15, 128, AES[:16])), ("AES192", key(15, 192, AES[:24])), ("AES256", key(15, 256, AES))]
for alg, name in [(13, "AES_128_CBC_NOPAD"), (14, "AES_128_ECB_NOPAD"), (18, "AES_192_CBC_NOPAD"),
                  (19, "AES_192_ECB_NOPAD"), (20, "AES_256_CBC_NOPAD"), (21, "AES_256_ECB_NOPAD"),
                  (22, "AES_CBC_M1"), (23, "AES_CBC_M2"), (24, "AES_CBC_PKCS5"), (25, "AES_ECB_M1"),
                  (26, "AES_ECB_M2"), (27, "AES_ECB_PKCS5")]:
    for kn, k in AESK:
        ciph(f"{name} {kn} enc 32", alg, 2, k, b"", MSG[:32])
    ciph(f"{name} AES128 enc 20", alg, 2, AESK[0][1], b"", MSG[:20])
    ciph(f"{name} AES128 enc 0", alg, 2, AESK[0][1], b"", b"")
    ciph(f"{name} AES128 enc 32 iv", alg, 2, AESK[0][1], IV16, MSG[:32])
    ciph(f"{name} AES128 enc 48 split 7 twice", alg, 2, AESK[0][1], IV16, MSG[:48], 7, 1)
    ciph(f"{name} AES128 enc 48 split 16", alg, 2, AESK[0][1], b"", MSG[:48], 16)
    ciph(f"{name} AES128 enc 48 split 23", alg, 2, AESK[0][1], b"", MSG[:48], 23)
    ciph(f"{name} AES128 dec 32 split 20 twice", alg, 1, AESK[0][1], IV16, MSG[:32], 20, 1)
    ciph(f"{name} AES128 dec 20", alg, 1, AESK[0][1], b"", MSG[:20])
    ciph(f"{name} AES128 bad iv 8", alg, 2, AESK[0][1], IV8, MSG[:32])
ciph("Cipher DES alg with AES key", 1, 2, AESK[0][1], b"", MSG[:16])
ciph("Cipher bad mode 3", 14, 3, AESK[0][1], b"", MSG[:16])


def sig(label, alg, k, iv, data, split=0, flags=0):
    add(label, 0x32, 0, flags, bytes([alg, 1]) + k + bytes([len(iv)]) + iv + struct.pack(">H", split) + data)


def ver(label, alg, k, msg, s, split=0):
    add(label, 0x32, 0, 0, bytes([alg, 2]) + k + b"\x00" + struct.pack(">H", split) + struct.pack(">H", len(msg))
        + msg + s)


for alg, name in [(1, "DES_MAC4_NOPAD"), (2, "DES_MAC8_NOPAD"), (3, "DES_MAC4_M1"), (4, "DES_MAC8_M1"),
                  (5, "DES_MAC4_M2"), (6, "DES_MAC8_M2"), (7, "DES_MAC4_PKCS5"), (8, "DES_MAC8_PKCS5"),
                  (19, "DES_MAC4_ISO9797_1_M2_ALG3"), (20, "DES_MAC8_ISO9797_1_M2_ALG3"),
                  (37, "ECDSA_SHA_224 with a DES key"), (47, "DES_MAC4_ISO9797_1_M1_ALG3"),
                  (48, "DES_MAC8_ISO9797_1_M1_ALG3")]:
    for kn, k in DESK:
        for ln in (16, 13):
            sig(f"{name} {kn} sign {ln}", alg, k, b"", MSG[:ln])
    sig(f"{name} 3DES2 sign 24 iv split 5 twice", alg, DESK[1][1], IV8, MSG[:24], 5, 1)
for alg, name in [(18, "AES_MAC_128_NOPAD"), (49, "AES_CMAC_128?")]:
    for kn, k in AESK:
        for ln in (32, 20, 0):
            sig(f"{name} {kn} sign {ln}", alg, k, b"", MSG[:ln])
    sig(f"{name} AES128 sign 48 iv split 7 twice", alg, AESK[0][1], IV16, MSG[:48], 7, 1)
for alg, name, bits in [(24, "HMAC_SHA1", 64), (25, "HMAC_SHA_256", 64), (26, "HMAC_SHA_384", 128),
                        (27, "HMAC_SHA_512", 128), (28, "HMAC_MD5", 64)]:
    for kl in (20, 32, 70):
        sig(f"{name} key {kl} sign 48", alg, key(19, bits, bytes(range(0x40, 0x40 + kl))), b"", MSG)
    sig(f"{name} key 20 sign 48 split 7 twice", alg, key(19, bits, bytes(range(0x40, 0x54))), b"", MSG, 7, 1)
    sig(f"{name} key 20 sign 0", alg, key(19, bits, bytes(range(0x40, 0x54))), b"", b"")

RSA = rsa_keys()
for b, k in RSA.items():
    n = k.public_key().public_numbers()
    pv = k.private_numbers()
    pub = rsakey(4, b, n.n, n.e)
    prv = rsakey(5, b, n.n, pv.d)
    crt = key(6, b, b"".join(struct.pack(">H", b // 16) + v.to_bytes(b // 16, "big")
                             for v in (pv.p, pv.q, pv.dmp1, pv.dmq1, pv.iqmp)))
    prvf = key(5, b, struct.pack(">H", b // 8) + n.n.to_bytes(b // 8, "big") + pv.d.to_bytes(b // 8, "big"))
    ciph(f"RSA_NOPAD {b} crt dec", 12, 1, crt, b"", bytes(1) + bytes(range(b // 8 - 1)))
    ciph(f"RSA_NOPAD {b} priv fixed-length d dec", 12, 1, prvf, b"", bytes(1) + bytes(range(b // 8 - 1)))
    ciph(f"RSA_PKCS1 {b} crt dec", 10, 1, crt, b"", once(f"pkcs1 {b}", lambda: k.public_key().encrypt(MSG[:20], padding.PKCS1v15())))
    sig(f"RSA_SHA_PKCS1 {b} crt sign 48", 10, crt, b"", MSG)
    sig(f"RSA_SHA_256_PKCS1 {b} crt sign 48", 40, crt, b"", MSG)
    m = MSG[:20]
    ciph(f"RSA_NOPAD {b} pub enc", 12, 2, pub, b"", bytes(1) + bytes(range(b // 8 - 1)))
    ciph(f"RSA_NOPAD {b} priv dec", 12, 1, prv, b"", bytes(1) + bytes(range(b // 8 - 1)))
    ct = once(f"pkcs1 {b}", lambda: k.public_key().encrypt(m, padding.PKCS1v15()))
    ciph(f"RSA_PKCS1 {b} priv dec", 10, 1, prv, b"", ct)
    ciph(f"RSA_PKCS1 {b} pub enc (random, length only)", 10, 2, pub, b"", m)
    ct = once(f"oaep {b}", lambda: k.public_key().encrypt(m, padding.OAEP(padding.MGF1(hashes.SHA1()),
                                                                           hashes.SHA1(), None)))
    ciph(f"RSA_PKCS1_OAEP {b} priv dec", 15, 1, prv, b"", ct)
    for alg, name, h in [(10, "RSA_SHA_PKCS1", hashes.SHA1()), (11, "RSA_MD5_PKCS1", hashes.MD5()),
                         (40, "RSA_SHA_256_PKCS1", hashes.SHA256()), (41, "RSA_SHA_384_PKCS1", hashes.SHA384()),
                         (42, "RSA_SHA_512_PKCS1", hashes.SHA512())]:
        sig(f"{name} {b} sign 48", alg, prv, b"", MSG)
        sig(f"{name} {b} crt sign 48", alg, crt, b"", MSG)
        ver(f"{name} {b} verify good", alg, pub, MSG, k.sign(MSG, padding.PKCS1v15(), h))
        ver(f"{name} {b} verify bad", alg, pub, MSG[:47] + b"x", k.sign(MSG, padding.PKCS1v15(), h))
    ver(f"RSA_SHA_PKCS1 {b} verify split 9", 10, pub, MSG, k.sign(MSG, padding.PKCS1v15(), hashes.SHA1()), 9)
ver("DES_MAC8_NOPAD verify", 2, DESK[1][1], MSG[:16], bytes(8))
ver("DES_MAC8_NOPAD verify good", 2, DESK[1][1], MSG[:16], bytes.fromhex("95536053b5ea2c8b"))

# RSA PSS (random salt: the card's signatures are checked offline), verify of Python's
for b, k in RSA.items():
    pv, n = k.private_numbers(), k.public_key().public_numbers()
    crt = key(6, b, b"".join(struct.pack(">H", b // 16) + v.to_bytes(b // 16, "big")
                             for v in (pv.p, pv.q, pv.dmp1, pv.dmq1, pv.iqmp)))
    pub = rsakey(4, b, n.n, n.e)
    for alg, name, h in [(21, "RSA_SHA_PKCS1_PSS", hashes.SHA1()), (44, "RSA_SHA_256_PKCS1_PSS", hashes.SHA256())]:
        sig(f"{name} {b} crt sign 48 (random)", alg, crt, b"", MSG)
        for slen, sn in [(h.digest_size, "salt=hash"), (0, "salt=0")]:
            ver(f"{name} {b} verify {sn}", alg, pub, MSG,
                once(f"{name} {b} {sn}", lambda: k.sign(MSG, padding.PSS(padding.MGF1(h), slen), h)))

# EC P-256 (prime field): keys, ECDSA (sign is random: checked offline), ECDH
P256 = [bytes.fromhex(x) for x in (
    "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",
    "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
    "046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"
    "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551")]


def eckey(t, last):
    return key(t, 256, b"".join(struct.pack(">H", len(v)) + v for v in P256 + [last]))


from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

ecs = [ec.derive_private_key(0x1234567890ABCDEF * (i + 1) + 0xC0FFEE, ec.SECP256R1()) for i in range(2)]
ECPT = [e.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        for e in ecs]
ECS = [e.private_numbers().private_value.to_bytes(32, "big") for e in ecs]
add("probe KeyAgreement 1..8", 0x30, 4, 8)
add("key type 11 256 bits", 0x36, 11, 0, struct.pack(">H", 256))
add("key type 12 256 bits", 0x36, 12, 0, struct.pack(">H", 256))
for alg, name, h in [(17, "ECDSA_SHA", hashes.SHA1()), (33, "ECDSA_SHA_256", hashes.SHA256())]:
    sig(f"{name} P256 sign 48 (random)", alg, eckey(12, ECS[0]), b"", MSG)
    sig(f"{name} P256 sign 48 split 9 (random)", alg, eckey(12, ECS[0]), b"", MSG, 9)
    good = once(name, lambda: ecs[0].sign(MSG, ec.ECDSA(h)))
    ver(f"{name} P256 verify good", alg, eckey(11, ECPT[0]), MSG, good)
    ver(f"{name} P256 verify bad", alg, eckey(11, ECPT[0]), MSG[:47] + b"x", good)
for alg, name in [(1, "EC_SVDP_DH"), (2, "EC_SVDP_DHC"), (3, "EC_SVDP_DH_PLAIN"), (4, "EC_SVDP_DHC_PLAIN")]:
    add(f"{name} P256", 0x37, 0, 0, bytes([alg]) + eckey(12, ECS[0]) + ECPT[1])
add("EC_SVDP_DH_PLAIN P256 compressed point", 0x37, 0, 0, bytes([3]) + eckey(12, ECS[0])
    + ecs[1].public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint))
add("EC_SVDP_DH_PLAIN P256 point not on curve", 0x37, 0, 0, bytes([3]) + eckey(12, ECS[0])
    + ECPT[1][:-1] + bytes([ECPT[1][-1] ^ 1]))

for alg, name in [(1, "SHA"), (2, "MD5"), (3, "RIPEMD160"), (4, "SHA_256"), (5, "SHA_384"), (6, "SHA_512"),
                  (7, "SHA_224")]:
    add(f"digest {name} abc", 0x33, 0, 0, bytes([alg]) + struct.pack(">H", 0) + b"abc")
    add(f"digest {name} 200 split 70 twice", 0x33, 0, 1, bytes([alg]) + struct.pack(">H", 70) + bytes(range(200)))

add("ext short 10", 0x34, 0, 0, bytes(range(10)))
add("ext Lc 600", 0x34, 0, 0, bytes(i & 0xFF for i in range(600)))
add("ext Lc 300 header only", 0x34, 1, 0, bytes(300))
add("ext no data", 0x34, 0, 0)
for alg in (1, 2, 3):
    add(f"random {alg} 16", 0x35, alg, 16)
add("random 2 255", 0x35, 2, 255)

json.dump(fixed, open(FIXED, "w"), indent=1)
with open(os.path.join(D, "cases.txt"), "w") as f:
    f.write(f"select {SEL}\n")
    for label, a in cases:
        f.write(f"{label.replace(' ', '_')} {a.hex().upper()}\n")
print(len(cases), "cases")
