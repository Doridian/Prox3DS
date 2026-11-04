#!/usr/bin/env python3
"""Passive authentication of an eMRTD dump (pace.py's OUTDIR): EF.SOD's DG hashes against the DG files,
the signed attributes' message digest, and the document signer's signature (its certificate from the SOD).
The DS certificate's own chain (CSCA) is not checked: that takes the country's CSCA certificate.

usage: sod.py DIR
"""
import hashlib, os, sys
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa


def der(d, i=0):
    """(tag, value start, value end, next) at i."""
    tag = d[i]; i += 1
    if tag & 0x1F == 0x1F:
        while True:
            tag = tag << 8 | d[i]; i += 1
            if not d[i - 1] & 0x80: break
    l = d[i]; i += 1
    if l & 0x80:
        n = l & 0x7F; l = int.from_bytes(d[i:i + n], 'big'); i += n
    return tag, i, i + l, i + l


def kids(d, s, e):
    out = []
    while s < e:
        t, vs, ve, s = der(d, s)
        out.append((t, vs, ve))
    return out


def oid(b):
    v = [b[0] // 40, b[0] % 40]; n = 0
    for x in b[1:]:
        n = n << 7 | x & 0x7F
        if not x & 0x80: v.append(n); n = 0
    return '.'.join(map(str, v))


HASH = {'1.3.14.3.2.26': 'sha1', '2.16.840.1.101.3.4.2.1': 'sha256', '2.16.840.1.101.3.4.2.2': 'sha384',
        '2.16.840.1.101.3.4.2.3': 'sha512', '2.16.840.1.101.3.4.2.4': 'sha224'}
CHASH = {'sha1': hashes.SHA1, 'sha256': hashes.SHA256, 'sha384': hashes.SHA384, 'sha512': hashes.SHA512,
         'sha224': hashes.SHA224}


def main():
    dir_ = sys.argv[1]
    d = open(os.path.join(dir_, 'SOD.bin'), 'rb').read()
    _, s, e, _ = der(d)                     # 77
    _, s, e, _ = der(d, s)                  # ContentInfo SEQUENCE
    ci = kids(d, s, e)
    _, s, e = ci[1]                         # [0]
    _, s, e, _ = der(d, s)                  # SignedData
    sd = kids(d, s, e)
    # version, digestAlgorithms, encapContentInfo, [0] certificates, signerInfos
    eci = kids(d, sd[2][1], sd[2][2])
    print('eContentType', oid(d[eci[0][1]:eci[0][2]]))
    _, s, e, _ = der(d, eci[1][1])          # [0] -> OCTET STRING
    econtent = d[s:e]
    lso = kids(econtent, *der(econtent)[1:3])  # LDSSecurityObject: version, hashAlg, dgHashes
    alg = HASH[oid(econtent[kids(econtent, lso[1][1], lso[1][2])[0][1]:kids(econtent, lso[1][1], lso[1][2])[0][2]])]
    print('DG hash:', alg)
    ok = True
    for t, s, e in kids(econtent, lso[2][1], lso[2][2]):
        n, h = kids(econtent, s, e)
        num = int.from_bytes(econtent[n[1]:n[2]], 'big')
        want = econtent[h[1]:h[2]]
        p = os.path.join(dir_, f'DG{num}.bin')
        if os.path.exists(p):
            got = hashlib.new(alg, open(p, 'rb').read()).digest()
            print(f'  DG{num}: {"OK" if got == want else "MISMATCH"}')
            ok &= got == want
        else:
            print(f'  DG{num}: not read')
    # the DS certificate: [0] certificates, the first one, whole
    c0 = kids(d, sd[3][1], sd[3][2])[0]
    cder = d[c0[1] - hdrlen(d, c0[1], c0[2]):c0[2]]
    cert = x509.load_der_x509_certificate(cder)
    print('DS cert:', cert.subject.rfc4514_string())
    print('  issuer:', cert.issuer.rfc4514_string())
    print('  valid', cert.not_valid_before_utc.date(), '-', cert.not_valid_after_utc.date())
    si = kids(d, *kids(d, sd[-1][1], sd[-1][2])[0][1:])
    # SignerInfo: version, sid, digestAlgorithm, [0] signedAttrs, signatureAlgorithm, signature
    sa = [x for x in si if x[0] == 0xA0][0]
    signed = b'\x31' + d[sa[1] - hdrlen(d, sa[1], sa[2]) + 1:sa[2]]  # hashed with SET (31) in place of [0]
    md = None
    for t, s, e in kids(d, sa[1], sa[2]):
        a = kids(d, s, e)
        if oid(d[a[0][1]:a[0][2]]) == '1.2.840.113549.1.9.4':
            _, vs, ve, _ = der(d, a[1][1])
            md = d[vs:ve]
    first = lambda x: oid(d[kids(d, x[1], x[2])[0][1]:kids(d, x[1], x[2])[0][2]])
    dalg = HASH[first(si[2])]
    print('signed attrs message digest:', 'OK' if md == hashlib.new(dalg, econtent).digest() else 'MISMATCH')
    salg = first(si[4])
    sig = d[si[5][1]:si[5][2]]
    try:
        pk = cert.public_key()
    except Exception:
        pk = None
    if pk is None:
        ok = ec_verify_explicit(cert.public_key_algorithm_oid, cder, hashlib.new(dalg, signed).digest(), sig)
        print(f'DS signature ({salg}, ECDSA on explicit curve):', 'OK' if ok else 'FAILED')
        return
    try:
        if isinstance(pk, ec.EllipticCurvePublicKey):
            pk.verify(sig, signed, ec.ECDSA(CHASH[dalg]()))
        elif salg == '1.2.840.113549.1.1.10':
            pk.verify(sig, signed, padding.PSS(padding.MGF1(CHASH[dalg]()), padding.PSS.AUTO), CHASH[dalg]())
        else:
            pk.verify(sig, signed, padding.PKCS1v15(), CHASH[dalg]())
        print(f'DS signature ({salg}, {type(pk).__name__}):', 'OK')
    except Exception as x:
        print(f'DS signature ({salg}):', 'FAILED', repr(x))


def hdrlen(d, vs, ve):
    """the tag + length bytes in front of a value at vs (short tags)"""
    l = ve - vs
    return 2 if l < 0x80 else 3 if l < 0x100 else 4


def ec_verify_explicit(_, cder, h, sig):
    """ECDSA with a certificate whose key has explicit curve parameters (ECParameters: fieldID prime, curve
    a b, base point, order)."""
    tbs = kids(cder, *kids(cder, *der(cder)[1:3])[0][1:])
    spki = [x for x in tbs if x[0] == 0x30 and kids(cder, x[1], x[2])[0][0] == 0x30
            and cder[kids(cder, *kids(cder, x[1], x[2])[0][1:])[0][1]:][:7] == bytes.fromhex('2A8648CE3D0201')][0]
    algo, bits = kids(cder, spki[1], spki[2])
    params = kids(cder, *kids(cder, algo[1], algo[2])[1][1:])
    fid, curve, base, order = params[1], params[2], params[3], params[4]
    i = lambda x: int.from_bytes(cder[x[1]:x[2]], 'big')
    p = i(kids(cder, fid[1], fid[2])[1])
    ca, cb = kids(cder, curve[1], curve[2])[:2]
    a, n = i(ca), i(order)
    g = cder[base[1]:base[2]]
    q = cder[bits[1] + 1:bits[2]]
    L = (len(g) - 1) // 2
    G = (int.from_bytes(g[1:1 + L], 'big'), int.from_bytes(g[1 + L:], 'big'))
    Q = (int.from_bytes(q[1:1 + L], 'big'), int.from_bytes(q[1 + L:], 'big'))
    def add(P1, P2):
        if P1 is None: return P2
        if P2 is None: return P1
        if P1[0] == P2[0] and (P1[1] + P2[1]) % p == 0: return None
        l = ((3 * P1[0] ** 2 + a) * pow(2 * P1[1], -1, p) if P1 == P2 else (P2[1] - P1[1]) * pow(P2[0] - P1[0], -1, p)) % p
        x = (l * l - P1[0] - P2[0]) % p
        return x, (l * (P1[0] - x) - P1[1]) % p
    def mul(k, P):
        R = None
        while k:
            if k & 1: R = add(R, P)
            P = add(P, P); k >>= 1
        return R
    rs = kids(sig, *der(sig)[1:3])
    r, s = (int.from_bytes(sig[x[1]:x[2]], 'big') for x in rs)
    e = int.from_bytes(h, 'big') >> max(0, len(h) * 8 - n.bit_length())
    w = pow(s, -1, n)
    X = add(mul(e * w % n, G), mul(r * w % n, Q))
    print(f'  DS key: {n.bit_length()}-bit curve, p {p:X}'[:60] + '...')
    return X is not None and X[0] % n == r


if __name__ == '__main__':
    main()
