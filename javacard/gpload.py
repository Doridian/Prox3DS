"""GlobalPlatform over the pm3 (no PC/SC reader needed): SCP03 with C-MAC, list / install / delete.
Runs inside the pm3 client (embedded Python):

    proxmark3 /dev/ttyACM0 -y gpload.py -- list
    proxmark3 /dev/ttyACM0 -y gpload.py -- install dspm-test.cap
    proxmark3 /dev/ttyACM0 -y gpload.py -- delete F0334453504D

Keys default to 404142..4F (GP_KEY=hex to change), the ISD to A000000151000000 (GP_ISD=hex). The card cryptogram from INITIALIZE UPDATE is
checked first; EXTERNAL AUTHENTICATE (the step whose failures the card counts) is only sent if it
matches, so wrong keys never cost a try.
"""
import os
import re
import sys
import zipfile

import pm3
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.cmac import CMAC

ISD = bytes.fromhex(os.environ.get("GP_ISD", "A000000151000000"))
KEY = bytes.fromhex(os.environ.get("GP_KEY", "404142434445464748494A4B4C4D4E4F"))
CAP_ORDER = ["Header", "Directory", "Import", "Applet", "Class", "Method", "StaticField", "Export",
             "ConstantPool", "RefLocation", "Descriptor"]

p = pm3.pm3()
first = True


class GpError(Exception):
    pass


def apdu(data, keep=True):
    """One APDU through hf 14a apdu; returns (response data, SW)."""
    global first
    flags = ("s" if first else "") + ("k" if keep else "")
    first = False
    p.console(f"hf 14a apdu {'-' + flags if flags else ''} -d {data.hex()}")
    out = p.grabbed_output
    m = re.search(r"<<< ([0-9A-Fa-f]+)", out)
    if not m:
        raise GpError("no answer: " + out.strip())
    r = bytes.fromhex(m.group(1))
    return r[:-2], r[-2] << 8 | r[-1]


def cmac(k, d):
    c = CMAC(algorithms.AES(k))
    c.update(d)
    return c.finalize()


def kdf(k, const, ctx, bits):
    return cmac(k, bytes(11) + bytes([const, 0]) + bits.to_bytes(2, "big") + b"\x01" + ctx)[:bits // 8]


class Scp03:
    def __init__(self):
        r, sw = apdu(bytes([0x00, 0xA4, 0x04, 0x00, len(ISD)]) + ISD + b"\x00")
        if sw != 0x9000:
            raise GpError(f"select ISD: {sw:04X}")
        hc = os.urandom(8)
        r, sw = apdu(b"\x80\x50\x00\x00\x08" + hc + b"\x00")
        if sw != 0x9000 or len(r) < 29:
            raise GpError(f"INITIALIZE UPDATE: {sw:04X} {r.hex()}")
        kvn, scp, cc, crypt = r[10], r[11], r[13:21], r[21:29]
        if scp != 3:
            raise GpError(f"SCP{scp:02X}, only SCP03 here")
        ctx = hc + cc
        self.smac = kdf(KEY, 0x06, ctx, 128)
        if kdf(self.smac, 0x00, ctx, 64) != crypt:
            raise GpError("card cryptogram mismatch: wrong keys (nothing sent, no try used)")
        print(f"card cryptogram ok (key version {kvn:02X})")
        self.chain = bytes(16)
        r, sw = self.send(0x80, 0x82, 0x01, 0x00, kdf(self.smac, 0x01, ctx, 64), le=False)
        if sw != 0x9000:
            raise GpError(f"EXTERNAL AUTHENTICATE: {sw:04X}")
        print("authenticated (C-MAC)")

    def send(self, cla, ins, p1, p2, data=b"", le=True, keep=True):
        hdr = bytes([cla | 0x04, ins, p1, p2, len(data) + 8])
        self.chain = cmac(self.smac, self.chain + hdr + data)
        return apdu(hdr + data + self.chain[:8] + (b"\x00" if le else b""), keep)


def tlv_len(n):
    return bytes([n]) if n < 0x80 else bytes([0x81, n]) if n < 0x100 else bytes([0x82, n >> 8, n & 0xFF])


def lv(b):
    return bytes([len(b)]) + b


def cap_load_file(path):
    """Concatenated CAP components (no Debug) in the C4 tag, plus the package and applet AIDs."""
    z = zipfile.ZipFile(path)
    comps = {n.rsplit("/", 1)[-1][:-4]: z.read(n) for n in z.namelist() if n.endswith(".cap")}
    blob = b"".join(comps[c] for c in CAP_ORDER if c in comps)
    hdr = comps["Header"]  # tag, size(2), magic(4), minor, major, flags, pkg minor, major, AID len, AID
    pkg = hdr[13:13 + hdr[12]]
    applets, a = [], comps.get("Applet", b"")
    if a:
        o = 4
        for _ in range(a[3]):
            applets.append(a[o + 1:o + 1 + a[o]])
            o += 1 + a[o] + 2
    return b"\xC4" + tlv_len(len(blob)) + blob, pkg, applets


def get_status(s, p1):
    """GET STATUS (P1 80 ISD, 40 apps, 20 packages): [(AID, state)]."""
    out, p2 = [], 0x02
    while True:
        r, sw = s.send(0x80, 0xF2, p1, p2, b"\x4F\x00")
        o = 0
        while o + 1 < len(r) and r[o] == 0xE3:
            body, o = r[o + 2:o + 2 + r[o + 1]], o + 2 + r[o + 1]
            aid, state, k = None, None, 0
            while k + 1 < len(body):
                t, ln = body[k], body[k + 1]
                if t == 0x4F:
                    aid = body[k + 2:k + 2 + ln]
                if t == 0x9F and body[k + 1] == 0x70:
                    ln = body[k + 2]
                    state = body[k + 3]
                    k += 1
                k += 2 + ln
            out.append((aid, state))
        if sw != 0x6310:
            return out
        p2 = 0x03


def delete(s, aid):
    r, sw = s.send(0x80, 0xE4, 0x00, 0x80, b"\x4F" + lv(aid))
    print(f"DELETE {aid.hex().upper()}: {sw:04X}")
    return sw


def install(s, path):
    lf, pkg, applets = cap_load_file(path)
    print(f"package {pkg.hex().upper()}, applets {[a.hex().upper() for a in applets]}, load file {len(lf)} bytes")
    if any(a == pkg for a, _ in get_status(s, 0x20)):
        delete(s, pkg)
    r, sw = s.send(0x80, 0xE6, 0x02, 0x00, lv(pkg) + b"\x00\x00\x00\x00")
    if sw != 0x9000:
        raise GpError(f"INSTALL [for load]: {sw:04X}")
    blk = 240
    for i, o in enumerate(range(0, len(lf), blk)):
        last = o + blk >= len(lf)
        r, sw = s.send(0x80, 0xE8, 0x80 if last else 0x00, i, lf[o:o + blk])
        if sw != 0x9000:
            raise GpError(f"LOAD block {i}: {sw:04X}")
    print(f"loaded {i + 1} blocks")
    for a in applets:
        data = lv(pkg) + lv(a) + lv(a) + b"\x01\x00" + b"\x02\xC9\x00" + b"\x00"
        r, sw = s.send(0x80, 0xE6, 0x0C, 0x00, data)
        if sw != 0x9000:
            raise GpError(f"INSTALL [for install] {a.hex()}: {sw:04X}")
        print(f"installed {a.hex().upper()}")


def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return
    try:
        s = Scp03()
        if args[0] == "list":
            for name, p1 in (("ISD", 0x80), ("applets", 0x40), ("packages", 0x20)):
                for aid, st in get_status(s, p1):
                    print(f"{name:9s} {aid.hex().upper() if aid else '?':32s} state {st if st is None else f'{st:02X}'}")
        elif args[0] == "install":
            install(s, args[1])
        elif args[0] == "delete":
            delete(s, bytes.fromhex(args[1]))
        else:
            print(__doc__)
    except GpError as e:
        print("ERROR:", e)
    p.console("hf 14a reader")  # without -k: field off afterwards


main()
