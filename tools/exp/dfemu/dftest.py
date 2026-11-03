#!/usr/bin/env python3
"""DESFire emulation (nfcprobe dfemu.c) against a reader written from pm3's desfirecore.c / desfiresecurechan.c:
D40 (0A) and EV2 (71 / 77) logins and their secure messaging, on test.txt. Run build.sh first.

The reader is derived from Proxmark3 (C) Proxmark3 contributors, GPL-3.0-or-later (desfirecore.c: libfreefare (C) 2010 Romain Tartiere); see CREDITS.md."""
import warnings
warnings.filterwarnings("ignore")
import os, subprocess, sys, binascii
from cryptography.hazmat.primitives.ciphers import Cipher, modes, algorithms
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives.cmac import CMAC

S = os.path.dirname(os.path.abspath(__file__))
p = subprocess.Popen([S + "/dfh", S + "/test.txt"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
def tx(b):
    p.stdin.write(b.hex() + "\n"); p.stdin.flush()
    r = bytes.fromhex(p.stdout.readline().strip())
    return r[0], r[1:]
def xchg(b):  # native with AF chaining
    st, d = tx(b)
    while st == 0xAF:
        st2, d2 = tx(b"\xAF"); d += d2; st = st2
    return st, d
def reset():
    p.stdin.write("R\n"); p.stdin.flush(); p.stdout.readline()

def ecb(alg, key, b, enc):
    c = Cipher(alg(key), modes.ECB())
    o = c.encryptor() if enc else c.decryptor()
    return o.update(b) + o.finalize()
def des(key, b, enc): return ecb(TripleDES, key if len(key) != 8 else key * 2, b, enc)
def aes(key, b, enc): return ecb(algorithms.AES, key, b, enc)
def xor(a, b): return bytes(x ^ y for x, y in zip(a, b))
def rol(b): return b[1:] + b[:1]
def crcA(d):
    c = 0x6363
    for x in d:
        b = (x ^ c) & 0xFF; b = (b ^ (b << 4)) & 0xFF
        c = (c >> 8) ^ (b << 8) ^ (b << 3) ^ (b >> 4)
    return bytes([c & 0xFF, c >> 8 & 0xFF])
ok = True
def check(name, cond):
    global ok
    print(("OK  " if cond else "BAD ") + name); ok &= bool(cond)

# ---- D40 (0A) on app 778899 ----
def d40_auth(k, key):
    st, e = tx(bytes([0x0A, k]))
    assert st == 0xAF and len(e) == 8, (st, e)
    rb = des(key, e, False)                     # receive: D(C) ^ IV0
    ra = os.urandom(8)
    y1 = des(key, ra, False)                    # send mode: D(x ^ iv)
    y2 = des(key, xor(rol(rb), y1), False)
    st, e = tx(b"\xAF" + y1 + y2)
    if st: return st, None
    got = des(key, e, False)
    if got != rol(ra): return 0xFE, None
    sk = ra[:4] + rb[:4] + ((ra[4:8] + rb[4:8]) if key[:8] != key[8:16] and len(key) == 16 else ra[:4] + rb[:4])
    return 0, sk
def d40_mac(sk, d):
    pad = d + bytes(-len(d) % 8)
    c = Cipher(TripleDES(sk), modes.CBC(bytes(8))).encryptor()
    return (c.update(pad) + c.finalize())[-8:][:4]

reset()
check("select 778899", tx(bytes.fromhex("5A998877"))[0] == 0)
st, sk = d40_auth(0, bytes.fromhex("1122334455667788") * 2)
check("D40 auth key 0 (DES)", st == 0)
st, d = xchg(bytes.fromhex("BD01000000000000"))
dec = Cipher(TripleDES(sk), modes.CBC(bytes(8))).decryptor().update(d)
data = dec[:16]
check(f"D40 full read: {data!r} crc", st == 0 and data == b"D40-FULL-FILE-01" and dec[16:18] == crcA(data) and not any(dec[18:]))
st, sk = d40_auth(1, bytes.fromhex("00112233445566778899AABBCCDDEEFF"))
check("D40 auth key 1 (2K3DES)", st == 0)
st, d = xchg(bytes.fromhex("BD02000000000000"))
check(f"D40 MAC read {d[:12]!r}", st == 0 and d[:12] == b"D40-MAC-FILE" and d[12:] == d40_mac(sk, d[:12]))
st, _ = d40_auth(1, bytes.fromhex("FF112233445566778899AABBCCDDEEFF"))
check("D40 wrong key refused", st == 0xAE)
reset(); tx(bytes.fromhex("5A332211"))
check("D40 on an AES app refused", tx(bytes.fromhex("0A01"))[0] == 0xAE)

# ---- EV2 (71) on app 112233 ----
KEY1 = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
def cmac(key, m): c = CMAC(algorithms.AES(key)); c.update(m); return c.finalize()
class Ev2: pass
ev = Ev2()
def ev2_auth(k, key, first=True):
    st, e = tx(bytes([0x71, k, 0]) if first else bytes([0x77, k]))
    assert st == 0xAF, st
    rb = aes(key, e, False); ra = os.urandom(16)
    c = Cipher(algorithms.AES(key), modes.CBC(bytes(16))).encryptor()
    st, e = tx(b"\xAF" + c.update(ra + rol(rb)) + c.finalize())
    if st: return st
    d = Cipher(algorithms.AES(key), modes.CBC(bytes(16))).decryptor().update(e)
    if first:
        ev.ti = d[:4]; ev.ctr = 0
        if d[4:20] != rol(ra): return 0xFE
    elif d[:16] != rol(ra): return 0xFE
    sv = bytearray(b"\xA5\x5A\x00\x01\x00\x80" + ra[:2] + xor(ra[2:8], rb[:6]) + rb[6:16] + ra[8:16])
    ev.ke = cmac(key, bytes(sv)); sv[0], sv[1] = 0x5A, 0xA5; ev.km = cmac(key, bytes(sv))
    return 0
def mact(code, data):
    f = cmac(ev.km, bytes([code, ev.ctr & 0xFF, ev.ctr >> 8]) + ev.ti + data); return f[1::2]
def ev2_cmd(cmd, full=False, mac=True):
    tx_ = cmd + (mact(cmd[0], cmd[1:]) if mac else b"")
    st, d = xchg(tx_)
    ev.ctr += 1
    if st: return st, d
    if mac or full:
        d, m = d[:-8], d[-8:]
        if m != mact(st, d): return 0xFD, d
    if full and d:
        iv = aes(ev.ke, b"\x5A\xA5" + ev.ti + bytes([ev.ctr & 0xFF, ev.ctr >> 8]) + bytes(8), True)
        d = Cipher(algorithms.AES(ev.ke), modes.CBC(iv)).decryptor().update(d)
        d = d.rstrip(b"\0"); assert d[-1] == 0x80; d = d[:-1]
    return st, d

reset(); tx(bytes.fromhex("5A332211"))
check("EV2 First key 1", ev2_auth(1, KEY1) == 0)
st, d = ev2_cmd(bytes.fromhex("45"))
check(f"EV2 MACed GetKeySettings {d.hex()}", st == 0 and d == bytes.fromhex("0B82"))
st, d = ev2_cmd(bytes.fromhex("BD01000000000000"), full=True)
check(f"EV2 full read {d!r}", st == 0 and d == b"SECRET-AES-FILE!")
st, d = ev2_cmd(bytes.fromhex("BD02000000000000"))
check(f"EV2 MAC read {d!r}", st == 0 and d == b"EV2-MAC!")
st, d = ev2_cmd(bytes.fromhex("F501"))
check(f"EV2 GetFileSettings {d.hex()}", st == 0 and d.hex() == "00031011100000")
ctr = ev.ctr
check("EV2 NonFirst key 1", ev2_auth(1, KEY1, first=False) == 0)
check(f"  counter carried on ({ctr})", ev.ctr == ctr)
st, d = ev2_cmd(bytes.fromhex("BD01000000000000"), full=True)
check(f"EV2 full read after NonFirst {d!r}", st == 0 and d == b"SECRET-AES-FILE!")
reset(); tx(bytes.fromhex("5A332211"))
check("EV2 wrong key refused", ev2_auth(1, bytes(15) + b"\1") == 0xAE)
check("EV2 NonFirst without a session refused", tx(bytes.fromhex("7701"))[0] == 0xAE)
reset(); tx(bytes.fromhex("5A998877"))
check("EV2 on a DES app refused", tx(bytes.fromhex("710000"))[0] == 0xAE)
# PICC GetCardUID over EV2 isn't possible (DES PICC key); EV1 still works:
reset(); tx(bytes.fromhex("5A332211"))
st, e = tx(bytes.fromhex("AA01")); check("EV1 AES still answers", st == 0xAF and len(e) == 16)

# ---- writes (pm3 framing: 1 + 54 bytes, then AF + 54) ----
def send(b):
    st, d = tx(b[:55]); b = b[55:]
    while b and st == 0xAF:
        st, d = tx(b"\xAF" + b[:54]); b = b[54:]
    return st, d
def d40_send(sk, x):
    y, out = bytes(8), b""
    for i in range(0, len(x), 8):
        y = des(sk, xor(x[i:i+8], y), False); out += y
    return out
def d40_read_full(sk, fid, n):
    st, d = xchg(bytes([0xBD, fid, 0, 0, 0, 0, 0, 0]))
    dec = Cipher(TripleDES(sk), modes.CBC(bytes(8))).decryptor().update(d)
    return st, dec[:n] if dec[n:n+2] == crcA(dec[:n]) else None

reset(); tx(bytes.fromhex("5A998877"))
st, sk = d40_auth(0, bytes.fromhex("1122334455667788") * 2)
data = b"pm3-D40-written!"
x = data + crcA(data); x += bytes(-len(x) % 8)
st, _ = send(bytes.fromhex("3D01000000100000") + d40_send(sk, x))
check("D40 full write", st == 0)
st, got = d40_read_full(sk, 1, 16)
check(f"  read back {got!r}", st == 0 and got == data)
st, sk = d40_auth(1, bytes.fromhex("00112233445566778899AABBCCDDEEFF"))
st, _ = send(bytes.fromhex("3D02000000040000") + b"mac!" + d40_mac(sk, b"mac!"))
check("D40 MAC write", st == 0)
st, _ = send(bytes.fromhex("3D02000000040000") + b"mac!" + b"\0\0\0\0")
check("D40 MAC write with a bad MAC refused (1E)", st == 0x1E)

reset(); tx(bytes.fromhex("5A332211"))
ev2_auth(1, KEY1)
def ev2_write(fid, data, full):
    hdr = bytes([0x3D, fid, 0, 0, 0, len(data), 0, 0])
    body = data
    if full:
        iv = aes(ev.ke, b"\xA5\x5A" + ev.ti + bytes([ev.ctr & 0xFF, ev.ctr >> 8]) + bytes(8), True)
        p = data + b"\x80"; p += bytes(-len(p) % 16)
        body = Cipher(algorithms.AES(ev.ke), modes.CBC(iv)).encryptor().update(p)
    cmd = hdr + body
    st, d = send(cmd + mact(cmd[0], cmd[1:]))
    ev.ctr += 1
    if st: return st
    return 0 if d == mact(0, b"") else 0xFD
check("EV2 full write", ev2_write(1, b"EV2 full written", True) == 0)
st, d = ev2_cmd(bytes.fromhex("BD01000000000000"), full=True)
check(f"  read back {d!r}", st == 0 and d == b"EV2 full written")
check("EV2 MAC write", ev2_write(2, b"ev2-mac!", False) == 0)
st, d = ev2_cmd(bytes.fromhex("BD02000000000000"))
check(f"  read back {d!r}", st == 0 and d == b"ev2-mac!")

reset(); tx(bytes.fromhex("5A665544"))
big = bytes(range(0x40, 0x60))
st, _ = send(bytes.fromhex("3D01000000200000") + big)   # 40 bytes: one frame
check("plain write 32", st == 0)
st, d = xchg(bytes.fromhex("BD01000000000000"))
check("  read back", d == big)
st, _ = send(bytes.fromhex("3B03000000080000") + b"\x09" * 8)
st2, _ = tx(bytes.fromhex("C7"))
st3, d = xchg(bytes.fromhex("BB03000000000000"))
check(f"record + commit: {len(d) // 8} records", st == st2 == st3 == 0 and d[-8:] == b"\x09" * 8 and len(d) == 32)
st, _ = send(bytes.fromhex("0C0205000000")); tx(bytes.fromhex("A7"))
st2, d = xchg(bytes.fromhex("6C02"))
check("credit then abort: value unchanged", st == 0 and d == bytes([100, 0, 0, 0]))

# a write in AF frames (a small frame size forces them)
reset(); tx(bytes.fromhex("5A332211")); ev2_auth(1, KEY1)
def send_small(b, n=20):
    st, d = tx(b[:n]); b = b[n:]
    while b and st == 0xAF:
        st, d = tx(b"\xAF" + b[:n]); b = b[n:]
    return st, d
hdr = bytes.fromhex("3D01000000100000")
iv = aes(ev.ke, b"\xA5\x5A" + ev.ti + bytes([ev.ctr & 0xFF, ev.ctr >> 8]) + bytes(8), True)
body = Cipher(algorithms.AES(ev.ke), modes.CBC(iv)).encryptor().update(b"chained frames!!" + b"\x80" + bytes(15))
cmd = hdr + body
st, d = send_small(cmd + mact(cmd[0], cmd[1:])); ev.ctr += 1
check("EV2 full write in 20-byte AF frames", st == 0 and d == mact(0, b""))
st, d = ev2_cmd(bytes.fromhex("BD01000000000000"), full=True)
check(f"  read back {d!r}", st == 0 and d == b"chained frames!!")
print("ALL OK" if ok else "FAILURES")
