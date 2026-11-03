#!/usr/bin/env python3
"""Hunt for chip RAM the ROM leaves alone during listen (room for a 4K Classic): load chip/emu.c as
mfcemu.py does, snapshot RAM 0x38000-0x40000 idle and after pm3 sessions against the emulation, print the
runs that never changed. With RANGES (hex a-b,a-b), fill those with a pattern first and check it survives.

    ramfree.py HOST DUMP [RANGES]
"""
import struct
import subprocess
import sys
import time

sys.path.insert(0, __file__.rsplit("/", 3)[0])
import chipmon
import nfcnet

OP_EMU, MODE_MFC = 5, 3
LO, HI = 0x38000, 0x40000
PM3 = ["pm3", "-p", "/dev/ttyACM1", "-c"]


def snap(mon):
    return mon.read(LO, HI - LO)


def session(nfc, secs):
    """Listen while the pm3 reads sector 0 a few times."""
    for c in (bytes.fromhex("2103030180" "01"),):
        nfc.cmd(b"\x10" + c)
    ok = 0
    end = time.time() + secs
    while time.time() < end:
        o = subprocess.run(PM3 + ["hf mf rdsc -s 0 -k FFFFFFFFFFFF; hw fpgaoff"], capture_output=True,
                           text=True, timeout=30).stdout
        ok += "ffffffffffff" in o.lower().replace(" ", "")
        for p in nfc.drain(50):
            if p[:3] == b"\x10\x61\x06" and p[4] == 0:
                time.sleep(0.1)
                nfc.write(bytes.fromhex("10" "2103030180" "01"))
    nfc.cmd(bytes.fromhex("1021060100"))
    nfc.drain(200)
    return ok


def runs(snaps, minlen=256):
    out, i, n = [], 0, HI - LO
    same = [all(s[k] == snaps[0][k] for s in snaps) for k in range(n)]
    while i < n:
        if not same[i]:
            i += 1
            continue
        j = i
        while j < n and same[j]:
            j += 1
        if j - i >= minlen:
            out.append((LO + i, LO + j))
        i = j
    return out


def main():
    host, path = sys.argv[1], sys.argv[2]
    fill = [tuple(int(x, 16) for x in r.split("-")) for r in sys.argv[3].split(",")] if len(sys.argv) > 3 else None
    mem = open(path, "rb").read()
    uid = mem[:4]
    nfc = nfcnet.Nfc(host)
    mon = chipmon.Mon(nfc, on_other=lambda p: None)
    mon.load("emu_mfc.bin")
    base, logp, memp = struct.unpack("<III", mon._do(OP_EMU, 0)[:12])
    print(f"struct emu {base:05X}, log {logp:05X}, mem {memp:05X}")
    mon.write(base + 1, bytes([len(mem) // 16, 0, 0]) + uid)
    for i in range(0, len(mem), chipmon.CHUNK):
        mon.write(memp + i, mem[i:i + chipmon.CHUNK])
    mon.write(base, bytes([MODE_MFC]))
    tl = bytes.fromhex("300104" "310100" "320108") + bytes([0x33, 4]) + uid
    for c in (bytes([0x20, 0x02, len(tl) + 1, 4]) + tl, bytes.fromhex("2100040104" "0202"),
              bytes.fromhex("200204018001" "01")):
        nfc.cmd(b"\x10" + c)
    if fill:
        rs = fill
    else:
        snaps = [snap(mon)]
        print("snap 0")
    if not fill:
        for k in range(2):
            print(f"session {k}: {session(nfc, 25)} reads")
            snaps.append(snap(mon))
        rs = runs(snaps)
        print(f"unchanged runs >= 256: {sum(b - a for a, b in rs)} bytes")
        for a, b in rs:
            print(f"  {a:05X}-{b:05X} {b - a:5}  first {snaps[0][a - LO:a - LO + 8].hex()}")
        return
    for a, b in rs:
        if a >= 0x3B80C and a < 0x3C530:
            continue  # our own image
        pat = bytes((x * 7 + 0x5A) & 0xFF for x in range(b - a))
        for i in range(0, b - a, chipmon.CHUNK):
            mon.write(a + i, pat[i:i + chipmon.CHUNK])
    print(f"filled; session: {session(nfc, 45)} reads")
    s = b"".join(mon.read(a, b - a) for a, b in rs)
    off = {}
    o = 0
    for a, b in rs:
        off[a] = o
        o += b - a
    for a, b in rs:
        if a >= 0x3B80C and a < 0x3C530:
            continue
        pat = bytes((x * 7 + 0x5A) & 0xFF for x in range(b - a))
        got = s[off[a]:off[a] + b - a]
        bad = [i for i in range(b - a) if got[i] != pat[i]]
        print(f"  {a:05X}-{b:05X}: {len(bad)} changed" + (f" (first at {a + bad[0]:05X}, last {a + bad[-1]:05X})" if bad else ""))


if __name__ == "__main__":
    main()
