#!/usr/bin/env python3
"""Drive the chip-side dumper (chip/dumper1.c) over Prox3DS's network server.

    dumpchip.py HOST v1 SRC SCAN_START SCAN_END   one load: report 16 bytes at SRC
    dumpchip.py HOST read ADDR [LEN]              v2, 20 bytes per load
    dumpchip.py HOST find START END LO HI         v2: words in [START,END) with LO <= value <= HI
    dumpchip.py HOST findbytes START END HEX4     v2: byte pattern (4 bytes)
    dumpchip.py HOST stream START LEN [OUT]       v3: 16 bytes per GET_PATCH_VERSION, one load
    dumpchip.py HOST v3debug                      v3: who reads the version struct (hits, PC, LR)
    dumpchip.py HOST dump START LEN [OUT]         v4: 16 bytes per request, no reloads, read twice
"""
import struct
import sys
import time

import mkpatch
import nfcnet

CHIP = __file__.rsplit("/", 2)[0] + "/chip/"
MARK = b"DMP1 marker 0000"


def load(nfc, ncd, tries=3, log=lambda s: None):
    """Power cycle, download, return the GET_PATCH_VERSION payload (None if the chip died).
    Loads occasionally fail (download rejected, or no answer afterwards); retry those."""
    for t in range(tries):
        nfc.power(True)
        nfc.drain()
        if not nfc.spd_download(ncd, log=log):
            print(f"  (try {t}: download rejected)")
            continue
        for pkt in nfc.cmd(nfcnet.CORE_RESET) + nfc.cmd(nfcnet.GET_PATCH_VERSION):
            if pkt[:3] == b"\x10\x4f\x2d":
                return pkt[4:]
        print(f"  (try {t}: no answer after download)")
    return None


def v1(nfc, src, start, end):
    img = bytearray(open(CHIP + "dumper1.bin", "rb").read())
    struct.pack_into("<III", img, len(img) - 28, src, start, end)  # params at the end
    p = load(nfc, mkpatch.build(bytes(img), MARK))
    if p is None:
        print(f"scan {start:05X}..{end:05X}: chip dead")
    elif p[4:20] == MARK:
        print(f"scan {start:05X}..{end:05X}: alive, marker untouched (not found)")
    else:
        addr, idx = struct.unpack_from("<II", p)
        print(f"scan {start:05X}..{end:05X}: copy @{addr:05X} idx {idx}: {src:08X}: {p[8:24].hex(' ')}")
    return p


def v2(nfc, mode, a, b=0, lo=0, hi=0):
    img = bytearray(open(CHIP + "dumper2.bin", "rb").read())
    struct.pack_into("<5I", img, len(img) - 20, mode, a, b, lo, hi)  # params at the end
    p = load(nfc, mkpatch.build(bytes(img)))
    if p is None:
        raise nfcnet.NfcError("chip dead")
    return p[:20]


def v3_load(nfc, start, debug=0):
    img = bytearray(open(CHIP + "dumper3.bin", "rb").read())
    struct.pack_into("<2I", img, len(img) - 8, start, debug)  # params at the end
    p = load(nfc, mkpatch.build(bytes(img)))
    if p is None:
        raise nfcnet.NfcError("chip dead")
    return p[:20]


def gpv(nfc):
    for pkt in nfc.cmd(nfcnet.GET_PATCH_VERSION):
        if pkt[:3] == b"\x10\x4f\x2d":
            return pkt[4:24]
    return None


def stream(nfc, start, length, out=None):
    """Read [start, start+length) 16 bytes per query; reload when the stream skips or dies."""
    data = bytearray()
    a = start
    p = None
    while a < start + length:
        if p is None:
            p = v3_load(nfc, a)
        addr = struct.unpack_from("<I", p)[0]
        if addr != a:
            print(f"  stream at {addr:08X}, wanted {a:08X}: reloading")
            p = None
            continue
        data += p[4:20]
        a += 16
        if out and (a & 0x3FF) == 0:
            open(out, "wb").write(data)
            print(f"  {a:08X}")
        p = gpv(nfc)
    data = data[:length]
    if out:
        open(out, "wb").write(data)
    return bytes(data)


class V4:
    """GET_PATCH_VERSION carrying 2F 2D 07 | session | seq16 | addr32 (see chip/dumper4.c)."""

    def __init__(self, nfc, scan=(0x3A001, 0x3B590, 4)):
        self.nfc, self.seq = nfc, 0
        self.session = int.from_bytes(__import__("os").urandom(1)) or 1
        img = bytearray(open(CHIP + "dumper4.bin", "rb").read())
        struct.pack_into("<4I", img, len(img) - 16, *scan, self.session)  # params at the end
        if load(nfc, mkpatch.build(bytes(img))) is None:
            raise nfcnet.NfcError("chip dead")

    def request(self, addr):
        self.seq += 1
        pkt = bytes([0x10, 0x2F, 0x2D, 7, self.session]) + struct.pack("<HI", self.seq, addr)
        for r in self.nfc.cmd(pkt):
            if r[:3] == b"\x10\x4f\x2d":
                return struct.unpack_from("<I", r, 4)[0], r[8:24]
        raise nfcnet.NfcError("no GET_PATCH_VERSION answer")

    def read(self, start, length, window=64, progress=None):
        """Pipelined: requests go out `window` at a time without waiting for replies, and
        each reply carries whichever chunk was filled last (usually the previous request's),
        keyed by its address. Missing chunks are requested again."""
        want = list(range(start, start + length, 16))
        got = {}
        while missing := [a for a in want if a not in got]:
            for i in range(0, len(missing), window):
                batch = missing[i:i + window]
                batch.append(batch[-1])  # the fill lags one request behind
                for a in batch:
                    self.seq += 1
                    pkt = bytes([0x10, 0x2F, 0x2D, 7, self.session]) + struct.pack("<HI", self.seq, a)
                    self.nfc.send_call(nfcnet.OP_XFER, struct.pack("<H", 500) + pkt)
                for _ in batch:
                    r = self.nfc.recv_reply(nfcnet.OP_XFER)
                    if r[:3] == b"\x10\x4f\x2d" and len(r) >= 24:
                        got[struct.unpack_from("<I", r, 4)[0]] = r[8:24]
                if progress:
                    progress(len(got) * 16)
        return b"".join(got[a] for a in want)[:length]

    def read_verified(self, start, length, progress=None):
        """Pipelining can tear a chunk (a new request refills OUT while the ROM copies it),
        so read everything twice and re-read chunks until two reads agree."""
        a = self.read(start, length, progress=progress)
        b = self.read(start, length, progress=progress)
        while bad := [o for o in range(0, length, 16) if a[o:o + 16] != b[o:o + 16]]:
            print(f"\n  {len(bad)} chunks disagree, re-reading")
            a = b
            b = bytearray(b)
            for o in bad:
                b[o:o + 16] = self.read(start + o, 16)
            b = bytes(b)
        return a

    def read16(self, addr, tries=4):
        """The fill may land after the reply was built; then the next request gets it."""
        for _ in range(tries):
            got, data = self.request(addr)
            if got == addr:
                return data
        raise nfcnet.NfcError(f"no data for {addr:08X} (last answer for {got:08X})")


def main():
    nfc = nfcnet.Nfc(sys.argv[1])
    nfc.takeover()
    if sys.argv[2] == "v1":
        v1(nfc, *(int(x, 16) for x in sys.argv[3:6]))
    elif sys.argv[2] == "read":
        addr = int(sys.argv[3], 16)
        end = addr + (int(sys.argv[4], 16) if len(sys.argv) > 4 else 20)
        for a in range(addr, end, 20):
            print(f"{a:08X}: {v2(nfc, 0, a).hex(' ')}")
    elif sys.argv[2] == "stream":
        start, length = int(sys.argv[3], 16), int(sys.argv[4], 16)
        data = stream(nfc, start, length, sys.argv[5] if len(sys.argv) > 5 else None)
        if len(sys.argv) <= 5:
            for i in range(0, len(data), 16):
                print(f"{start + i:08X}: {data[i:i + 16].hex(' ')}")
    elif sys.argv[2] == "v3debug":
        print("load: ", v3_load(nfc, 0, 1).hex(" "))
        for _ in range(3):
            print("query:", gpv(nfc).hex(" "))
    elif sys.argv[2] == "findbytes":
        pat = ~struct.unpack("<I", bytes.fromhex(sys.argv[5]))[0] & 0xFFFFFFFF
        r = v2(nfc, 2, int(sys.argv[3], 16), int(sys.argv[4], 16), pat)
        n = struct.unpack_from("<I", r)[0]
        print(f"{n} hits:", " ".join(f"{a:08X}" for a in struct.unpack_from("<4I", r, 4)[:min(n, 4)]))
    elif sys.argv[2] == "dump":
        start, length = int(sys.argv[3], 16), int(sys.argv[4], 16)
        out = sys.argv[5] if len(sys.argv) > 5 else None
        v4 = V4(nfc)
        t0 = time.time()
        data = v4.read_verified(start, length, progress=lambda n: print(f"\r  {n:#x}/{length:#x} bytes, {n / (time.time() - t0 + 1e-9):.0f} B/s", end="", flush=True))
        print()
        if out:
            open(out, "wb").write(data)
        else:
            for i in range(0, length, 16):
                print(f"{start + i:08X}: {data[i:i + 16].hex(' ')}")
    elif sys.argv[2] == "find":
        r = v2(nfc, 1, *(int(x, 16) for x in sys.argv[3:7]))
        n = struct.unpack_from("<I", r)[0]
        print(f"{n} hits:", " ".join(f"{a:08X}" for a in struct.unpack_from("<4I", r, 4)[:min(n, 4)]))


if __name__ == "__main__":
    main()
