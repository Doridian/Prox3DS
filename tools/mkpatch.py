#!/usr/bin/env python3
"""Build a Broadcom SPD patch (.ncd) around our own SRAM image.

Header and AON segment are taken from the stock B5 patch (the AON entry only calls
a ROM function); the hook table is replaced (default: no hooks), the SRAM segment is
ours, the signature is 48 zero bytes (not checked, see NOTES.md).

    mkpatch.py SRAM.bin OUT.ncd [--chipver STR16] [--hook ROMADDR:HALFWORDS ...]
"""
import argparse
import struct

STOCK = __file__.rsplit("/", 2)[0] + "/extracted/patch_20791B5.ncd"
CHUNK = 0xF0


def records(ncd):
    o = 0
    while o + 5 <= len(ncd):
        ln = ncd[o + 3]
        yield ncd[o + 4], ncd[o + 5:o + 4 + ln]
        o += 4 + ln


def frame(rtype, data):
    return bytes([0x10, 0x2F, 0x2E, len(data) + 1, rtype]) + data


def build(sram, chipver=None, hooks=()):
    stock = list(records(open(STOCK, "rb").read()))
    header = bytearray(next(d for t, d in stock if t == 0))
    aon = b"".join(d for t, d in stock if t == 2)

    load = (struct.unpack_from("<I", sram)[0] & ~1) - 4
    struct.pack_into("<I", header, 17, load)  # SRAM load address field
    if chipver is not None:
        header[25:41] = chipver.ljust(16, b"\0")[:16]

    # Hook table: N ROM word addresses, enable mask, N replacement words.
    hook = struct.pack(f"<{len(hooks)}I", *(a // 4 for a, _ in hooks))
    hook += struct.pack("<I", (1 << len(hooks)) - 1)
    hook += struct.pack(f"<{len(hooks)}I", *(w for _, w in hooks))

    out = frame(0, bytes(header)) + frame(3, hook)
    for seg_type, seg in ((2, aon), (1, sram)):
        for i in range(0, len(seg), CHUNK):
            out += frame(seg_type, seg[i:i + CHUNK])
    return out + frame(6, bytes(48))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("sram")
    ap.add_argument("out")
    ap.add_argument("--chipver", help="16-byte chip version string in the header")
    ap.add_argument("--hook", action="append", default=[], help="ROMADDR:WORD (hex)")
    a = ap.parse_args()
    hooks = [tuple(int(x, 16) for x in h.split(":")) for h in a.hook]
    ncd = build(open(a.sram, "rb").read(), a.chipver.encode() if a.chipver else None, hooks)
    open(a.out, "wb").write(ncd)
    print(f"{a.out}: {len(ncd)} bytes")


if __name__ == "__main__":
    main()
