#!/usr/bin/env python3
"""Build a Broadcom SPD patch (.ncd) around our own SRAM image.

Everything is generated here, nothing is copied from the stock patch: the header is
built field by field (values as in the stock B5 patch), the AON segment is a thunk to
the ROM init the stock AON entry calls (plus our AON code at 0x68018, if any), the hook table is ours (default: no hooks), the
SRAM segment is ours, the signature is 48 zero bytes (not checked, see NOTES.md).

    mkpatch.py SRAM.bin OUT.ncd [--aon AON.bin] [--chipver STR16] [--hook ROMADDR:HALFWORDS ...]
"""
import argparse
import struct

CHUNK = 0xF0
AON_LOAD = 0x68008
AON_CODE = 0x68018  # chip/link.ld's aoncode region: free AON RAM after the thunk
AON_ROM_INIT = 0x11888  # what the stock AON entry calls: [0x68C80] = 0x32E0, [0x68C84] = 0
PROJECT = 0x0004
VERSION = (11, 64)  # shown as major.minor by GET_PATCH_VERSION


def frame(rtype, data):
    return bytes([0x10, 0x2F, 0x2E, len(data) + 1, rtype]) + data


def thumb_bl(pc, target):
    off = (target - (pc + 4)) >> 1
    return struct.pack("<HH", 0xF000 | (off >> 11) & 0x7FF, 0xF800 | off & 0x7FF)


def aon_thunk():
    # Entry pointer, then push {lr}; bl AON_ROM_INIT; pop {r1}; bx r1 (entered at load + 4).
    code = struct.pack("<I", AON_LOAD + 4 | 1) + b"\x00\xb5"
    code += thumb_bl(AON_LOAD + 6, AON_ROM_INIT)
    return code + b"\x02\xbc\x08\x47"


def header(sram_load, chipver):
    # u8 1, RAM ptrs 0x3B590 / 0 / 0x3B598, AON load, SRAM load, u16 project, u8 0, u8 7,
    # chipver[16] (echoed by GET_PATCH_VERSION), version major, 0, minor, 0.
    return (struct.pack("<BIIIIIHBB", 1, 0x3B590, 0, 0x3B598, AON_LOAD, sram_load, PROJECT, 0, 7)
            + chipver.ljust(16, b"\0")[:16] + bytes([VERSION[0], 0, VERSION[1], 0]))


def build(sram, chipver=None, hooks=(), aon=b""):
    load = (struct.unpack_from("<I", sram)[0] & ~1) - 4

    # Hook table: N ROM word addresses, enable mask, N replacement words.
    hook = struct.pack(f"<{len(hooks)}I", *(a // 4 for a, _ in hooks))
    hook += struct.pack("<I", (1 << len(hooks)) - 1)
    hook += struct.pack(f"<{len(hooks)}I", *(w for _, w in hooks))

    out = frame(0, header(load, chipver or b"20791B5")) + frame(3, hook)
    aon_seg = aon_thunk()
    if aon:
        aon_seg = aon_seg.ljust(AON_CODE - AON_LOAD, b"\0") + aon
    for seg_type, seg in ((2, aon_seg), (1, sram)):
        for i in range(0, len(seg), CHUNK):
            out += frame(seg_type, seg[i:i + CHUNK])
    return out + frame(6, bytes(48))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("sram")
    ap.add_argument("out")
    ap.add_argument("--aon", help="code for the AON RAM at 0x68018 (chip/<name>.aon.bin)")
    ap.add_argument("--chipver", help="16-byte chip version string in the header")
    ap.add_argument("--hook", action="append", default=[], help="ROMADDR:WORD (hex)")
    a = ap.parse_args()
    hooks = [tuple(int(x, 16) for x in h.split(":")) for h in a.hook]
    ncd = build(open(a.sram, "rb").read(), a.chipver.encode() if a.chipver else None, hooks,
                open(a.aon, "rb").read() if a.aon else b"")
    open(a.out, "wb").write(ncd)
    print(f"{a.out}: {len(ncd)} bytes")


if __name__ == "__main__":
    main()
