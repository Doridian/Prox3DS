#!/usr/bin/env python3
"""Decode a Broadcom BCM2079x SPD patch (.ncd, as extracted from the 3DS nfc sysmodule).

Records: 10 2F 2E <len> <type> <payload>. Types: 00 header, 01 SRAM, 02 AON,
03 ROM hook table, 04 secure patch table, 06 signature.
SRAM/AON streams start with a Thumb entry pointer; load address = (entry & ~1) - 4.
Hook table: N ROM word addresses, enable mask, N replacement Thumb BL instructions.
"""
import struct, sys, collections

def segments(blob):
    segs, o = {}, 0
    while o < len(blob):
        ln = blob[o + 3]
        p = blob[o + 4:o + 4 + ln]
        segs.setdefault(p[0], bytearray()).extend(p[1:])
        o += 4 + ln
    return {k: bytes(v) for k, v in segs.items()}

def bl_target(pc, ins):
    hi, lo = ins & 0xFFFF, ins >> 16
    off = ((hi & 0x7FF) << 12) | ((lo & 0x7FF) << 1)
    if off & 0x400000: off -= 0x800000
    return pc + 4 + off

def hooks(t3):
    words = [struct.unpack_from('<I', t3, i)[0] for i in range(0, len(t3) // 4 * 4, 4)]
    for n in range(1, len(words)):
        if words[n] == (1 << n) - 1:
            return [(a * 4, words[n + 1 + i]) for i, a in enumerate(words[:n])]
    raise ValueError('no enable mask found')

def main(path):
    s = segments(open(path, 'rb').read())
    loads = {}
    for t, name in ((1, 'sram'), (2, 'aon')):
        entry = struct.unpack_from('<I', s[t], 0)[0]
        loads[name] = ((entry & ~1) - 4, len(s[t]))
        print(f'{name}: load {loads[name][0]:#08x}..{loads[name][0] + loads[name][1]:#08x} entry {entry:#x}')
    print('hooks (ROM site: replacement halfwords):')
    for rom, ins in hooks(s[3]):
        is_bl = (ins & 0xF800) == 0xF000 and (ins >> 16) & 0xF800 == 0xF800
        what = f'BL {bl_target(rom, ins):#08x}' if is_bl else 'raw insn'
        print(f'  {rom:#07x}: {ins & 0xFFFF:04x} {ins >> 16:04x}  {what}')
    print('literal-looking words in patch code, by 64K region:')
    regions = collections.Counter()
    for t in (1, 2):
        d = s[t]
        for i in range(0, len(d) - 3):
            v = struct.unpack_from('<I', d, i)[0]
            if (i + loads['sram' if t == 1 else 'aon'][0]) % 4 == 0 and 0x10000 <= v < 0x10000000:
                regions[v >> 16] += 1
    for r, c in sorted(regions.items()):
        if c >= 3: print(f'  {r << 16:#010x}: {c}')

if __name__ == '__main__':
    main(sys.argv[1])
