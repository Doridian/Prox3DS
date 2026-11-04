# usage: tdis.py START END -> Thumb disassembly of the ROM, literal loads resolved
import struct, sys, capstone
rom = open(__file__.rsplit('/', 3)[0] + '/docs/dump/rom_20791B5.bin', 'rb').read()
md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
md.skipdata = True
s, e = int(sys.argv[1], 16), int(sys.argv[2], 16)
for i in md.disasm(rom[s:e], s):
    extra = ''
    if i.mnemonic.startswith('ldr') and '[pc' in i.op_str:
        try:
            imm = int(i.op_str.split('#')[-1].rstrip(']'), 0)
            t = ((i.address + 4) & ~3) + imm
            extra = f'   ; ={struct.unpack_from("<I", rom, t)[0]:#x}'
        except ValueError: pass
    print(f'{i.address:6x}: {i.bytes.hex():10s} {i.mnemonic} {i.op_str}{extra}')
