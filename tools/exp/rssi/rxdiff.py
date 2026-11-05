import sys, collections
sys.path.insert(0, __file__.rsplit('/', 3)[0])
from mfc import *
from rawa import with_crc
s = Session(sys.argv[1]); s.recover()
def snap():
    out = {}
    for base in range(0x5C000, 0x5C800, 0x80):
        if base == 0x5C600: continue
        for i, v in enumerate(s.mon.read32(base, 32)): out[base + 4 * i] = v
    return out
IQ = {0x5C420, 0x5C424, 0x5C428, 0x5C42C, 0x5C454, 0x5C458, 0x5C510, 0x5C514, 0x5C518, 0x5C04C}
idle = [snap() for k in range(3)]
cmds = [b'\x30\x00', b'\x30\x04', b'\x60', b'\x30\x08', b'\x30\x00']
after = []
for c in cmds:
    a = s.answer(with_crc(c)); after.append(snap())
keys = sorted(idle[0])
for k in keys:
    iv = {d[k] for d in idle}; av = [d[k] for d in after]
    if len(iv) == 1 and len(set(av) | iv) > 1 and k not in IQ:
        print(f'{k:x} idle {next(iter(iv)):x} after', ' '.join(f'{v:x}' for v in av))
    elif len(iv) > 1 and k not in IQ:
        print(f'{k:x} idle-varies', ' '.join(f'{d[k]:x}' for d in idle), '|', ' '.join(f'{v:x}' for v in av))
