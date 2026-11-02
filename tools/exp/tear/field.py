# Tear-off groundwork (#18): which register switches the reader field off? Activate a card
# (UL EV1 test card), READ page 0, poke a candidate, restore the field (0x5C55C = 0x81 as the
# ROM does), and see whether the card lost its state (READ silent, WUPA answers = power-cycled).
import sys, time
sys.path.insert(0, __file__.rsplit('/', 3)[0])
from mfc import *
from rawa import with_crc

s = Session(sys.argv[1] if len(sys.argv) > 1 else '192.0.2.6')
s.recover()
print('uid', s.uid.hex(), 'atqa', s.atqa.hex(), 'sak', s.sak)

def rd():
    a = s.answer(with_crc(b'\x30\x00'))
    return a.hex() if a else None

def regs():
    w = s.mon.read32(0x5C540, 32)
    return ' '.join(f'{v:x}' for v in w)

print('regs', regs())
print('read', rd())
for val in [int(x, 16) for x in sys.argv[2:]]:
    s.mon.write32(0x5C55C, [val])
    time.sleep(0.02)
    after = s.mon.read32(0x5C540, 32)
    s.mon.write32(0x5C55C, [0x41]); time.sleep(0.003); s.mon.write32(0x5C55C, [0x81]); time.sleep(0.01)
    r = rd()
    w = s.answer(b'\x52', 0x07)
    print(f'{val:02x}: read {r}  wupa {w.hex() if w else None}  55c={after[7]:x}')
    if w:  # back to ACTIVE for the next try (CL1 + CL2 for a 7-byte UID)
        u = s.uid
        s.answer(b'\x93\x20'); s.answer(b'\x93\x70' + b'\x88' + u[:3] + bytes([0x88 ^ u[0] ^ u[1] ^ u[2]]))
        s.answer(b'\x95\x20'); s.answer(b'\x95\x70' + u[3:7] + bytes([u[3] ^ u[4] ^ u[5] ^ u[6]]))
        print('   reselected, read', rd())
