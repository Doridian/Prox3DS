# Encrypted Mifare Classic WRITE via mixed-parity frames (NOTES.md). Writes block 2 with a test
# pattern under key A FF..FF, reads it back encrypted, then restores zeros via the Gen1a backdoor.
# Usage: encwrite.py "j1,j2/j1,j2..." N  (HW-parity pairs to allow, number of writes)
import sys
sys.path.insert(0, __file__.rsplit('/', 1)[0])
from mixed import *
from crypto1 import Crypto1
import rawa

BLK, KEY = 2, bytes.fromhex('FFFFFFFFFFFF')
PAIRS = [tuple(int(x) for x in p.split(',')) for p in sys.argv[1].split('/')] if len(sys.argv) > 1 else [(0, 1)]
TRIES = int(sys.argv[2]) if len(sys.argv) > 2 else 3
s = Session('192.0.2.132')
s.recover()
pat2 = bytes.fromhex('c0ffee00112233445566778899aabbcc')
done = 0


def running_ok(data, par, hw):
    # HW parity = odd parity of every stream bit since the last inserted parity bit (raw included)
    bits = []
    for b, p in zip(data, par):
        bits += [(b >> k) & 1 for k in range(8)] + [p]
    last = 0
    for j in sorted(hw):
        if par[j] != 1 ^ (sum(bits[last:9 * j + 8]) & 1):
            return False
        last = 9 * j + 9
    return True

for attempt in range(40):
    c = s.retry(lambda: s.auth(BLK, KEY))
    if c is None:
        print('auth failed'); continue
    cmd = bytes([0xA0, BLK])
    enc, par = c.encrypt(cmd + crc_a(cmd))
    raw, off = s.ptx(enc, par)
    ack = c.decrypt_bits((raw[0] >> off) & 0xF, 4) if raw else None
    if ack != 0xA:
        print(f'attempt {attempt}: A0 answer {raw.hex() if raw else None} -> {ack}'); continue
    probe = Crypto1.from_state(c.odd, c.even)
    penc, ppar = probe.encrypt(pat2 + crc_a(pat2))
    ok = [p for p in PAIRS if running_ok(penc, ppar, p)]
    if not ok:
        continue  # leave the card waiting; the next auth resets it
    enc, par = c.encrypt(pat2 + crc_a(pat2))
    fifo, sched = build(enc, par, set(ok[0]))
    s.mon.frames()
    d, _ = txtime(s, fifo, 0x70, sched=sched)
    s.nfc.drain(150)
    fr = s.mon.frames()
    raw = fr[-1][1] if fr else None
    ack = c.decrypt_bits(raw[0] & 0xF, 4) if raw else None
    s.parity(False)
    rb = s.read_block(c, BLK) if ack == 0xA else None
    print(f'attempt {attempt}: pair {ok[0]} busy {d / 9.44 - 2.4:.1f}b answer {raw.hex() if raw else None} -> {ack}'
          f' readback {rb.hex() if rb else rb}{" MATCHES" if rb == pat2 else ""}', flush=True)
    done += 1
    if done >= TRIES:
        break
s.parity(True)
s.gen1a_write(BLK, bytes(16), verify=False)
print('restored:', (rawa.RawA.read_block(s, BLK) if s.gen1a_unlock() else b'').hex())
