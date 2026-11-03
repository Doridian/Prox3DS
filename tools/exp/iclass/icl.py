#!/usr/bin/env python3
"""iClass reader prototype on the BCM20791 through the reader image: 1-of-4 V TX (0x5C558 = 5) from a
stalled V poll, RX with the V analog setup, iClass anticollision / select / read / auth.

    icl.py HOST [KD_HEX]     read blocks 0-2 and 5 plain; with the diversified Kd, auth and read all
"""
import os
import struct
import sys
import time

sys.path.insert(0, __file__.rsplit("/", 3)[0])
import chipmon
import nfcnet

# V-only analog / framer values (the ROM's V tech setup, which the stall skips)
V_REGS = [(0x5C440, 0x08), (0x5C444, 0xD5), (0x5C448, 0x1C), (0x5C44C, 0x9A), (0x5C48C, 0x18),
          (0x5C53C, 0x01), (0x5C554, 0x18), (0x5C558, 0x05), (0x5C560, 0x0C)]
ACTALL, IDENTIFY, SELECT, READCHECK_KD, READCHECK_KC, CHECK, READ = 0x0A, 0x0C, 0x81, 0x88, 0x18, 0x05, 0x0C


def crc_iclass(data):
    """iClass CRC: poly 1021 reflected, init E012 (4807 bit-reversed), no final xor, LSB first."""
    crc = 0xE012  # 4807 bit-reversed (refin)
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = crc >> 1 ^ 0x8408 if crc & 1 else crc >> 1
    return bytes([crc & 0xFF, crc >> 8])


# --- iClass MAC (pm3 armsrc/optimized_cipher.c, opt_doReaderMAC) ---
def _lut():
    t = []
    for r in range(256):
        ls2 = (r << 2) & 0xFF
        a, o, n = r & ls2, r | ls2, r & ~ls2 & 0xFF
        z0 = (a >> 5) ^ (n >> 4) ^ (o >> 3)
        z1 = (o >> 6) ^ (o >> 1) ^ (r >> 5) ^ r
        z2 = (n >> 4) ^ (a >> 3) ^ r
        t.append((z0 & 4) | (z1 & 2) | (z2 & 1))
    return t


SEL = _lut()


def _succ(k, s, y):
    l, r, b, t = s
    tt = t & 0xC533
    tt ^= tt >> 1
    tt ^= tt >> 4
    tt ^= tt >> 10
    tt ^= tt >> 8
    tt &= 1
    t = (t >> 1) | ((tt ^ (r >> 7) ^ (r >> 3)) & 1) << 15
    ob = b ^ (b >> 6) ^ (b >> 5) ^ (b >> 4)
    b = ((b >> 1) | ((ob ^ r) & 1) << 7) & 0xFF
    sel = SEL[r] & 4 | (SEL[r] ^ ((tt ^ y) << 1)) & 2 | (SEL[r] ^ tt) & 1
    nr = ((k[sel] ^ b) + l) & 0xFF
    return [(nr + r) & 0xFF, nr, b, t]


def reader_mac(div_key, cc_nr):
    k = div_key
    s = [((k[0] ^ 0x4C) + 0xEC) & 0xFF, ((k[0] ^ 0x4C) + 0x21) & 0xFF, 0x4C, 0xE012]
    for byte in cc_nr:
        for i in range(8):
            s = _succ(k, s, (byte >> i) & 1)
    out = b""
    for _ in range(4):
        v = 0
        for i in range(8):
            v |= ((s[1] & 4) >> 2) << i
            s = _succ(k, s, 0)
        out += bytes([v])
    return out


class IClass:
    def __init__(self, host):
        self.nfc = nfcnet.Nfc(host)
        self.mon = chipmon.Mon(self.nfc, on_other=lambda p: None)

    def start(self):
        mon, nfc = self.mon, self.nfc
        mon.load()
        for c in ["20020401B70102", "21000401830183"]:
            nfc.cmd(bytes.fromhex("10" + c))
        mon.capture(True)
        nfc.write(bytes.fromhex("10210303017601"))  # stalls with capture on
        time.sleep(0.5)
        nfc.drain(100)
        for a, v in V_REGS:
            mon.write32(a, [v])

    def xfer(self, frame, wait=0.01):
        self.mon.frames()  # drop stale
        self.mon.txsched(frame, len(frame) << 4, [], r570=1, r574=5)
        time.sleep(wait)
        fr = self.mon.frames()
        return fr[-1][1] if fr else None

    def select(self):
        self.xfer(bytes([ACTALL]))
        asn = self.xfer(bytes([IDENTIFY]))
        if not asn or len(asn) < 10:
            return None
        csn = self.xfer(bytes([SELECT]) + asn[:8])
        return csn

    def read(self, block):
        r = self.xfer(bytes([READ, block]) + crc_iclass([block]))
        return r

    def auth(self, div_key, kc=False, block=2):
        cc = self.xfer(bytes([READCHECK_KC if kc else READCHECK_KD, block]))
        if not cc or len(cc) < 8:
            return None, cc
        nr = b"\0\0\0\0"
        mac = reader_mac(div_key, cc[:8] + nr)
        tmac = self.xfer(bytes([CHECK]) + nr + mac)
        return tmac, cc

    def stop(self):
        self.mon.capture(False)
        self.nfc.cmd(bytes.fromhex("1021060100"))


def main():
    ic = IClass(sys.argv[1])
    ic.start()
    csn = ic.select()
    print("CSN", csn and csn.hex(), "crc ok" if csn and crc_iclass(csn[:8]) == csn[8:10] else "")
    for blk in (0, 1, 2, 5):
        r = ic.read(blk)
        print(f"block {blk}: {r.hex() if r else None}")
    if len(sys.argv) > 2:
        tmac, cc = ic.auth(bytes.fromhex(sys.argv[2]))
        print("CC", cc and cc.hex(), "tag MAC", tmac and tmac.hex())
        if tmac:
            for blk in range(6, 0x20):
                r = ic.read(blk)
                print(f"block {blk:2}: {r.hex() if r else None}")
    ic.stop()


if __name__ == "__main__":
    main()
