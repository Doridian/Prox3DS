#!/usr/bin/env python3
"""Mifare Classic over the raw framer (tools/rawa.py) with parity under our control.

With 0x5C560 = 8 the framer sends and receives raw bit streams: we pack each byte LSB first plus
its parity bit (encrypted parity for Crypto1), and answers come back the same way. The RX stream
continues at the bit position where our TX frame ended (TX bits % 8), except after 7-bit short
frames (WUPA/REQA), where it starts at bit 0.
"""
import socket
import sys
import time

import chipmon
import nfcnet
import rawa
from crypto1 import Crypto1, prng_successor
from rawa import crc_a

PARITY_REG = 0x5C560
PARITY_OFF = 0x08


def pack(data, par=None):
    """Bytes (+ given or plain odd parity bits) -> (FIFO bytes, length code)."""
    bits = []
    for i, b in enumerate(data):
        bits += [(b >> k) & 1 for k in range(8)]
        bits.append(par[i] if par is not None else 1 ^ (bin(b).count("1") & 1))
    out = bytearray((len(bits) + 7) // 8)
    for i, v in enumerate(bits):
        out[i // 8] |= v << (i % 8)
    return bytes(out), (len(bits) // 8) << 4 | (len(bits) % 8)


def unpack(raw, off, nbytes=None):
    """Raw RX stream -> (bytes, parity bits), 9-bit groups starting at bit `off`."""
    bits = [(raw[i // 8] >> (i % 8)) & 1 for i in range(len(raw) * 8)][off:]
    n = len(bits) // 9 if nbytes is None else nbytes
    out, par = bytearray(), []
    for k in range(n):
        g = bits[9 * k:9 * k + 9]
        if len(g) < 9:
            break
        out.append(sum(g[j] << j for j in range(8)))
        par.append(g[8])
    return bytes(out), par


class Session(rawa.RawA):
    def __init__(self, host):
        super().__init__(host)
        self.host = host

    def reconnect(self):
        """New TCP connection: after a timeout, late replies left in the old socket desync every
        later call."""
        try:
            self.nfc.sock.close()
        except OSError:
            pass
        for _ in range(10):
            try:
                self.nfc.sock = socket.create_connection((self.host, nfcnet.PORT), timeout=10)
                self.nfc.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                return
            except OSError as e:
                print(f"  (reconnect: {e})")
                time.sleep(2)

    def recover(self):
        while True:
            try:
                if self.start():
                    return
            except (chipmon.MonError, nfcnet.NfcError, OSError) as e:
                print(f"  (recover: {e})")
            self.reconnect()

    def retry(self, fn, tries=4):
        """Run fn(); on a chip stall reload the monitor, re-activate and try again."""
        for _ in range(tries):
            try:
                return fn()
            except (chipmon.MonError, nfcnet.NfcError, OSError) as e:
                print(f"  (stall: {e}; reloading)")
                self.reconnect()
                self.recover()
        raise chipmon.MonError("giving up")

    def parity(self, on):
        self.mon.write32(PARITY_REG, [0 if on else PARITY_OFF])

    def ptx(self, data, par=None):
        """Parity-off TX; returns (raw answer or None, RX bit offset)."""
        fifo, code = pack(data, par)
        fr = self.tx(fifo, code)
        return (fr[-1][1] if fr else None), (len(data) * 9) % 8

    def wupa(self):
        """HLTA + WUPA with parity on; returns ATQA or None."""
        self.parity(True)
        self.halt()
        return self.answer(b"\x52", 0x07)

    def auth(self, block, key, key_b=False, nr=0x12345678):
        """Select, then first (plaintext nt) auth via reader.c OP_AUTH. Returns the Crypto1 state
        positioned after {at}, or None (wrong key: the card stays silent or {at} mismatches).
        Leaves parity off; the card is in the authenticated state."""
        self.parity(True)
        if self.select() is None:
            raise chipmon.MonError("select failed")
        self.parity(False)
        a = bytes([0x61 if key_b else 0x60, block])
        fifo, code = pack(a + crc_a(a))
        self.mon.frames()
        r = self.mon.auth(key, int.from_bytes(self.uid, "big"), nr, fifo, code)
        if not r:
            raise chipmon.MonError("no nt")
        nt, odd, even = r
        self.nfc.drain(100)
        fr = self.mon.frames()
        if len(fr) < 2:
            return None
        c = Crypto1.from_state(odd, even)
        at = int.from_bytes(c.decrypt(unpack(fr[-1][1], 0, 4)[0]), "big")
        return c if at == prng_successor(nt, 96) else None

    def read_block(self, c, block):
        """Encrypted READ in an authenticated session; returns 16 bytes or None."""
        cmd = bytes([0x30, block])
        enc, par = c.encrypt(cmd + crc_a(cmd))
        raw, off = self.ptx(enc, par)
        if not raw:
            return None
        d = c.decrypt(unpack(raw, off, 18)[0])
        return d[:16] if len(d) == 18 and crc_a(d[:16]) == d[16:] else None


DEFAULT_KEYS = ["FFFFFFFFFFFF", "A0A1A2A3A4A5", "D3F7D3F7D3F7", "000000000000", "B0B1B2B3B4B5",
                "4D3A99C351DD", "1A982C7E459A", "AABBCCDDEEFF", "714C5C886E97", "587EE5F9350F"]


def first_block(sector):
    return sector * 4 if sector < 32 else 128 + (sector - 32) * 16


def dump(s, keys, sectors=16):
    """Find a key per sector (A, then B) and read the sector. Returns (blocks, keys found):
    blocks[i] is None where unreadable; trailers get the found keys filled in (they read as 0)."""
    blocks, found = {}, {}
    for sec in range(sectors):
        n = 4 if sec < 32 else 16
        b0 = first_block(sec)
        for key_b in (False, True):
            for key in keys:
                c = s.retry(lambda: s.auth(b0, key, key_b))
                if c is None:
                    continue
                found[sec, key_b] = key
                data = s.retry(lambda: [s.read_block(c, b0 + i) for i in range(n)])
                for i, d in enumerate(data):
                    if d is not None and blocks.get(b0 + i) is None:
                        blocks[b0 + i] = d
                break
            if all(blocks.get(b0 + i) is not None for i in range(n)):
                break
        t = blocks.get(b0 + n - 1)
        if t is not None:
            ka = found.get((sec, False), t[:6])
            kb = found.get((sec, True), t[10:])
            blocks[b0 + n - 1] = ka + t[6:10] + kb
        ka, kb = found.get((sec, False)), found.get((sec, True))
        print(f"sector {sec:2}: A {ka.hex() if ka else '?' * 12}  B {kb.hex() if kb else '?' * 12}",
              flush=True)
    return blocks, found


def main():
    import argparse
    ap = argparse.ArgumentParser(description="Mifare Classic reader over the 3DS NFC chip")
    ap.add_argument("host")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("read", help="read one block")
    r.add_argument("block", type=int)
    r.add_argument("key")
    r.add_argument("-b", action="store_true", help="use key B")
    d = sub.add_parser("dump", help="dump the card with a key list (read only)")
    d.add_argument("keys", nargs="*", help="keys to try in addition to the defaults")
    d.add_argument("-o", help="output .bin (unreadable blocks are zero-filled)")
    d.add_argument("--compare", help="compare with a reference dump")
    d.add_argument("--sectors", type=int, default=16)
    a = ap.parse_args()

    s = Session(a.host)
    s.recover()
    print(f"UID {s.uid.hex()}")
    if a.cmd == "read":
        def run():
            c = s.auth(a.block, bytes.fromhex(a.key), a.b)
            return "auth failed" if c is None else s.read_block(c, a.block)
        d = s.retry(run)
        print(d.hex(" ") if isinstance(d, bytes) else d)
        return
    keys = list(dict.fromkeys(bytes.fromhex(k) for k in a.keys + DEFAULT_KEYS))
    blocks, _ = dump(s, keys, a.sectors)
    nblk = first_block(a.sectors)
    img = b"".join(blocks.get(i) or bytes(16) for i in range(nblk))
    missing = [i for i in range(nblk) if blocks.get(i) is None]
    print(f"{nblk - len(missing)}/{nblk} blocks read" + (f", missing {missing}" if missing else ""))
    if a.o:
        open(a.o, "wb").write(img)
    if a.compare:
        ref = open(a.compare, "rb").read()
        diff = [i for i in range(nblk) if i not in missing and img[16 * i:16 * i + 16] != ref[16 * i:16 * i + 16]]
        print("matches reference" if not diff else f"differs from reference in blocks {diff}")
        for i in diff:
            print(f"  {i:3}: {img[16 * i:16 * i + 16].hex(' ')}\n       {ref[16 * i:16 * i + 16].hex(' ')}")


if __name__ == "__main__":
    main()
