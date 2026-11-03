#!/usr/bin/env python3
"""Raw ISO14443A through the debug monitor (chip/reader.c): our frames go straight to the
framer (OP_TXRAW) and answers come from the capture ring (OP_CAPTURE), with the ROM's RF state
machine shut out. The ROM still does the first activation (field on, card selected).

    rawa.py HOST info                      activate, show ATQA/UID/SAK, probe the Gen1a backdoor
    rawa.py HOST gen1a-dump OUT [BLOCKS]   read every block through the Gen1a backdoor (default 64)
    rawa.py HOST gen1a-write BLK HEX32     write 16 bytes to a block through the Gen1a backdoor
    rawa.py HOST nonce [N]                 collect N AUTH nonces (key A, block 0)

Framer facts (NOTES.md): in mode r574 = 1 frames go out exactly as given (no CRC), except a
SELECT (93/95/97 70 ...) which the hardware CRCs itself; r568 = bytes << 4 | extra bits; a
1-byte frame needs a padding byte in the FIFO. RX status 0x5C588 bit 1 = no/bad CRC.
"""
import struct
import sys
import time

import chipmon
import nfcnet

RF_DISCOVER_MAP = bytes.fromhex("1021000701020101040101")  # T2T + ISO-DEP -> Frame interface
RF_DISCOVER_A = bytes.fromhex("10210303010001")             # NFC-A passive poll
RF_DEACTIVATE = bytes.fromhex("1021060100")


def crc_a(data):
    c = 0x6363
    for b in data:
        b ^= c & 0xFF
        b ^= (b << 4) & 0xFF
        c = (c >> 8) ^ (b << 8) ^ (b << 3) ^ (b >> 4)
    return bytes([c & 0xFF, c >> 8])


def with_crc(data):
    return bytes(data) + crc_a(data)


class RawA:
    def __init__(self, host):
        self.nfc = nfcnet.Nfc(host)
        self.ntfs = []
        self.mon = chipmon.Mon(self.nfc, on_other=self.ntfs.append)
        self.uid = self.atqa = self.sak = None

    def start(self, tries=4):
        """Load the monitor, let the ROM activate a card, then take over the framer."""
        for _ in range(tries):
            try:
                self.mon.load()
                self.nfc.cmd(RF_DISCOVER_MAP)
                pkts = self.nfc.cmd(RF_DISCOVER_A, 1000)
                t = time.time()
                while not any(p[1:3] == b"\x61\x05" for p in pkts) and time.time() - t < 3:
                    pkts += self.nfc.drain(200)
                act = [p for p in pkts if p[1:3] == b"\x61\x05"]
                if not act:
                    continue
                self._parse_activation(act[0])
                self.mon.capture(True)
                return True
            except (chipmon.MonError, nfcnet.NfcError) as e:
                print(f"  (start retry: {e})")
        return False

    def _parse_activation(self, pkt):
        # RF_INTF_ACTIVATED_NTF: id, intf, proto, mode, max, credits, len, NFC-A params
        p = pkt[4:]
        params = p[7:7 + p[6]]
        self.atqa = params[0:2]
        uid_len = params[2]
        self.uid = params[3:3 + uid_len]
        self.sak = params[4 + uid_len] if params[3 + uid_len] else None

    def tx(self, data, code=None):
        """Send one frame, return the captured answers [(regs, bytes)]."""
        data = bytes(data)
        code = len(data) << 4 if code is None else code
        if len(data) == 1 and not code & 0xF:
            data += b"\0"  # a lone full byte needs a padding byte in the TX FIFO (7-bit frames don't)
        self.mon.txraw(data, code)
        self.nfc.drain(150)
        return self.mon.frames()

    def answer(self, data, code=None):
        fr = self.tx(data, code)
        return fr[-1][1] if fr else None

    def halt(self):
        self.tx(with_crc(b"\x50\x00"))

    def select(self):
        """HLTA + WUPA + SELECT (cascade level 1 only); returns SAK or None."""
        self.halt()
        atqa = self.answer(b"\x52", 0x07)
        if not atqa or len(atqa) != 2:
            return None
        sel = b"\x93\x70" + self.uid + bytes([self.uid[0] ^ self.uid[1] ^ self.uid[2] ^ self.uid[3]])
        a = self.answer(sel)  # the hardware adds SELECT's CRC
        return a[0] if a else None

    def gen1a_unlock(self):
        self.halt()
        a = self.answer(b"\x40", 0x07)
        b = self.answer(b"\x43", 0x10)
        return a == b"\x0a" and b == b"\x0a"

    def read_block(self, blk):
        """READ (16 bytes) with CRC checked; None on failure."""
        a = self.answer(with_crc(bytes([0x30, blk])))
        if a and len(a) == 18 and crc_a(a[:16]) == a[16:]:
            return a[:16]
        return None

    def data_tx(self, payload):
        """Data-mode (r574 = 0) TX with a HW-appended CRC (length code 0); last answer or None.
        Data mode feeds the whole frame through the deeper FIFO, so it is not limited to the 7-byte
        parity-off bit-mode FIFO -- that is how an 18-byte WRITE data frame goes out (NOTES.md)."""
        self.mon.txraw(bytes(payload), code=0, r574=0)
        self.nfc.drain(150)
        fr = self.mon.frames()
        return fr[-1][1] if fr else None

    def gen1a_write(self, blk, data, verify=True):
        """Gen1a backdoor WRITE (plaintext, no auth): unlock, then A0 blk + 16 data bytes, each
        answered by a 4-bit ACK (0x0a). HW does parity and CRC. Returns True ok, False on NAK,
        None if the backdoor or card went silent. data: 16 bytes. WRITES THE CARD."""
        data = bytes(data)
        if len(data) != 16:
            raise ValueError("block data must be 16 bytes")
        if not self.gen1a_unlock():
            return None
        if self.data_tx(bytes([0xA0, blk])) != b"\x0a":
            return False
        if self.data_tx(data) != b"\x0a":
            return False
        if not verify:
            return True
        self.gen1a_unlock()
        return self.read_block(blk) == data


def gen1a_dump(host, out, n_blocks=64):
    r = RawA(host)
    blocks = {}
    while len(blocks) < n_blocks:
        if not r.start():
            sys.exit("no card")
        try:
            if not r.gen1a_unlock():
                sys.exit("Gen1a backdoor not answering (not a magic card?)")
            for blk in range(n_blocks):
                if blk in blocks:
                    continue
                for _ in range(3):
                    d = r.read_block(blk)
                    if d:
                        blocks[blk] = d
                        break
                    r.gen1a_unlock()
                print(f"{blk:3d}: {d.hex(' ') if d else 'FAILED'}")
        except chipmon.MonError as e:
            print(f"  (chip stalled at {len(blocks)} blocks: {e}; reloading)")
    open(out, "wb").write(b"".join(blocks[i] for i in range(n_blocks)))
    print(f"wrote {out}")


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    host, what, args = sys.argv[1], sys.argv[2], sys.argv[3:]
    if what == "info":
        r = RawA(host)
        if not r.start():
            sys.exit("no card")
        print(f"ATQA {r.atqa.hex()} UID {r.uid.hex()} SAK {r.sak:02X}")
        print("Gen1a backdoor:", "yes" if r.gen1a_unlock() else "no")
    elif what == "gen1a-dump":
        gen1a_dump(host, args[0], int(args[1]) if len(args) > 1 else 64)
    elif what == "gen1a-write":
        blk, data = int(args[0]), bytes.fromhex(args[1])
        r = RawA(host)
        if not r.start():
            sys.exit("no card")
        before = r.read_block(blk)
        print(f"block {blk} before: {before.hex(' ') if before else before}")
        ok = r.gen1a_write(blk, data)
        print(f"wrote {data.hex(' ')}")
        print("VERIFIED" if ok else f"write failed ({ok})")
    elif what == "nonce":
        r = RawA(host)
        if not r.start():
            sys.exit("no card")
        for _ in range(int(args[0]) if args else 8):
            r.select()
            nt = r.answer(with_crc(b"\x60\x00"))
            print("nt", nt.hex() if nt else None)
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
