"""Crypto1 (Mifare Classic), straight port of crapto1's reference cipher (odd/even LFSR halves).

Words are big-endian as on the wire (uid, nt, nr as uint32 from 4 bytes MSB first); bytes go
through the cipher LSB first.

Derived from crapto1 (C) 2008-2014 bla <blapost@gmail.com> and the Proxmark3 contributors, GPL; see CREDITS.md."""

LF_POLY_ODD = 0x29CE5C
LF_POLY_EVEN = 0x870804


def _bit(x, n):
    return (x >> n) & 1


def _parity(x):
    return bin(x).count("1") & 1


def filter_bit(x):
    f = (0xF22C0 >> (x & 0xF)) & 16
    f |= (0x6C9C0 >> ((x >> 4) & 0xF)) & 8
    f |= (0x3C8B0 >> ((x >> 8) & 0xF)) & 4
    f |= (0x1E458 >> ((x >> 12) & 0xF)) & 2
    f |= (0x0D938 >> ((x >> 16) & 0xF)) & 1
    return _bit(0xEC57E80A, f)


def odd_parity_bit(b):
    """ISO14443A parity bit for a plaintext byte (makes the 9 bits odd)."""
    return 1 ^ _parity(b)


def prng_successor(x, n):
    x = int.from_bytes(x.to_bytes(4, "big"), "little")
    for _ in range(n):
        x = (x >> 1) | (((x >> 16) ^ (x >> 18) ^ (x >> 19) ^ (x >> 21)) & 1) << 31
    return int.from_bytes(x.to_bytes(4, "little"), "big")


class Crypto1:
    def __init__(self, key):
        """key: 6 bytes."""
        k = int.from_bytes(key, "big")
        self.odd = self.even = 0
        for i in range(47, 0, -2):
            self.odd = (self.odd << 1) | _bit(k, (i - 1) ^ 7)
            self.even = (self.even << 1) | _bit(k, i ^ 7)

    @classmethod
    def from_state(cls, odd, even):
        c = cls(bytes(6))
        c.odd, c.even = odd, even
        return c

    def bit(self, inp=0, encrypted=False):
        ret = filter_bit(self.odd)
        feed = (ret if encrypted else 0) ^ (1 if inp else 0)
        feed ^= LF_POLY_ODD & self.odd
        feed ^= LF_POLY_EVEN & self.even
        self.even = ((self.even << 1) | _parity(feed)) & 0xFFFFFF
        self.odd, self.even = self.even, self.odd
        return ret

    def byte(self, inp=0, encrypted=False):
        return sum(self.bit(_bit(inp, i), encrypted) << i for i in range(8))

    def word(self, inp=0, encrypted=False):
        """32 bits, fed in wire order: byte 0 (MSB) first, each byte LSB first."""
        ret = 0
        for i in range(32):
            ret |= self.bit(_bit(inp, i ^ 24), encrypted) << (i ^ 24)
        return ret

    def peek(self):
        """Keystream bit for the next parity bit (the state is not advanced for parity)."""
        return filter_bit(self.odd)

    def encrypt(self, data):
        """Encrypt plaintext bytes for TX: returns (cipher bytes, encrypted parity bits)."""
        out, par = bytearray(), []
        for b in data:
            out.append(self.byte() ^ b)
            par.append(self.peek() ^ odd_parity_bit(b))
        return bytes(out), par

    def decrypt(self, data):
        return bytes(self.byte() ^ b for b in data)

    def decrypt_bits(self, value, n):
        """Decrypt an n-bit (< 8) answer such as a 4-bit ACK."""
        return value ^ sum(self.bit() << i for i in range(n))


def auth_answer(key, uid, nt, nr):
    """Reader side of the 3-pass auth after receiving plaintext nt (first auth).
    Returns (cipher state, {nr}{ar} 8 bytes, their 8 parity bits, expected at)."""
    c = Crypto1(key)
    c.word(uid ^ nt)
    out, par = bytearray(), []
    for b in nr.to_bytes(4, "big"):
        out.append(c.byte(b) ^ b)
        par.append(c.peek() ^ odd_parity_bit(b))
    ar = prng_successor(nt, 64)
    for b in ar.to_bytes(4, "big"):
        out.append(c.byte() ^ b)
        par.append(c.peek() ^ odd_parity_bit(b))
    return c, bytes(out), par, prng_successor(nt, 96)
