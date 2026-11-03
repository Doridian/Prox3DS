"""Crypto1 key recovery (crapto1 port): recover the 48-bit key from 32 keystream bits + the fed
input (uid ^ nt), as produced by a Mifare nested-auth tag nonce. Forward cipher is in crypto1.py.

lfsr_recovery32(ks2, in) -> candidate (odd, even) states (crypto1.py representation) positioned
after feeding `in`; roll them back over `in` and read the key with recover_keys().

Faithful port of bla's crapto1 (extend_table / recover / rollback); the odd/even state split and
the filter match crypto1.py, so recovered states plug straight into Crypto1.from_state().

Derived from crapto1 (C) 2008-2014 bla <blapost@gmail.com> and the Proxmark3 contributors, GPL; see CREDITS.md."""

from crypto1 import filter_bit, _parity, Crypto1

LF_POLY_ODD = 0x29CE5C
LF_POLY_EVEN = 0x870804
M32 = 0xFFFFFFFF


def _bebit(x, n):
    return (x >> (n ^ 24)) & 1


def _update_contribution(item, m1, m2):
    p = item >> 25
    p = (p << 1) | _parity(item & m1)
    p = (p << 1) | _parity(item & m2)
    return ((p << 24) | (item & 0xFFFFFF)) & M32


def _extend_table(tbl, bit, m1, m2, inn):
    inn = (inn << 24) & M32
    out = []
    for t in tbl:
        t = (t << 1) & M32
        if filter_bit(t) ^ filter_bit(t | 1):
            t |= filter_bit(t) ^ bit
            out.append(_update_contribution(t, m1, m2) ^ inn)
        elif filter_bit(t) == bit:
            out.append(_update_contribution(t, m1, m2) ^ inn)
            out.append(_update_contribution(t | 1, m1, m2) ^ inn)
        # else: drop
    return out


def _extend_table_simple(tbl, bit):
    out = []
    for t in tbl:
        t = (t << 1) & M32
        if filter_bit(t) ^ filter_bit(t | 1):
            out.append(t | (filter_bit(t) ^ bit))
        elif filter_bit(t) == bit:
            out.append(t)
            out.append(t | 1)
    return out


def _bucket_intersect(odd, even):
    """Group both lists by their top contribution byte; yield (odd_bucket, even_bucket) for the
    buckets present in both (the crapto1 bucket_sort_intersect, as a dict join)."""
    ob, eb = {}, {}
    for x in odd:
        ob.setdefault(x >> 24, []).append(x)
    for x in even:
        eb.setdefault(x >> 24, []).append(x)
    for k, ol in ob.items():
        el = eb.get(k)
        if el:
            yield ol, el


def _recover(odd, oks, even, eks, rem, states, inn):
    if rem == -1:
        for e in even:
            e2 = ((e << 1) ^ _parity(e & LF_POLY_EVEN) ^ (1 if inn & 4 else 0)) & M32
            for o in odd:
                states.append((e2 ^ _parity(o & LF_POLY_ODD), o))  # (odd, even)
        return
    i = 0
    while i < 4:
        old = rem
        rem -= 1
        if old == 0:
            break
        oks >>= 1
        eks >>= 1
        inn >>= 2
        odd = _extend_table(odd, oks & 1, (LF_POLY_EVEN << 1) | 1, LF_POLY_ODD << 1, 0)
        if not odd:
            return
        even = _extend_table(even, eks & 1, LF_POLY_ODD, (LF_POLY_EVEN << 1) | 1, inn & 3)
        if not even:
            return
        i += 1
    for ol, el in _bucket_intersect(odd, even):
        _recover(ol, oks, el, eks, rem, states, inn)


def lfsr_recovery32(ks2, inn):
    """Candidate (odd, even) states that produce the 32 keystream bits ks2 while input `inn` is fed
    (wire/BEBIT order, as crypto1.py's word())."""
    oks = eks = 0
    for i in range(31, -1, -2):
        oks = (oks << 1) | _bebit(ks2, i)
    for i in range(30, -1, -2):
        eks = (eks << 1) | _bebit(ks2, i)
    odd, even = [], []
    for i in range((1 << 20) + 1):
        if filter_bit(i) == (oks & 1):
            odd.append(i)
        if filter_bit(i) == (eks & 1):
            even.append(i)
    for _ in range(4):
        oks >>= 1
        eks >>= 1
        odd = _extend_table_simple(odd, oks & 1)
        even = _extend_table_simple(even, eks & 1)
    inn = (inn >> 16 & 0xFF) | ((inn << 16) & M32) | (inn & 0xFF00)
    states = []
    _recover(odd, oks, even, eks, 11, states, (inn << 1) & M32)
    return states


def lfsr_rollback_bit(s, inn, fb):
    """Roll the (odd, even) state s=[odd, even] back one bit; returns the keystream bit."""
    s[0] &= 0xFFFFFF
    s[0], s[1] = s[1], s[0]
    out = s[1] & 1
    s[1] >>= 1
    out ^= LF_POLY_EVEN & s[1]
    out ^= LF_POLY_ODD & s[0]
    out ^= 1 if inn else 0
    ret = filter_bit(s[0])
    out ^= ret & (1 if fb else 0)
    s[1] |= _parity(out) << 23
    return ret


def lfsr_rollback_word(s, inn, fb):
    ret = 0
    for i in range(31, -1, -1):
        ret |= lfsr_rollback_bit(s, _bebit(inn, i), fb) << (i ^ 24)
    return ret


def crypto1_get_lfsr(odd, even):
    """48-bit key from an (odd, even) state at the key-load position."""
    lfsr = 0
    for i in range(23, -1, -1):
        lfsr = lfsr << 1 | ((odd >> (i ^ 3)) & 1)
        lfsr = lfsr << 1 | ((even >> (i ^ 3)) & 1)
    return lfsr


def recover_keys(uid, nt, ks):
    """Candidate 48-bit keys for a nested nonce: ks = enc_nt ^ nt (32 target-keystream bits)."""
    inn = uid ^ nt
    keys = []
    for odd, even in lfsr_recovery32(ks, inn):
        s = [odd, even]
        lfsr_rollback_word(s, inn, 0)
        keys.append(crypto1_get_lfsr(s[0], s[1]))
    return keys
