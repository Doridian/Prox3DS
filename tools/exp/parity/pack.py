def pack(data, flip=()):
    """Bytes + odd parity (parity bit i inverted for i in flip) as a bit stream (raw TX sends each FIFO byte MSB first), padded to bytes."""
    bits = []
    for i, b in enumerate(data):
        bits += [b >> k & 1 for k in range(8)]
        bits.append((bin(b).count("1") + 1) % 2 ^ (i in flip))
    bits += [0] * (-len(bits) % 8)
    return bytes(sum(bits[i + k] << (7 - k) for k in range(8)) for i in range(0, len(bits), 8)), len(bits)
