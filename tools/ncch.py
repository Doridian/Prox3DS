import sys, struct, os

def blz_decompress(data):
    # 3DS "backward LZ" used for ExeFS .code
    buf_top, orig_bottom = struct.unpack_from('<II', data, len(data)-8)
    hdr_len = buf_top >> 24
    enc_len = buf_top & 0xFFFFFF
    out_len = len(data) + orig_bottom
    out = bytearray(out_len)
    out[:len(data)] = data
    src = len(data) - hdr_len
    dst = out_len
    stop = len(data) - enc_len
    while src > stop:
        src -= 1; flags = out[src]
        for _ in range(8):
            if src <= stop: break
            if flags & 0x80:
                src -= 2
                v = out[src] | (out[src+1] << 8)
                disp = (v & 0xFFF) + 3
                n = (v >> 12) + 3
                for _ in range(n):
                    dst -= 1
                    out[dst] = out[dst + disp]
            else:
                src -= 1; dst -= 1
                out[dst] = out[src]
            flags = (flags << 1) & 0xFF
    return bytes(out)

path, outdir = sys.argv[1], sys.argv[2]
os.makedirs(outdir, exist_ok=True)
d = open(path, 'rb').read()
assert d[0x100:0x104] == b'NCCH', 'not NCCH'
flags = d[0x188:0x190]
print('flags', flags.hex(), 'NoCrypto' if flags[7] & 4 else 'ENCRYPTED')
exh_size = struct.unpack_from('<I', d, 0x180)[0]
exh = d[0x200:0x200 + 0x800]
open(f'{outdir}/exheader.bin', 'wb').write(exh)
name = exh[:8].rstrip(b'\0').decode()
compressed = exh[0xD] & 1
text_addr, text_pages, text_size = struct.unpack_from('<III', exh, 0x10)
ro_addr, ro_pages, ro_size = struct.unpack_from('<III', exh, 0x20)
data_addr, data_pages, data_size = struct.unpack_from('<III', exh, 0x30)
bss = struct.unpack_from('<I', exh, 0x3C)[0]
print(f'name={name} compressed={compressed}')
print(f'text {text_addr:#x} size {text_size:#x}; ro {ro_addr:#x} size {ro_size:#x}; data {data_addr:#x} size {data_size:#x}; bss {bss:#x}')
# ARM11 local caps: service access list at exh+0x250, 34 entries * 8 (0x20 in first, rest later)
svcs = []
for i in range(34):
    off = 0x250 + i*8
    s = exh[off:off+8].rstrip(b'\0')
    if s: svcs.append(s.decode(errors='replace'))
print('services:', ', '.join(svcs))
# ARM11 kernel caps at exh+0x370, 28 descriptors
kc = [struct.unpack_from('<I', exh, 0x370 + i*4)[0] for i in range(28)]
print('kernel caps:', ' '.join(f'{x:08x}' for x in kc if x != 0xFFFFFFFF))
exefs_off = struct.unpack_from('<I', d, 0x1A0)[0] * 0x200
ex = d[exefs_off:]
for i in range(10):
    fn, foff, fsz = struct.unpack_from('<8sII', ex, i*16)
    fn = fn.rstrip(b'\0').decode()
    if not fn: continue
    blob = ex[0x200 + foff:0x200 + foff + fsz]
    if fn == '.code' and compressed:
        blob = blz_decompress(blob)
    open(f'{outdir}/{fn.lstrip(".")}.bin', 'wb').write(blob)
    print(f'exefs {fn}: {fsz:#x} -> {len(blob):#x}')
