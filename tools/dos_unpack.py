"""The DOS game's packed files (PES, PCS, DAT and the screens) in plain Python: the Huffman and RLE passes
of unpack_file (06c9:6d50) without the segment arithmetic, and the named-entry archives.

Usage: python tools/dos_unpack.py reference/dos/ROAD.PES   (prints the archive's entry names)
"""
import struct
import sys


def huffman(data, pos):
    lo = struct.unpack_from('<H', data, pos + 1)[0]
    size = lo | data[pos + 3] << 16
    nb = data[pos + 4]
    nlen = nb & 0x7F
    pos += 5
    offs, lims = [], []
    cx = dx = di = 0
    for _ in range(nlen):
        dx <<= 1
        offs.append(cx - dx)
        c = data[pos]
        pos += 1
        dx += c
        cx += c
        if c:
            di = dx
        lims.append(di)
    alpha = data[pos:pos + cx]
    pos += cx
    out = bytearray()
    delta = nb & 0x80
    prev = 0
    bits = nbits = 0
    while len(out) < size:
        code = level = 0
        while True:
            if nbits == 0:
                bits = data[pos]
                pos += 1
                nbits = 8
            code = code << 1 | (bits & 1)
            bits >>= 1
            nbits -= 1
            if code < lims[level]:
                break
            level += 1
        v = alpha[code + offs[level]]
        if delta:
            v = (v + prev) & 0xFF
            prev = v
        out.append(v)
    return bytes(out)


def rle(data, pos):
    count = struct.unpack_from('<I', data, pos + 4)[0]
    ec = data[pos + 8]
    nesc = ec & 0x7F
    escapes = data[pos + 9:pos + 9 + nesc]
    src = data[pos + 9 + nesc:]
    if ec <= 0x80:
        src, count = sequences(src, count, escapes[1])
    tab = {code: i + 1 for i, code in enumerate(escapes)}
    out = bytearray()
    i = 0
    while count > 0:
        b = src[i]
        i += 1
        cl = tab.get(b, 0)
        if cl == 0:
            out.append(b)
            count -= 1
            continue
        if cl == 1:
            n, v = src[i], src[i + 1]
            i += 2
            count -= 3
        elif cl == 3:
            n, v = src[i] | src[i + 1] << 8, src[i + 2]
            i += 3
            count -= 4
        else:
            n, v = cl - 1, src[i]
            i += 1
            count -= 2
        out += bytes([v]) * n
    return bytes(out)


def sequences(src, count, seq):
    """The sequence pass: bytes between two markers, then a count, repeat as a block."""
    out = bytearray()
    i = 0
    while count > 0:
        b = src[i]
        i += 1
        if b != seq:
            out.append(b)
            count -= 1
            continue
        start = len(out)
        while src[i] != seq:
            out.append(src[i])
            i += 1
            count -= 1
        n = src[i + 1]
        i += 2
        body = out[start:]
        out += body * ((n - 1) & 0xFF or 256)
        count -= 3
    return bytes(out), len(out)


def unpack(data):
    passes = 1
    pos = 0
    if data[0] & 0x80:
        passes = data[0] & 0x7F
        pos = 4
    while True:
        t = data[pos]
        if t == 1:
            data = rle(data, pos)
        elif t == 2:
            data = huffman(data, pos)
        else:
            raise ValueError(f'pack type {t}')
        passes -= 1
        if passes <= 0:
            return data
        pos = 0


def entries(arc, big_endian=False):
    """(name, bytes) for each entry of an unpacked archive. The Amiga .shp archives are the same layout,
    big-endian."""
    e = '>' if big_endian else '<'
    n = struct.unpack_from(e + 'H', arc, 4)[0]
    names = [arc[6 + 4 * i:10 + 4 * i].decode('latin-1').rstrip(' \0') for i in range(n)]
    offs = [struct.unpack_from(e + 'I', arc, 6 + 4 * n + 4 * i)[0] for i in range(n)]
    base = 6 + 8 * n
    ends = sorted(set(offs + [len(arc) - base]))
    out = []
    for name, off in zip(names, offs):
        end = next(x for x in ends if x > off) if off < len(arc) - base else off
        out.append((name, arc[base + off:base + end]))
    return out


if __name__ == '__main__':
    arc = unpack(open(sys.argv[1], 'rb').read())
    print(len(arc), 'bytes:', ' '.join(name for name, _ in entries(arc)))
