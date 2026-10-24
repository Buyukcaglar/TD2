"""IFF ILBM pictures (after Rpck unpacking): header, palette and bitplanes.

Usage: python tools/amiga/ilbm.py runs/amiga/pics/title2 out.png   (needs PIL)
"""
import struct
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))
import rpck  # noqa: E402


class Picture:
    def __init__(self):
        self.width = self.height = self.planes = 0
        self.masking = self.compression = 0
        self.transparent = 0
        self.palette = []          # (r, g, b) 0..255
        self.pixels = None         # bytes, one colour index per pixel, or None for a palette-only file
        self.camg = None


def chunks(data, pos, end):
    while pos + 8 <= end:
        cid = data[pos:pos + 4]
        n = struct.unpack_from('>I', data, pos + 4)[0]
        yield cid, data[pos + 8:pos + 8 + n]
        pos += 8 + n + (n & 1)


def byterun1(src, size):
    out = bytearray()
    i = 0
    while len(out) < size and i < len(src):
        n = src[i]
        i += 1
        if n < 128:
            out += src[i:i + n + 1]
            i += n + 1
        elif n > 128:
            out += src[i:i + 1] * (257 - n)
            i += 1
    return bytes(out[:size])


def parse(data):
    data = rpck.read(data)
    if data[:4] != b'FORM' or data[8:12] != b'ILBM':
        raise ValueError('not an ILBM')
    end = 8 + struct.unpack_from('>I', data, 4)[0]
    pic = Picture()
    body = None
    for cid, c in chunks(data, 12, end):
        if cid == b'BMHD':
            (pic.width, pic.height, _, _, pic.planes, pic.masking, pic.compression, _,
             pic.transparent) = struct.unpack_from('>HHhhBBBBH', c)
        elif cid == b'CMAP':
            pic.palette = [tuple(c[i:i + 3]) for i in range(0, len(c) - 2, 3)]
        elif cid == b'CAMG':
            pic.camg = struct.unpack_from('>I', c)[0]
        elif cid == b'BODY':
            body = c
    if body is not None:
        row = ((pic.width + 15) // 16) * 2
        nplanes = pic.planes + (1 if pic.masking == 1 else 0)
        size = row * nplanes * pic.height
        raw = byterun1(body, size) if pic.compression == 1 else body[:size]
        px = bytearray(pic.width * pic.height)
        for y in range(pic.height):
            for p in range(pic.planes):
                line = raw[(y * nplanes + p) * row:(y * nplanes + p + 1) * row]
                bit = 1 << p
                for x in range(pic.width):
                    if line[x >> 3] & (0x80 >> (x & 7)):
                        px[y * pic.width + x] |= bit
        pic.pixels = bytes(px)
    return pic


def to_image(pic, palette=None):
    from PIL import Image
    pal = palette or pic.palette
    img = Image.frombytes('P', (pic.width, pic.height), pic.pixels)
    flat = [v for rgb in pal for v in rgb]
    img.putpalette(flat + [0] * (768 - len(flat)))
    return img


if __name__ == '__main__':
    pic = parse(open(sys.argv[1], 'rb').read())
    print(f'{pic.width}x{pic.height}, {pic.planes} planes, masking {pic.masking}, compression {pic.compression}, '
          f'{len(pic.palette)} colours, CAMG {pic.camg}')
    if len(sys.argv) > 2 and pic.pixels is not None:
        to_image(pic).convert('RGB').resize((pic.width * 2, pic.height * 2)).save(sys.argv[2])
