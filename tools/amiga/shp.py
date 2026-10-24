"""The Amiga sprite archives (.shp): the DOS archive layout, big-endian, with planar sprites.

Each sprite is a 20-byte header and its bitplanes:
  +0  width in bytes        +2  height
  +4  hot spot x, y (signed) +8  position x, y (signed)
  +12, +13 planes set to one wherever the sprite is drawn (bit n = plane n); the fuel gauge's +13 = 10h
          gives exactly the dashboard picture's colours. Why there are two bytes is still open.
  +14 the planes stored, one bit each, in order, up to six bytes, ended by 0
  +20 the stored planes, each width x height bytes

Usage: python tools/amiga/shp.py runs/amiga/cars/f40dash.shp out.png [palette ILBM]   (needs PIL)
"""
import os
import struct
import sys

sys.path[:0] = [os.path.dirname(__file__), os.path.join(os.path.dirname(__file__), '..')]
import dos_unpack  # noqa: E402
import rpck  # noqa: E402


INTERLEAVED = False   # stored planes follow each other (checked: interleaved rows scramble the shapes)


class Sprite:
    def __init__(self, name, data):
        self.name = name
        (self.wbytes, self.height, self.hot_x, self.hot_y, self.x, self.y) = struct.unpack_from('>HHhhhh', data)
        self.ones, self.flags = data[12], data[13]
        self.planes = []
        for b in data[14:20]:
            if not b:
                break
            self.planes.append(b)
        self.width = self.wbytes * 8
        n = self.wbytes * self.height
        self.size = 20 + n * len(self.planes)
        pix = bytearray(self.width * self.height)
        cover = bytearray(self.width * self.height)
        np_ = len(self.planes)
        for k, bit in enumerate(self.planes):
            for i in range(n):
                y, xb = divmod(i, self.wbytes)
                byte = data[20 + (y * np_ + k) * self.wbytes + xb] if INTERLEAVED else data[20 + k * n + i]
                if byte:
                    base = y * self.width + xb * 8
                    for b in range(8):
                        if byte & (0x80 >> b):
                            pix[base + b] |= bit
                            cover[base + b] = 1
        for i in range(len(pix)):
            if cover[i]:
                pix[i] |= self.ones | self.flags
        self.pixels = bytes(pix)
        self.mask = bytes(cover)    # drawn where any stored plane is set (the blitter's cookie)


def read(path_or_bytes):
    data = path_or_bytes if isinstance(path_or_bytes, bytes) else open(path_or_bytes, 'rb').read()
    arc = rpck.read(data)
    return [Sprite(name, body) for name, body in dos_unpack.entries(arc, big_endian=True)]


def sheet(sprites, palette, columns=6):
    from PIL import Image, ImageDraw
    cw = max(s.width for s in sprites) + 8
    ch = max(s.height for s in sprites) + 18
    rows = (len(sprites) + columns - 1) // columns
    img = Image.new('RGB', (cw * columns, ch * rows), (40, 40, 40))
    draw = ImageDraw.Draw(img)
    for i, s in enumerate(sprites):
        ox, oy = (i % columns) * cw + 4, (i // columns) * ch + 14
        draw.text((ox, oy - 12), f'{s.name} {s.width}x{s.height}', fill=(255, 255, 0))
        for y in range(s.height):
            for x in range(s.width):
                j = y * s.width + x
                if s.mask[j]:
                    img.putpixel((ox + x, oy + y), palette[s.pixels[j]])
    return img


if __name__ == '__main__':
    sprites = read(sys.argv[1])
    for s in sprites:
        print(f'{s.name:5} {s.width:3}x{s.height:<3} hot {s.hot_x:4},{s.hot_y:<4} at {s.x:4},{s.y:<4} '
              f'ones {s.ones:02x} flags {s.flags:02x} planes {[f"{p:02x}" for p in s.planes]}')
    if len(sys.argv) > 2:
        import ilbm
        pal = ilbm.parse(open(sys.argv[3], 'rb').read()).palette if len(sys.argv) > 3 else \
            [(i * 8, i * 8, i * 8) for i in range(32)]
        sheet(sprites, pal).save(sys.argv[2])
