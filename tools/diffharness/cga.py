"""TD2CGA's graphics library against the port's CGA backend (gfx_cga*.c through the gfx.c front).

The original runs in the TD2CGA image (DGROUP 251Dh, library at 06CFh) and the port in its usual
TD2EGA one, so the two sides keep their state at different addresses: the current target's
descriptor is at CS:913Eh in TD2CGA and CS:AF3Ah in TD2EGA, and the buffer's row table goes at the
start of each side's row-table pool (CS:93D6h and CS:B26Bh). Each case writes the same target
buffer (segment 8000h, a 16-byte header, then linear rows) and sprite (segment 7000h) into both
memories, with the descriptor and row table in each side's own place, and compares the buffer and
sprite bytes afterwards. Cases that use the screen also write the same video memory at B800h and
the interleaved screen descriptor.
"""
from __future__ import annotations

import random
import struct

from .harness import ASM_SEG, DGROUP, LOAD_SEG, MEM, Case, Spec, default_regs, lin

CGA_CS = LOAD_SEG + 0x06CF
CGA_DGROUP = LOAD_SEG + 0x151D
BUF, SPR = 0x8000, 0x7000
SCREEN = 0xB800
STACK_SEG = 0x9000
CGA_ENTRY_SP = 0x9E00            # inside TD2CGA's stack (its top is 160h below TD2EGA's A3CEh)
OBSERVE = [(lin(BUF, 0), 0x10000), (lin(SPR, 0), 0x1000)]
OBSERVE_SCREEN = OBSERVE + [(lin(SCREEN, 0), 0x4000)]

# (code segment, current descriptor, screen descriptor, start of the row-table pool) per side
LAYOUT = {'port': (ASM_SEG, 0xAF3A, 0xAF54, 0xB26B), 'orig': (CGA_CS, 0x913E, 0x9158, 0x93D6)}

_image: list[bytes] = []


def cga_image() -> bytes:
    """1 MiB with the unpacked TD2CGA image at 1000:0000, relocated."""
    if not _image:
        import exepack
        from .cases import game_dir
        image, relocations, _ = exepack.unpack((game_dir() / 'TD2CGA.EXE').read_bytes())
        mem = bytearray(MEM)
        mem[LOAD_SEG * 16:LOAD_SEG * 16 + len(image)] = image
        for r in relocations:
            at = LOAD_SEG * 16 + r['image_relative']
            struct.pack_into('<H', mem, at, (struct.unpack_from('<H', mem, at)[0] + LOAD_SEG) & 0xFFFF)
        _image.append(bytes(mem))
    return _image[0]


def put16(mem: bytearray, seg: int, off: int, v: int):
    a = lin(seg, off)
    mem[a], mem[a + 1] = v & 0xFF, (v >> 8) & 0xFF


class Scene:
    """One target buffer and one sprite, written identically into both memories."""

    def __init__(self, rng: random.Random, w: int, h: int, clip: tuple[int, int, int, int]):
        self.w, self.h, self.clip = w, h, clip
        self.pixels = bytes(rng.randrange(256) for _ in range(w * h))
        self.sprite = b''
        self.screen = b''

    def set_screen(self, rng: random.Random):
        """Random video memory, and the interleaved screen descriptor in both layouts."""
        self.screen = rng.randbytes(0x4000)

    def set_sprite(self, rng: random.Random, sw: int, sh: int, hot: tuple[int, int], own: tuple[int, int]):
        hdr = struct.pack('<6H4x', sw, sh, hot[0] & 0xFFFF, hot[1] & 0xFFFF, own[0] & 0xFFFF, own[1] & 0xFFFF)
        self.sprite = hdr + bytes(rng.randrange(256) for _ in range(sw * sh))

    def write(self, mem: bytearray, side: str):
        cs, cur, screen, rows = LAYOUT[side]
        base = lin(BUF, 0)
        mem[base:base + 0x10] = struct.pack('<2H12x', self.w, self.h)
        mem[base + 0x10:base + 0x10 + len(self.pixels)] = self.pixels
        x0, x1, y0, y1 = self.clip
        desc = [0, BUF, 0, 0, 0, rows, x0, x1, y0, y1, self.w, 0, self.w * 4]
        for i, v in enumerate(desc):
            put16(mem, cs, cur + 2 * i, v)
        for y in range(self.h):
            put16(mem, cs, rows + 2 * y, 0x10 + y * self.w)
        s = lin(SPR, 0)
        mem[s:s + len(self.sprite)] = self.sprite
        if self.screen:
            v = lin(SCREEN, 0)
            mem[v:v + 0x4000] = self.screen
            srows = screen + 0x1A                  # the screen's row table follows its descriptor
            for i, val in enumerate([0, SCREEN, 0, 0, 0, srows, 0, 80, 0, 200, 80, 0, 320]):
                put16(mem, cs, screen + 2 * i, val)
            for y in range(200):
                put16(mem, cs, srows + 2 * y, (y & 1) * 0x2000 + (y >> 1) * 80)

    def case(self, rng: random.Random, base: bytes, args: list[int], label: str, **regs_in: int) -> Case:
        port, orig = bytearray(base), bytearray(cga_image())
        self.write(port, 'port')
        self.write(orig, 'orig')
        regs = default_regs(rng)
        regs.update(ds=CGA_DGROUP, es=CGA_DGROUP, ss=STACK_SEG, sp=0xF000)
        regs.update(regs_in)
        # The original runs with SS = DS, as in the game (the scene routines index tables with BP);
        # the port's adapters read their arguments from a stack clear of the TD2EGA image.
        return Case(port, regs, [a & 0xFFFF for a in args], label, orig_mem=orig,
                    orig_regs=dict(ss=CGA_DGROUP, sp=CGA_ENTRY_SP))


def random_clip(rng: random.Random, w: int, h: int) -> tuple[int, int, int, int]:
    if rng.random() < 0.3:
        return 0, w, 0, h
    x0, x1 = sorted(rng.randint(0, w) for _ in range(2))
    y0, y1 = sorted(rng.randint(0, h) for _ in range(2))
    return x0, x1, y0, y1


def blit_cases(entry: str, clipped: bool):
    """Sprites of 1..12 bytes by 1..24 rows at every alignment. Clipped blits go anywhere around
    the clip box; unclipped ones stay inside the buffer, with room for the shifted extra byte."""
    def cases(rng: random.Random, base: bytes):
        while True:
            w, h = rng.randint(4, 40), rng.randint(4, 60)
            sw, sh = rng.randint(1, min(12, w - 1)), rng.randint(1, min(24, h))
            sc = Scene(rng, w, h, random_clip(rng, w, h) if clipped else (0, w, 0, h))
            if clipped and rng.random() < 0.75:                      # across the clip box's edges
                x0, x1, y0, y1 = sc.clip
                x, y = rng.randint(x0 * 4 - sw * 4, x1 * 4), rng.randint(y0 - sh, y1)
            elif clipped:
                x, y = rng.randint(-sw * 4 - 8, w * 4 + 8), rng.randint(-sh - 4, h + 4)
            else:
                x, y = rng.randint(0, (w - sw - 1) * 4 + 3), rng.randint(0, h - sh)
            hx, hy = (rng.randint(-8, 8), rng.randint(-4, 4)) if rng.random() < 0.5 else (0, 0)
            if entry == 'hot':
                sc.set_sprite(rng, sw, sh, (hx, hy), (0, 0))
                args = [0, SPR, x + hx, y + hy]
            elif entry == 'raw':
                sc.set_sprite(rng, sw, sh, (hx, hy), (0, 0))
                args = [0, SPR, x, y]
            else:
                sc.set_sprite(rng, sw, sh, (hx, hy), (x, y))
                args = [0, SPR]
            yield sc.case(rng, base, args, f'{w}x{h} buffer, {sw}x{sh} sprite at {x},{y}, clip {sc.clip}')
    return cases


def grab_cases(entry: str):
    """Sprites filled from inside the buffer (the grab does not clip)."""
    def cases(rng: random.Random, base: bytes):
        while True:
            w, h = rng.randint(4, 40), rng.randint(4, 60)
            sw, sh = rng.randint(1, w - 1), rng.randint(1, h)
            sc = Scene(rng, w, h, random_clip(rng, w, h))
            x, y = rng.randint(0, (w - sw) * 4 + 3), rng.randint(0, h - sh)
            if entry == 'hot':
                hx, hy = rng.randint(-8, 8), rng.randint(-4, 4)
                sc.set_sprite(rng, sw, sh, (hx, hy), (0, 0))
                args = [0, SPR, x + hx, y + hy]
            elif entry == 'raw':
                sc.set_sprite(rng, sw, sh, (0, 0), (0, 0))
                args = [0, SPR, x, y]
            else:
                sc.set_sprite(rng, sw, sh, (0, 0), (x, y))
                args = [0, SPR]
            yield sc.case(rng, base, args, f'{w}x{h} buffer, {sw}x{sh} sprite from {x},{y}')
    return cases


def colour(rng: random.Random) -> int:
    return rng.choice([0, 0xFFFF, 0x5555, 0xAAAA, 0x8822, 0x9966, 1, 2, 3, rng.randrange(0x10000)])


def fill_cases(clipped: bool):
    def cases(rng: random.Random, base: bytes):
        while True:
            w, h = rng.randint(2, 40), rng.randint(2, 60)
            sc = Scene(rng, w, h, random_clip(rng, w, h))
            if clipped:
                x, y = rng.randint(-20, w * 4 + 8), rng.randint(-8, h + 8)
                fw, fh = rng.randint(-4, w * 4 + 16), rng.randint(-4, h + 8)
            else:
                x, y = rng.randint(0, w * 4 - 1), rng.randint(0, h - 1)
                fw, fh = rng.randint(1, w * 4 - x), rng.randint(1, h - y)
            c = colour(rng)
            yield sc.case(rng, base, [x, y, fw, fh, c], f'{w}x{h} buffer, {fw}x{fh} at {x},{y}, colour {c:04X}')
    return cases


def clear_cases(rng: random.Random, base: bytes):
    while True:
        w, h = rng.randint(2, 40), rng.randint(2, 60)
        sc = Scene(rng, w, h, random_clip(rng, w, h))
        c = colour(rng)
        yield sc.case(rng, base, [c], f'{w}x{h} buffer, clip {sc.clip}, colour {c:04X}')


def plot_cases(rng: random.Random, base: bytes):
    while True:
        w, h = rng.randint(2, 40), rng.randint(2, 60)
        sc = Scene(rng, w, h, (0, w, 0, h))
        x, y = rng.randint(0, w * 4 - 1), rng.randint(0, h - 1)
        c = rng.choice([0, 1, 2, 3])
        yield sc.case(rng, base, [x, y, c], f'{w}x{h} buffer, pixel {x},{y}, colour {c}')


def line_cases(or_mode: bool):
    """Lines between points inside the buffer: horizontal, vertical and steep or shallow slopes. The
    OR line leaves out steep lines drawn upwards, whose start x the original takes from the stack
    (gfx_cga.c, cga_draw_line); the game only draws straight OR lines."""
    def cases(rng: random.Random, base: bytes):
        while True:
            w, h = rng.randint(2, 40), rng.randint(2, 60)
            sc = Scene(rng, w, h, (0, w, 0, h))
            px = lambda: rng.randint(0, w * 4 - 1)                   # noqa: E731
            py = lambda: rng.randint(0, h - 1)                       # noqa: E731
            x0, y0 = px(), py()
            kind = rng.randrange(4)
            x1, y1 = (px(), y0) if kind == 0 else (x0, py()) if kind == 1 else (px(), py())
            if or_mode and x0 != x1 and abs(x1 - x0) < abs(y1 - y0) and y1 < y0:
                continue
            c = colour(rng)
            yield sc.case(rng, base, [x0, y0, x1, y1, c], f'{w}x{h} buffer, {x0},{y0} to {x1},{y1}, colour {c:04X}')
    return cases


def clear_screen_cases(rng: random.Random, base: bytes):
    while True:
        sc = Scene(rng, 4, 4, (0, 4, 0, 4))
        sc.set_screen(rng)
        c = colour(rng)
        yield sc.case(rng, base, [c], f'colour {c:04X}')


def dissolve_cases(rng: random.Random, base: bytes):
    """A sprite revealed at its own position in one phase; rows are visited 12 apart."""
    while True:
        w, h = rng.randint(2, 40), rng.randint(2, 80)
        sw, sh = rng.randint(1, w - 1), rng.randint(1, h)
        sc = Scene(rng, w, h, (0, w, 0, h))
        x, y = rng.randint(0, (w - sw) * 4 + 3), rng.randint(0, h - sh)
        sc.set_sprite(rng, sw, sh, (0, 0), (x, y))
        phase = rng.randrange(256)
        yield sc.case(rng, base, [0, SPR, phase], f'{w}x{h} buffer, {sw}x{sh} sprite at {x},{y}, phase {phase}')


def grab_screen_cases(rng: random.Random, base: bytes):
    """A block of the screen (interleaved rows) copied into the buffer."""
    while True:
        w, h = rng.randint(2, 40), rng.randint(2, 60)
        sc = Scene(rng, w, h, (0, w, 0, h))
        sc.set_screen(rng)
        n = rng.randint(1, w)
        rows = rng.randint(1, h)
        sx, sy = rng.randint(0, (80 - n) * 4 + 3), rng.randint(0, 200 - rows)
        dx, dy = rng.randint(0, (w - n) * 4 + 3), rng.randint(0, h - rows)
        yield sc.case(rng, base, [sx, sy, dx, dy, n * 4, rows],
                      f'{n * 4}x{rows} from {sx},{sy} to {dx},{dy} of a {w}x{h} buffer')


# The text state block (11 words: fg, bg, margin x, x, y, -, glyph height, font far pointer,
# advance x, advance y, enabled) in each side's DGROUP; TD2CGA's sits 160h lower.
TEXT = {'port': (DGROUP, 0x6820), 'orig': (CGA_DGROUP, 0x66C0)}
FONT, STRING = 0xF000, 0xF800        # free DGROUP offsets in both images


def text_cases(rng: random.Random, base: bytes):
    """A string with glyphs, blanks and line breaks in a random font, laid out inside the buffer."""
    while True:
        w, h = rng.randint(4, 40), rng.randint(8, 60)
        gh, adv_x = rng.randint(1, 8), rng.choice([4, 8, 12])
        adv_y = gh + rng.randint(0, 2)
        chars = [rng.choice([0x41, 0x42, 0x43, 0x20, 0x0D, 0x0A, 0x7E]) for _ in range(rng.randint(1, 12))]
        x0, y0 = rng.randint(0, w * 4 - 8), rng.randint(0, h - gh)
        margin = rng.randint(0, w * 4 - 8)
        glyphs = {c: rng.random() < 0.8 for c in set(chars) if c not in (0x0D, 0x0A)}
        x, y, fits = x0, y0, True
        for c in chars:
            if glyphs.get(c):
                fits &= (x >> 2) + 2 <= w and y + gh <= h
                x += adv_x
            elif c in (0x0D, 0x0A):
                x, y = margin, y + adv_y
        if not fits:
            continue
        sc = Scene(rng, w, h, (0, w, 0, h))
        fg, bg = rng.randrange(4), rng.randrange(4)
        font = bytearray(512)
        bitmaps = bytearray()
        for c, has in glyphs.items():
            if has:
                struct.pack_into('<H', font, 2 * c, FONT + 512 + len(bitmaps))
                bitmaps += rng.randbytes(gh)
        text = bytes(chars) + b'\0'
        case = sc.case(rng, base, [STRING, x0, y0], f'{w}x{h} buffer, {bytes(chars)!r} at {x0},{y0}, '
                                                    f'glyphs {gh} high, colours {fg}/{bg}')
        for mem, side in ((case.mem, 'port'), (case.orig_mem, 'orig')):
            ds, block = TEXT[side]
            for i, v in enumerate([fg, bg, margin, 0, 0, 0, gh, FONT, ds, adv_x, adv_y, 1]):
                put16(mem, ds, block + 2 * i, v)
            a = lin(ds, FONT)
            mem[a:a + 512 + len(bitmaps)] = bytes(font) + bytes(bitmaps)
            a = lin(ds, STRING)
            mem[a:a + len(text)] = text
        yield case


# Ground span state: (TD2CGA offset, port offset) of the pixel-in-byte and span x words, and the
# view width and row-done jump target the span fill reads.
SPAN_STATE = (0x09BA, 0x09BE)
VIEW_WIDTH = {'port': 0x5348, 'orig': 0x5244}
ROW_DONE = 0x0702


def span_cases(rng: random.Random, base: bytes):
    """One ground span from the current x to a random end, on a random row; ends at the view width
    take the row-done exit (jmp [0702h], pointed back at the call's return)."""
    while True:
        w, h = rng.randint(2, 80), rng.randint(1, 8)
        sc = Scene(rng, w, h, (0, w, 0, h))
        y = rng.randrange(h)
        x = rng.randint(0, w * 4 - 1)
        bit = x & 3 if rng.random() < 0.8 else rng.randrange(4)
        end = rng.choice([x, w * 4, rng.randint(x, w * 4)])
        view = w * 4 if rng.random() < 0.7 else rng.randint(1, w * 4)
        pat, si = rng.randrange(0x10000), rng.randrange(0x10000)
        di = 0x10 + y * w + (x >> 2)
        case = sc.case(rng, base, [], f'{w}-byte row {y}, span {x}..{end} (pixel {bit}), view {view}, '
                                      f'pattern {pat:04X}', ax=end, bx=pat, si=si, di=di, es=BUF)
        for mem, side in ((case.mem, 'port'), (case.orig_mem, 'orig')):
            ds = DGROUP if side == 'port' else CGA_DGROUP
            span = SPAN_STATE[side == 'port']
            put16(mem, ds, span, bit)
            put16(mem, ds, span + 2, x)
            put16(mem, ds, VIEW_WIDTH[side], view)
        put16(case.orig_mem, CGA_DGROUP, ROW_DONE, 0xFFFE)
        yield case


def hline_cases(rng: random.Random, base: bytes):
    """The scene's unclipped hline on a random row, including empty and single-byte spans."""
    while True:
        w, h = rng.randint(2, 80), rng.randint(1, 8)
        sc = Scene(rng, w, h, (0, w, 0, h))
        y = rng.randrange(h)
        x0 = rng.randint(0, w * 4 - 1)
        x1 = rng.choice([x0, x0 + 1, rng.randint(x0, min(w * 4, (x0 | 3) + 1)), rng.randint(0, w * 4)])
        pat = rng.randrange(0x10000)
        yield sc.case(rng, base, [], f'{w}-byte row {y}, {x0}..{x1}, pattern {pat:04X}',
                      ax=x1, dx=x0, bx=pat, si=2 * y, di=0x10 + y * w, es=BUF)


def _blit_specs():
    specs = []
    entries = {  # name: (hot, raw, own) TD2CGA addresses
        'blit_copy_clip': ('888a', '88ae', '88cc'), 'blit_or_clip': ('8cfa', '8d1e', '8d3c'),
        'blit_and_clip': ('7c9e', '7cc2', '7ce0'), 'blit_xor_clip': ('9be2', '9c06', '9c24'),
        'blit_copy': ('8adc', '8b00', '8b1e'), 'blit_or': ('8f36', '8f5a', '8f78'),
        'blit_and': ('7ee4', '7f08', '7f26'), 'blit_xor': ('9e1e', '9e42', '9e60'),
    }
    for name, addrs in entries.items():
        for entry, addr in zip(('hot', 'raw', 'own'), addrs):
            specs.append(Spec(f'cga_{name}_{entry}', f'06cf:{addr}', True, [],
                              blit_cases(entry, name.endswith('_clip')),
                              'TD2CGA: random buffer, sprite, position and clip', observe=OBSERVE))
    for entry, addr in zip(('hot', 'raw', 'own'), ('908a', '90ae', '90d2')):
        specs.append(Spec(f'cga_grab_into_sprite_{entry}', f'06cf:{addr}', True, [], grab_cases(entry),
                          'TD2CGA: sprite filled from the buffer', observe=OBSERVE))
    return specs


CGA_SPECS = _blit_specs() + [
    Spec('cga_fill_rect', '06cf:8438', True, [], fill_cases(False), 'TD2CGA: rectangle inside the buffer, pattern words',
         observe=OBSERVE),
    Spec('cga_fill_rect_clip', '06cf:83d2', True, [], fill_cases(True), 'TD2CGA: any rectangle against the clip',
         observe=OBSERVE),
    Spec('cga_clear_clip', '06cf:8052', True, [], clear_cases, 'TD2CGA: clip box, pattern words', observe=OBSERVE),
    Spec('cga_plot', '06cf:9ba6', True, [], plot_cases, 'TD2CGA: one pixel, colours 0..3', observe=OBSERVE),
    Spec('cga_draw_line', '06cf:80ae', True, [], line_cases(False), 'TD2CGA: lines inside the buffer',
         observe=OBSERVE),
    Spec('cga_draw_line_or', '06cf:a326', True, [], line_cases(True),
         'TD2CGA: OR lines inside the buffer, except steep ones drawn upwards', observe=OBSERVE),
    Spec('cga_clear_screen', '06cf:8032', True, [], clear_screen_cases, 'TD2CGA: video memory, pattern words',
         observe=OBSERVE_SCREEN),
    Spec('cga_dissolve4', '06cf:86d4', True, [], dissolve_cases, 'TD2CGA: one phase of the 4-step reveal',
         observe=OBSERVE),
    Spec('cga_dissolve8', '06cf:879e', True, [], dissolve_cases, 'TD2CGA: one phase of the 8-step reveal',
         observe=OBSERVE),
    Spec('cga_grab_screen', '06cf:a208', True, [], grab_screen_cases,
         'TD2CGA: interleaved screen rows into the buffer', observe=OBSERVE_SCREEN),
    Spec('cga_draw_text', '06cf:8c2e', True, [], text_cases,
         'TD2CGA: random font, glyphs, blanks and line breaks, colours 0..3', observe=OBSERVE),
    Spec('cga_span_to', '06cf:0c1c', False, ['di'], span_cases,
         'TD2CGA scene: one ground span, odd and even rows, row-done exit; span state compared',
         observe=OBSERVE + [(lin(CGA_DGROUP, SPAN_STATE[0]), lin(DGROUP, SPAN_STATE[1]), 4)]),
    Spec('cga_scene_hline', '06cf:0c8e', False, [], hline_cases,
         'TD2CGA scene: unclipped hline, empty and single-byte spans', observe=OBSERVE),
]
