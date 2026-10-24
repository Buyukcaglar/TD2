"""TD2EGA against TD2CGA, function by function.

    python tools/cga_compare.py                  # summary of every EGA function without an identical twin
    python tools/cga_compare.py 06c9:4674 ...    # side-by-side diff of those functions

Both executables are unpacked from runs/game (tools/exepack.py). Functions come from the Kylofon
indexes (port/td2/port/td2{ega,cga}_functions.json), are paired per segment by aligning size,
instruction count, call count and strings, and the pairs are corrected by the calls they make.

A pair is compared on its disassembly after normalising what a relink moves: branch targets become
instruction labels, calls become the EGA name of the callee, segment constants become EGA segments.
A number that still differs passes only if the CGA value is provably the moved EGA address
(Addresses). What is left is a real difference. The findings are written up in docs/cga.md.
"""
from __future__ import annotations

import csv
import difflib
import json
import re
import sys
from bisect import bisect_right
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
sys.path.insert(0, str(ROOT / 'analysis/tools/python'))

import exepack                                                          # noqa: E402
from capstone import CS_ARCH_X86, CS_MODE_16, Cs                       # noqa: E402

GAME = ROOT / 'runs/game'
INDEX = ROOT / 'port/td2/port'


@dataclass
class Build:
    name: str
    image: bytes
    dgroup: int                  # segment, relative to the image
    funcs: list[dict]            # sorted by linear start
    by_addr: dict[str, dict]
    segs: list[str]

    def ds(self) -> bytes:
        a = self.dgroup * 16
        return self.image[a:a + 0x10000]


def load(name: str) -> Build:
    image, _, _ = exepack.unpack((GAME / f'{name}.EXE').read_bytes())
    idx = json.loads((INDEX / f'{name.lower()}_functions.json').read_text())
    funcs = sorted(idx['functions'], key=lambda f: int(f['image'], 16))
    for f in funcs:
        f['lin'] = int(f['image'], 16)
        f['seg'] = f['start'].split(':')[0]
    # The indexes stop a function where their flow analysis stops (unfollowed jump tables), so compare
    # each one up to the next indexed function of its segment.
    for f, g in zip(funcs, funcs[1:] + [None]):
        f['last_in_seg'] = g is None or g['seg'] != f['seg']
        f['extent'] = f['size'] if f['last_in_seg'] else g['lin'] - f['lin']
    segs = sorted({f['seg'] for f in funcs}, key=lambda s: int(s, 16))
    return Build(name, image, int(idx['dgroup'], 16), funcs, {f['start']: f for f in funcs}, segs)


def signature(f: dict, full: bool = True) -> tuple:
    strings = tuple(sorted(f.get('strings', {}).values())) if isinstance(f.get('strings'), dict) else ()
    base = (len(f['calls']), strings, f['far'], tuple(f.get('ints', [])))
    return (f['size'], f['insns']) + base if full else base


def pair(ega: Build, cga: Build) -> tuple[dict[str, str], dict[str, str]]:
    """EGA start -> CGA start, and the segment map."""
    segmap = dict(zip(ega.segs, cga.segs))
    pairs = {}
    for es, cs in segmap.items():
        a = [f for f in ega.funcs if f['seg'] == es]
        b = [f for f in cga.funcs if f['seg'] == cs]
        sm = difflib.SequenceMatcher(None, [signature(f) for f in a], [signature(f) for f in b], autojunk=False)
        for tag, i1, i2, j1, j2 in sm.get_opcodes():
            if tag == 'equal' or (tag == 'replace' and i2 - i1 == j2 - j1):
                for i, j in zip(range(i1, i2), range(j1, j2)):
                    pairs[a[i]['start']] = b[j]['start']
            elif tag == 'replace':
                # Unequal gap: match on calls / strings / far first, then leftovers by order.
                ga, gb = a[i1:i2], b[j1:j2]
                sub = difflib.SequenceMatcher(None, [signature(f, False) for f in ga],
                                              [signature(f, False) for f in gb], autojunk=False)
                for t2, k1, k2, l1, l2 in sub.get_opcodes():
                    if t2 == 'equal' or (t2 == 'replace' and k2 - k1 == l2 - l1):
                        for k, l in zip(range(k1, k2), range(l1, l2)):
                            pairs[ga[k]['start']] = gb[l]['start']
    return pairs, segmap


def dgroup_map(ega: Build, cga: Build, k: int = 8) -> list[tuple[int, int, int]]:
    """Runs (ega_off, cga_off, length) of identical initialised DGROUP bytes: data that moved between
    the builds, found by content. Anchors are k-byte strings; among several places the one that keeps
    the previous run's shift wins."""
    a = ega.image[ega.dgroup * 16:]
    b = cga.image[cga.dgroup * 16:]
    where: dict[bytes, list[int]] = {}
    for j in range(len(b) - k + 1):
        where.setdefault(b[j:j + k], []).append(j)
    runs, i, delta = [], 0, 0
    while i <= len(a) - k:
        js = where.get(a[i:i + k])
        if not js or len(set(a[i:i + k])) <= 2 or len(js) > 16:   # zeros and fills anchor nowhere
            i += 1
            continue
        j = min(js, key=lambda j: abs((j - i) - delta))
        n = k
        while i + n < len(a) and j + n < len(b) and a[i + n] == b[j + n]:
            n += 1
        runs.append((i, j, n))
        delta = j - i
        i += n
    return runs


class DsTranslator:
    """CGA DGROUP offset -> EGA offset. Initialised data is matched by content; the uninitialised
    data after it (not in the file) keeps its order, so it moves by the difference in initialised size."""
    def __init__(self, runs, ega_init: int, cga_init: int):
        self.runs = sorted((c, e, n) for e, c, n in runs)   # by CGA offset
        self.keys = [r[0] for r in self.runs]
        self.ega_init, self.cga_init = ega_init, cga_init

    def cga_to_ega(self, off: int) -> int | None:
        if off >= self.cga_init:
            return off - self.cga_init + self.ega_init
        i = bisect_right(self.keys, off) - 1
        if 0 <= i < len(self.runs) - 1:
            (c0, e0, n0), (c1, e1, _) = self.runs[i], self.runs[i + 1]
            if c0 + n0 < off < c1 and e0 - c0 == e1 - c1:          # a gap (e.g. a jump table of code
                return off + (e0 - c0)                             # addresses) inside one shifted block
        if i >= 0:
            c, e, n = self.runs[i]
            if c <= off < c + n:
                return e + (off - c)
            if off == c + n:                                   # one past the end of a table
                return e + n
        return None


MD = Cs(CS_ARCH_X86, CS_MODE_16)
HEX = re.compile(r'0x[0-9a-f]+')


def disasm(b: Build, f: dict) -> list:
    code = b.image[f['lin']:f['lin'] + f['extent']]
    seg = int(f['seg'], 16)
    return list(MD.disasm(code, f['lin'] - seg * 16))


def normalise(b: Build, f: dict, names, segmap, raw_calls: bool = False) -> list[str]:
    """Instruction text with relink-dependent values replaced. names: CGA/EGA start -> EGA start;
    raw_calls keeps callees as their own addresses (for pairing by calls)."""
    seg = int(f['seg'], 16)
    insns = disasm(b, f)
    index = {i.address: n for n, i in enumerate(insns)}
    out = []
    for i in insns:
        m, ops = i.mnemonic, i.op_str
        if m.startswith('j') or m in ('call', 'loop', 'loope', 'loopne', 'jcxz') and not ops.startswith(('word', 'dword', 'b', 's', 'd')):
            t = HEX.fullmatch(ops)
            if t:
                tgt = int(ops, 16)
                if m == 'call':
                    key = f"{f['seg']}:{tgt:04x}"
                    ops = f'CALL {key}' if raw_calls else names.get(key, f'near?{tgt:04x}')
                else:
                    if tgt in index:
                        ops = f'L{index[tgt]}'
                    else:                                  # leaves the function: name where it lands
                        lin = seg * 16 + tgt
                        home = [g for g in b.funcs if g['lin'] <= lin < g['lin'] + g['extent']]
                        ops = f"Lx {names.get(home[0]['start'], home[0]['start'])}" if home else f'Lx 0x{tgt:x}'
        elif m in ('lcall', 'ljmp') and re.fullmatch(r'(0x[0-9a-f]+|[0-9]+), (0x[0-9a-f]+|[0-9]+)', ops):
            s, o = [int(x, 0) for x in ops.split(', ')]
            key = f'{s:04x}:{o:04x}'
            ops = f'CALL {key}' if raw_calls else names.get(key, f'far?{s:04x}:{o:04x}')
        elif m in ('mov', 'push', 'cmp', 'add', 'sub') and re.search(r', 0x[0-9a-f]+$', ops):
            head, imm = ops.rsplit(', ', 1)
            v = int(imm, 16)
            if v == b.dgroup:
                ops = f'{head}, DGROUP'
            elif b.name == 'TD2CGA' and v in segmap_c2e(segmap):
                ops = f'{head}, seg_{segmap_c2e(segmap)[v]:04x}'
            elif b.name == 'TD2EGA' and f'{v:04x}' in segmap:
                ops = f'{head}, seg_{v:04x}'
        # [reg - 0x735a] addresses 0x8ca6: write displacements as the unsigned offsets they are.
        ops = re.sub(r' - (0x[0-9a-f]+)\]', lambda mo: f' + 0x{(0x10000 - int(mo.group(1), 16)) & 0xffff:x}]', ops)
        out.append(f'{m} {ops}'.strip())
    return out


def segmap_c2e(segmap) -> dict[int, int]:
    return {int(c, 16): int(e, 16) for e, c in segmap.items()}


class Compare:
    def __init__(self):
        self.ega, self.cga = load('TD2EGA'), load('TD2CGA')
        self.pairs, self.segmap = pair(self.ega, self.cga)
        self.names_e = {f['start']: f['start'] for f in self.ega.funcs}
        self.names_c = {c: e for e, c in self.pairs.items()}
        self.ds = DsTranslator(dgroup_map(self.ega, self.cga), len(self.ega.image) - self.ega.dgroup * 16,
                               len(self.cga.image) - self.cga.dgroup * 16)
        self.refine_by_calls()
        self.merge_unpaired()
        self.addr = Addresses(self)
        lines = []
        for e_addr in self.pairs:
            ea, ca = self.norm_pair(e_addr)
            sm = difflib.SequenceMatcher(None, [shape(x) for x in ea], [shape(x) for x in ca], autojunk=False)
            for tag, i1, i2, j1, j2 in sm.get_opcodes():
                if tag == 'equal':
                    lines += [(LABEL.sub('L', ea[i]), LABEL.sub('L', ca[j]))
                              for i, j in zip(range(i1, i2), range(j1, j2)) if ea[i] != ca[j]]
        self.addr.learn(lines)

    def merge_unpaired(self):
        """An index can split one function in two (06c9:1a37 is the tail of EGA draw_front_objects).
        A function without a twin that directly follows a paired one in the same segment is taken as
        that function's tail."""
        for b, paired in ((self.ega, set(self.pairs)), (self.cga, set(self.pairs.values()))):
            for f, g in zip(b.funcs, b.funcs[1:]):
                if g['start'] not in paired and g['seg'] == f['seg'] and f['lin'] + f['extent'] == g['lin']:
                    g['tail_of'] = f.get('tail_of', f['start'])
                    b.by_addr[g['tail_of']]['extent'] += g['extent']

    def refine_by_calls(self, rounds: int = 3):
        """Calls at the same place in two paired functions name twins: pair callees by majority vote."""
        from collections import Counter, defaultdict
        for _ in range(rounds):
            votes = defaultdict(Counter)
            for e_addr, c_addr in list(self.pairs.items()):
                ea = normalise(self.ega, self.ega.by_addr[e_addr], {}, self.segmap, raw_calls=True)
                ca = normalise(self.cga, self.cga.by_addr[c_addr], {}, self.segmap, raw_calls=True)
                sm = difflib.SequenceMatcher(None, [shape(x) for x in ea], [shape(x) for x in ca], autojunk=False)
                for tag, i1, i2, j1, j2 in sm.get_opcodes():
                    if tag == 'equal' or (tag == 'replace' and i2 - i1 == j2 - j1):
                        for i, j in zip(range(i1, i2), range(j1, j2)):
                            if ea[i].startswith(('lcall CALL', 'call CALL')) and ca[j].startswith(('lcall CALL', 'call CALL')):
                                votes[ea[i].split('CALL ')[1]][ca[j].split('CALL ')[1]] += 1
            changed = False
            taken = {}
            for e_addr, cnt in votes.items():
                c_addr, n = cnt.most_common(1)[0]
                if e_addr in self.ega.by_addr and c_addr in self.cga.by_addr and self.pairs.get(e_addr) != c_addr:
                    if n >= 2 or e_addr not in self.pairs:
                        taken[e_addr] = c_addr
            if taken:
                used = set(taken.values())
                for e_addr, c_addr in list(self.pairs.items()):
                    if c_addr in used and taken.get(e_addr) != c_addr:
                        del self.pairs[e_addr]
                self.pairs.update(taken)
                changed = True
            self.names_c = {c: e for e, c in self.pairs.items()}
            if not changed:
                break

    def norm_pair(self, e_addr: str):
        c_addr = self.pairs.get(e_addr)
        if c_addr is None:
            return None, None
        ef, cf = dict(self.ega.by_addr[e_addr]), dict(self.cga.by_addr[c_addr])
        # A function the index cut short (no return at its end) gets its twin's length.
        for f, g, b in ((ef, cf, self.ega), (cf, ef, self.cga)):
            last = disasm(b, f)[-1:]
            if g['extent'] > f['extent'] and last and (f['last_in_seg'] or last[0].mnemonic not in ('ret', 'retf', 'jmp', 'iret')):
                f['extent'] = g['extent']
        ea = normalise(self.ega, ef, self.names_e, self.segmap)
        ca = normalise(self.cga, cf, self.names_c, self.segmap)
        return ea, ca


class Addresses:
    """Decides whether a CGA number is the relinked counterpart of an EGA number: a DGROUP address
    that moved with its data, or a code address at the same place inside the paired function."""
    def __init__(self, cmp: 'Compare'):
        self.c = cmp
        self.ds = cmp.ds
        self.ega_ds, self.cga_ds = cmp.ega.ds(), cmp.cga.ds()
        self.cga_funcs = cmp.cga.funcs
        self.back = {c: e for e, c in cmp.pairs.items()}
        self.asm_c = int(cmp.segmap['06c9'], 16)
        self.learned: dict[int, int] = {}

    def data(self, c: int, e: int) -> bool:
        ds = self.ds
        if ds.cga_to_ega(c) == e:
            return True
        if c >= ds.cga_init:
            return False
        # Between two runs with different shifts: either shift, if both builds hold the same word there.
        i = bisect_right(ds.keys, c) - 1
        for k in (i, i + 1):
            if 0 <= k < len(ds.runs):
                rc, re_, _ = ds.runs[k]
                if e - c == re_ - rc and self.ega_ds[e:e + 2] == self.cga_ds[c:c + 2]:
                    return True
        return False

    def code(self, c: int, e: int) -> bool:
        lin = self.asm_c * 16 + c
        fs = [f for f in self.cga_funcs if f['lin'] <= lin < f['lin'] + f['extent']]
        if not fs:
            return False
        ce = self.back.get(fs[0]['start'])
        if ce is None:
            return False
        es, eo = [int(x, 16) for x in ce.split(':')]
        return (es * 16 + eo) + (lin - fs[0]['lin']) - 0x6c9 * 16 == e

    def table(self, c: int, e: int) -> bool:
        """A table of near code addresses (jump table): its first two entries point to the same
        places in paired functions."""
        if not (0 <= c < len(self.cga_ds) - 4 and 0 <= e < len(self.ega_ds) - 4):
            return False
        cw = [int.from_bytes(self.cga_ds[c + k:c + k + 2], 'little') for k in (0, 2)]
        ew = [int.from_bytes(self.ega_ds[e + k:e + k + 2], 'little') for k in (0, 2)]
        return all(self.code(a, b) for a, b in zip(cw, ew))

    # The graphics library's target state in its code segment: the live descriptor copy and the
    # screen descriptor (26 words; same layout in both, found from gfx_select_target and select_screen).
    GFX_STATE_EGA, GFX_STATE_CGA, GFX_STATE_LEN = 0xAF3A, 0x913E, 0x34

    def gfx_state(self, c: int, e: int) -> bool:
        k = c - self.GFX_STATE_CGA
        return 0 <= k < self.GFX_STATE_LEN and e == self.GFX_STATE_EGA + k

    def same(self, c: int, e: int) -> bool:
        return (c == e or self.data(c, e) or self.code(c, e) or self.learned.get(c) == e
                or self.table(c, e) or self.gfx_state(c, e))

    def learn(self, pairs_of_lines):
        """DGROUP addresses whose data cannot anchor (tables the game fills at run time) are learned
        from the code: CGA value c stands for EGA value e when c always meets e, and another address
        at least 4 bytes away within 0x40 shows the same shift. One coincidence cannot pass."""
        from collections import defaultdict
        seen = defaultdict(set)
        for e_line, c_line in pairs_of_lines:
            for a, b in zip(HEX.findall(e_line), HEX.findall(c_line)):
                a, b = int(a, 16), int(b, 16)
                if a != b and 0x100 <= b < self.ds.cga_init and not self.data(b, a) and not self.code(b, a):
                    seen[b].add(a)
        unique = {c: next(iter(es)) for c, es in seen.items() if len(es) == 1}
        self.learned = {}
        for c, e in unique.items():
            d = e - c
            if any(abs(c2 - c) >= 4 and abs(c2 - c) <= 0x40 and e2 - c2 == d for c2, e2 in unique.items()):
                self.learned[c] = e


def names_csv() -> dict[str, tuple[str, str]]:
    out = {}
    for r in csv.DictReader(open(INDEX / 'symbols.csv')):
        if r['kind'] == 'func':
            out[r['address'].lower()] = (r['name'], r['owner'])
    return out


LABEL = re.compile(r'\bL(\d+)\b')


def shape(line: str) -> str:
    return LABEL.sub('L#', HEX.sub('#', line))


def same_line(e: str, c: str, addr: 'Addresses', lines: dict[int, int]) -> bool:
    """Equal, or equal except numbers where the CGA value is the moved address of the EGA one and
    branch targets that are aligned instructions (lines: EGA instruction -> CGA instruction)."""
    if shape(e) != shape(c):
        return False
    el, cl = LABEL.findall(e), LABEL.findall(c)
    if any(lines.get(int(a)) != int(b) for a, b in zip(el, cl)):
        return False
    e, c = LABEL.sub('L', e), LABEL.sub('L', c)
    if e == c:
        return True
    et, ct = HEX.findall(e), HEX.findall(c)
    if len(et) != len(ct):
        return False
    return all(addr.same(int(b, 16), int(a, 16)) for a, b in zip(et, ct))


def classify(ea: list[str], ca: list[str], ds: 'Addresses') -> tuple[str, list[str]]:
    """Aligns on instruction shape (numbers blanked), then checks the numbers of aligned lines."""
    sm = difflib.SequenceMatcher(None, [shape(x) for x in ea], [shape(x) for x in ca], autojunk=False)
    lines = {}
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == 'equal' or (tag == 'replace' and i2 - i1 == j2 - j1):
            lines.update(zip(range(i1, i2), range(j1, j2)))
    out = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == 'equal':
            for i, j in zip(range(i1, i2), range(j1, j2)):
                if not same_line(ea[i], ca[j], ds, lines):
                    out += [f'@ EGA line {i + 1}', f'-{ea[i]}', f'+{ca[j]}']
        else:
            out.append(f'@ EGA lines {i1 + 1}-{i2}')
            out += [f'-{x}' for x in ea[i1:i2]] + [f'+{x}' for x in ca[j1:j2]]
    if not out:
        return 'same after relink', []
    return f'{sum(d.startswith("-") for d in out)} EGA / {sum(d.startswith("+") for d in out)} CGA lines differ', out


def main(argv: list[str]) -> int:
    c = Compare()
    names = names_csv()
    if argv:
        for a in argv:
            ea, ca = c.norm_pair(a.lower())
            nm = names.get(a.lower(), ('?', '?'))[0]
            if ea is None:
                print(f'{a} {nm}: no CGA twin')
                continue
            kind, diff = classify(ea, ca, c.addr)
            print(f'=== {a} {nm} -> {c.pairs[a.lower()]}: {kind}')
            print('\n'.join(diff))
        return 0
    for f in c.ega.funcs:
        cf = c.pairs.get(f['start'])
        nm, owner = names.get(f['start'], ('?', '?'))
        if cf is None:
            what = f"tail of {f['tail_of']}" if 'tail_of' in f else 'no CGA twin'
            print(f"{f['start']} {nm:28} {owner:12} {what}")
            continue
        g = c.cga.by_addr[cf]
        if signature(f) == signature(g):
            continue
        ea, ca = c.norm_pair(f['start'])
        kind, _ = classify(ea, ca, c.addr)
        print(f"{f['start']} {nm:28} {owner:12} -> {cf}  size {f['size']}/{g['size']}  {kind}")
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
