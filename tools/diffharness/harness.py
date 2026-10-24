"""Differential harness: run an original TD2EGA function under Unicorn and the matching port C
function (build/td2diff.dll) on the same memory snapshot, and compare what each one leaves behind.

Observable outputs are the registers a function returns in plus every byte of memory it changes,
except the original's own stack frame below the entry SP (the C code keeps its locals elsewhere).
Flags and untouched memory are not compared.

Memory layout matches the port's mem[]: the unpacked load image at segment 1000h with relocations
applied, DGROUP at 278Fh, SS = DS = DGROUP. Addresses wrap at 1 MiB on both sides.
"""
from __future__ import annotations

import ctypes as C
import random
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable

from unicorn import (UC_ARCH_X86, UC_HOOK_INSN, UC_HOOK_INTR, UC_MODE_16, UC_PROT_ALL, Uc, UcError)
from unicorn.x86_const import (UC_X86_INS_IN, UC_X86_INS_OUT, UC_X86_REG_AX, UC_X86_REG_BP, UC_X86_REG_BX,
                               UC_X86_REG_CS, UC_X86_REG_CX, UC_X86_REG_DI, UC_X86_REG_DS, UC_X86_REG_DX,
                               UC_X86_REG_EFLAGS, UC_X86_REG_ES, UC_X86_REG_IP, UC_X86_REG_SI, UC_X86_REG_SP,
                               UC_X86_REG_SS)

ROOT = Path(__file__).resolve().parents[2]
UNPACKED_EXE = ROOT / 'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe'
SYMBOLS_H = ROOT / 'port/td2/td2port/src/symbols.h'
DLL = ROOT / 'build/td2diff.dll'

MEM = 0x100000                 # 1 MiB, the 8086 address space
LOAD_SEG = 0x1000
DGROUP = LOAD_SEG + 0x178F
ASM_SEG = LOAD_SEG + 0x06C9
HEAP_BOTTOM = DGROUP + 0x1000
HEAP_TOP = 0xA000
ENTRY_SP = 0xA000              # SP at the call; below DS_STACK_TOP (A3CEh) and above the game's tables
FRAME = 0x800                  # bytes below the entry SP treated as the callee's private frame
SENTINEL_FAR = (0x0050, 0x0000)  # return address for far calls (linear 500h, unused)
SENTINEL_NEAR_IP = 0xFFFE      # return IP for near calls, in the function's own segment
MAX_INSNS = 50_000_000

REGS = ['ax', 'bx', 'cx', 'dx', 'si', 'di', 'bp', 'sp', 'ds', 'es', 'ss']
UC_REGS = dict(ax=UC_X86_REG_AX, bx=UC_X86_REG_BX, cx=UC_X86_REG_CX, dx=UC_X86_REG_DX, si=UC_X86_REG_SI,
               di=UC_X86_REG_DI, bp=UC_X86_REG_BP, sp=UC_X86_REG_SP, ds=UC_X86_REG_DS, es=UC_X86_REG_ES,
               ss=UC_X86_REG_SS)


def lin(seg: int, off: int) -> int:
    return ((seg << 4) + off) & (MEM - 1)


def parse_addr(text: str) -> tuple[int, int]:
    """'06c9:780e' (file segment) -> (loaded segment, offset)."""
    seg, off = text.split(':')
    return LOAD_SEG + int(seg, 16), int(off, 16)


def load_symbols(path: Path = SYMBOLS_H) -> dict[str, int]:
    """DS_/CS_/FN_ names from the port's symbols.h."""
    syms = {}
    for m in re.finditer(r'^#define\s+((?:DS|CS|FN)_\w+)\s+0x([0-9A-Fa-f]+)u?\b', path.read_text(), re.M):
        syms[m.group(1)] = int(m.group(2), 16)
    return syms


def load_image(path: Path = UNPACKED_EXE) -> bytearray:
    """1 MiB memory with the unpacked TD2EGA image at 1000:0000, relocated, in the state the port's
    mem_load_exe leaves it (copy protection set to its "passed" state)."""
    mz = path.read_bytes()
    if mz[:2] != b'MZ':
        raise ValueError(f'{path} is not an MZ executable')
    nrel, hdr_paras = struct.unpack_from('<HH', mz, 6)
    lfarlc = struct.unpack_from('<H', mz, 0x18)[0]
    image = bytearray(mz[hdr_paras * 16:])
    if len(image) != 0x1FCC0:
        raise ValueError(f'unexpected TD2EGA image size {len(image)}')
    for i in range(nrel):
        off, seg = struct.unpack_from('<HH', mz, lfarlc + 4 * i)
        at = seg * 16 + off
        struct.pack_into('<H', image, at, (struct.unpack_from('<H', image, at)[0] + LOAD_SEG) & 0xFFFF)
    mem = bytearray(MEM)
    mem[LOAD_SEG * 16:LOAD_SEG * 16 + len(image)] = image
    jne = mem[lin(LOAD_SEG + 0x13A8, 0x03D2)]
    for off in (0x424A, 0x4275, 0x42AD):
        mem[lin(ASM_SEG, off)] = jne
    mem[lin(ASM_SEG, 0x1BF7)] = 0xCB
    mem[lin(DGROUP, 0x5656)] = 0
    return mem


@dataclass
class Case:
    """One call: register inputs, stack arguments and the memory snapshot.

    With steps > 1 the function is called that many times in a row. The original and the port each
    carry on from their own memory and registers, and they are compared after every call; the first
    call that differs ends the case. Before each call, between(step, orig_mem, port_mem) can change
    both memories the same way (key presses, say), and entry(step) gives register values that
    replace the original's leftover ones (what interrupted code would leave).

    orig_mem, when set, is the original's own memory: TD2CGA cases run the original in the TD2CGA
    image and the port in its usual one (cga.py), each with the same buffers and arguments."""
    mem: bytearray
    regs: dict[str, int] = field(default_factory=dict)
    args: list[int] = field(default_factory=list)
    label: str = ''
    steps: int = 1
    between: Callable[[int, bytearray, bytearray], None] | None = None
    entry: Callable[[int], dict[str, int]] | None = None
    orig_mem: bytearray | None = None
    orig_regs: dict[str, int] = field(default_factory=dict)   # with orig_mem: the original's own SS, SP, DS...


@dataclass
class Spec:
    """An original function and how to test it. cases(rng, base) yields Case objects; outputs names
    the registers the function returns in ('al' means the low byte of AX only). observe, when set,
    lists the linear (start, length) ranges compared instead of every changed byte, or (original
    start, port start, length) for data the two sides keep at different addresses; cases with
    orig_mem need it, since the rest of their memory differs between the two sides."""
    name: str
    addr: str
    far: bool
    outputs: list[str]
    cases: Callable[[random.Random, bytes], Iterable[Case]]
    note: str = ''
    max_cases: int = 0           # caps the run's case count for slow specs (0 = no cap)
    observe: list[tuple[int, int]] | None = None


@dataclass
class Outcome:
    regs: dict[str, int]
    mem: bytes
    error: str = ''


@dataclass
class Result:
    label: str
    ok: bool
    problems: list[str]
    changed: int                 # bytes the original changed (outside its frame)
    error: str = ''              # harness or port failure, not a behaviour mismatch


def default_regs(rng: random.Random) -> dict[str, int]:
    r = {k: rng.randrange(0x10000) for k in ('ax', 'bx', 'cx', 'dx', 'si', 'di', 'bp')}
    r.update(ds=DGROUP, es=DGROUP, ss=DGROUP, sp=ENTRY_SP)
    return r


def push_call(case: Case, far: bool, cs: int) -> dict[str, int]:
    """Writes the cdecl arguments and the return address below the entry SP; returns the registers
    at the first instruction."""
    regs = dict(case.regs)
    ss, sp = regs['ss'], regs['sp']
    words = ([SENTINEL_FAR[1], SENTINEL_FAR[0]] if far else [SENTINEL_NEAR_IP]) + list(case.args)
    sp = (sp - 2 * len(words)) & 0xFFFF
    for i, w in enumerate(words):
        a = lin(ss, sp + 2 * i)
        case.mem[a] = w & 0xFF
        case.mem[(a + 1) % MEM] = (w >> 8) & 0xFF
    regs['sp'] = sp
    return regs


class Original:
    """The original code under Unicorn, 16-bit real mode, with a 20-bit wrapping address bus."""

    def __init__(self):
        self.uc = Uc(UC_ARCH_X86, UC_MODE_16)
        self.backing = (C.c_uint8 * MEM)()
        ptr = C.addressof(self.backing)
        self.uc.mem_map_ptr(0, MEM, UC_PROT_ALL, ptr)
        self.uc.mem_map_ptr(MEM, MEM, UC_PROT_ALL, ptr)      # FFFF:0010 and up wraps to 0
        self.fault = ''
        self.uc.hook_add(UC_HOOK_INTR, self._on_interrupt)
        self.uc.hook_add(UC_HOOK_INSN, self._on_io, None, 1, 0, UC_X86_INS_IN)
        self.uc.hook_add(UC_HOOK_INSN, self._on_io, None, 1, 0, UC_X86_INS_OUT)

    def _on_interrupt(self, uc, num, _):
        """A software interrupt whose vector points into the game's own code (the keyboard handlers
        it installs) runs that handler, as the CPU would. Anything else (BIOS, DOS) stops the run."""
        b = self.backing
        off, seg = b[num * 4] | b[num * 4 + 1] << 8, b[num * 4 + 2] | b[num * 4 + 3] << 8
        if seg != ASM_SEG:
            self.fault = f'interrupt {num:02X}h'
            uc.emu_stop()
            return
        ss, sp = uc.reg_read(UC_X86_REG_SS), uc.reg_read(UC_X86_REG_SP)
        flags = uc.reg_read(UC_X86_REG_EFLAGS)
        sp = (sp - 6) & 0xFFFF
        for i, w in enumerate((uc.reg_read(UC_X86_REG_IP), uc.reg_read(UC_X86_REG_CS), flags & 0xFFFF)):
            a = lin(ss, sp + 2 * i)
            b[a], b[(a + 1) % MEM] = w & 0xFF, w >> 8
        uc.reg_write(UC_X86_REG_SP, sp)
        uc.reg_write(UC_X86_REG_EFLAGS, flags & ~0x0300)       # IF and TF cleared
        uc.reg_write(UC_X86_REG_CS, seg)
        uc.reg_write(UC_X86_REG_IP, off)

    def _on_io(self, uc, *_):
        self.fault = 'port I/O'
        uc.emu_stop()
        return 0

    def run(self, seg: int, off: int, far: bool, regs: dict[str, int], mem: bytes) -> Outcome:
        C.memmove(self.backing, bytes(mem), MEM)
        for k in REGS:
            self.uc.reg_write(UC_REGS[k], regs[k])
        self.uc.reg_write(UC_X86_REG_CS, seg)
        self.uc.reg_write(UC_X86_REG_EFLAGS, 0x0202)          # IF set, DF clear, as MSC callers leave it
        ret_cs, ret_ip = SENTINEL_FAR if far else (seg, SENTINEL_NEAR_IP)
        self.fault = ''
        error = ''
        try:
            self.uc.emu_start(lin(seg, off), lin(ret_cs, ret_ip), count=MAX_INSNS)
        except UcError as e:
            error = f'cpu fault: {e}'
        except OSError as e:
            # Unicorn itself can crash when wild code rewrites the code it is running (seen when a
            # traffic list count was 0). Report it and start a fresh emulator for the next case.
            out = {k: 0 for k in REGS}
            mem_after = bytes(self.backing)
            self.__init__()
            return Outcome(out, mem_after, f'emulator crashed: {e}')
        cs, ip = self.uc.reg_read(UC_X86_REG_CS), self.uc.reg_read(UC_X86_REG_IP)
        out = {k: self.uc.reg_read(UC_REGS[k]) for k in REGS}
        if not error:
            if self.fault:
                error = f'{self.fault} at {cs:04X}:{ip:04X}'
            elif (cs, ip) != (ret_cs, ret_ip):
                error = f'did not return (stopped at {cs:04X}:{ip:04X})'
        return Outcome(out, bytes(self.backing), error)


class DhRegs(C.Structure):
    _fields_ = [(k, C.c_uint16) for k in REGS]


class Port:
    """The port's C functions in build/td2diff.dll."""

    def __init__(self, path: Path = DLL):
        if not path.exists():
            raise FileNotFoundError(f'{path} missing: run build.ps1')
        self.dll = C.CDLL(str(path))
        self.dll.dh_mem.restype = C.POINTER(C.c_uint8)
        self.dll.dh_mem_size.restype = C.c_uint32
        self.dll.dh_call.argtypes = [C.c_char_p, C.POINTER(DhRegs)]
        self.dll.dh_call.restype = C.c_int
        self.dll.dh_fatal_message.restype = C.c_char_p
        self.dll.dh_load_exe.argtypes = [C.c_char_p, C.c_char_p, C.c_size_t]
        self.dll.dh_load_exe.restype = C.c_bool
        self.dll.dh_name.argtypes = [C.c_int]
        self.dll.dh_name.restype = C.c_char_p
        self.size = self.dll.dh_mem_size()
        self.mem = (C.c_uint8 * self.size).from_address(C.addressof(self.dll.dh_mem().contents))

    def names(self) -> list[str]:
        return [self.dll.dh_name(i).decode() for i in range(self.dll.dh_count())]

    def load_exe(self, path: Path) -> bytes:
        """Runs the port's own loader on a TD2EGA.EXE and returns the first 1 MiB of mem[]."""
        err = C.create_string_buffer(256)
        if not self.dll.dh_load_exe(str(path).encode(), err, len(err)):
            raise RuntimeError(err.value.decode())
        return C.string_at(C.addressof(self.mem), MEM)

    def run(self, name: str, regs: dict[str, int], mem: bytes) -> Outcome:
        C.memmove(self.mem, bytes(mem), MEM)
        C.memset(C.addressof(self.mem) + MEM, 0, self.size - MEM)
        r = DhRegs(**{k: regs[k] for k in REGS})
        rc = self.dll.dh_call(name.encode(), C.byref(r))
        error = ''
        if rc == -1:
            error = f'no adapter named {name}'
        elif rc == 1:
            error = 'port fatal: ' + self.dll.dh_fatal_message().decode(errors='replace')
        elif C.string_at(C.addressof(self.mem) + MEM, self.size - MEM).strip(b'\0'):
            error = 'port wrote above 1 MiB'
        return Outcome({k: getattr(r, k) for k in REGS}, C.string_at(C.addressof(self.mem), MEM), error)


class Harness:
    def __init__(self, port: Port | None = None):
        self.base = bytes(load_image())
        self.original = Original()
        self.port = port or Port()
        self.symbols = load_symbols()
        self._names = {v: k for k, v in self.symbols.items() if k.startswith('DS_')}

    def where(self, a: int) -> str:
        """Readable address: DS:xxxx with the nearest symbol at or below it, else seg-relative."""
        d = a - DGROUP * 16
        if 0 <= d < 0x10000:
            below = [o for o in self._names if o <= d and d - o < 0x100]
            if below:
                o = max(below)
                return f'DS:{d:04X} ({self._names[o]}+{d - o})' if d != o else f'DS:{d:04X} ({self._names[o]})'
            return f'DS:{d:04X}'
        c = a - ASM_SEG * 16
        if 0 <= c < 0x10000:
            return f'CS(06C9):{c:04X}'
        return f'{a >> 4:04X}:{a & 15:04X}'

    def call(self, spec: Spec, case: Case) -> tuple[Outcome, Outcome, dict[str, int]]:
        seg, off = parse_addr(spec.addr)
        regs = push_call(case, spec.far, seg)
        return (self.original.run(seg, off, spec.far, regs, case.mem),
                self.port.run(spec.name, regs, case.mem), regs)

    def compare(self, spec: Spec, case: Case) -> Result:
        if case.orig_mem is not None:
            return self.split(spec, case)
        if case.steps > 1:
            return self.sequence(spec, case)
        orig, port, regs = self.call(spec, case)
        return self._diff(spec, case.label, bytes(case.mem), orig, port, lin(regs['ss'], case.regs['sp']))

    def sequence(self, spec: Spec, case: Case) -> Result:
        seg, _ = parse_addr(spec.addr)
        mems = [bytearray(case.mem), bytearray(case.mem)]
        regs = [dict(case.regs), dict(case.regs)]
        changed = 0
        for step in range(case.steps):
            if case.between:
                case.between(step, mems[0], mems[1])
            if case.entry:
                regs[0].update(case.entry(step))
            calls = [Case(mems[i], dict(regs[i], sp=case.regs['sp'], ss=case.regs['ss'], ds=case.regs['ds'],
                                        es=case.regs['es']), case.args) for i in (0, 1)]
            start = [push_call(c, spec.far, seg) for c in calls]
            before = bytes(mems[0])
            orig = self.original.run(seg, parse_addr(spec.addr)[1], spec.far, start[0], mems[0])
            port = self.port.run(spec.name, start[1], mems[1])
            r = self._diff(spec, case.label, before, orig, port, lin(case.regs['ss'], case.regs['sp']))
            changed += r.changed
            if not r.ok:
                where = f'call {step + 1} of {case.steps}'
                return Result(case.label, False, [f'{where}: {p}' for p in r.problems], changed,
                              r.error and f'{where}: {r.error}')
            mems = [bytearray(orig.mem), bytearray(port.mem)]
            regs = [orig.regs, port.regs]
        return Result(case.label, True, [], changed)

    def split(self, spec: Spec, case: Case) -> Result:
        """One call with separate memories for the original and the port; only spec.observe is compared."""
        seg, off = parse_addr(spec.addr)
        regs = push_call(case, spec.far, seg)
        orig_regs = push_call(Case(case.orig_mem, dict(case.regs, **case.orig_regs), case.args), spec.far, seg)
        before = bytes(case.orig_mem)
        orig = self.original.run(seg, off, spec.far, orig_regs, case.orig_mem)
        port = self.port.run(spec.name, regs, case.mem)
        if orig.error or port.error:
            return Result(case.label, False, [], 0, orig.error and f'original: {orig.error}' or port.error)
        problems = []
        for r in spec.outputs:
            mask, reg = (0xFF, 'ax') if r == 'al' else (0xFFFF, r)
            if orig.regs[reg] & mask != port.regs[reg] & mask:
                problems.append(f'{r.upper()}: original {orig.regs[reg] & mask:04X}, port {port.regs[reg] & mask:04X}')
        changed, diffs = 0, []
        for item in spec.observe or []:
            o_start, p_start, n = item if len(item) == 3 else (item[0], item[0], item[1])
            changed += sum(orig.mem[o_start + i] != before[o_start + i] for i in range(n))
            diffs += [(o_start + i, p_start + i) for i in range(n) if orig.mem[o_start + i] != port.mem[p_start + i]]
        if diffs:
            o, p = diffs[0]
            problems.append(f'{len(diffs)} memory bytes differ, first {self.where(p)}: original '
                            f'{orig.mem[o]:02X}, port {port.mem[p]:02X} (was {before[o]:02X})')
        return Result(case.label, not problems, problems, changed)

    def _diff(self, spec: Spec, label: str, before: bytes, orig: Outcome, port: Outcome, frame_hi: int) -> Result:
        """before is the snapshot with the pushed arguments and return address."""
        if orig.error or port.error:
            return Result(label, False, [], 0, orig.error and f'original: {orig.error}' or port.error)
        problems = []
        for r in spec.outputs:
            mask, reg = (0xFF, 'ax') if r == 'al' else (0xFFFF, r)
            o, p = orig.regs[reg] & mask, port.regs[reg] & mask
            if o != p:
                problems.append(f'{r.upper()}: original {o:04X}, port {p:04X}')
        frame = range(frame_hi - FRAME, frame_hi)
        changed = 0
        diffs = []
        for blk in range(0, MEM, 4096):
            s, o, p = before[blk:blk + 4096], orig.mem[blk:blk + 4096], port.mem[blk:blk + 4096]
            if s == o and s == p:
                continue
            for i in range(4096):
                a = blk + i
                if a in frame:
                    continue
                if o[i] != s[i]:
                    changed += 1
                if o[i] != p[i]:
                    diffs.append(a)
        if diffs:
            first = diffs[0]
            problems.append(f'{len(diffs)} memory bytes differ, first {self.where(first)}: original '
                            f'{orig.mem[first]:02X}, port {port.mem[first]:02X} (was {before[first]:02X})')
        return Result(label, not problems, problems, changed)

    def run(self, spec: Spec, n: int, seed: int) -> list[Result]:
        rng = random.Random(f'{spec.name}/{seed}')
        n = min(n, spec.max_cases or n)
        results = []
        for case in spec.cases(rng, self.base):
            results.append(self.compare(spec, case))
            if len(results) >= n:
                break
        return results
