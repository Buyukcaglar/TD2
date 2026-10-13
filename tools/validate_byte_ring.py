"""Compare recovered C against only the original 29-byte EGA function.

No DOS/game session, interrupts, ports or external resource reads are provided.
All game bytes are read from an admitted private derived image, never fixtures.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
from pathlib import Path
import random
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "analysis/tools/python"))
from unicorn import Uc, UC_ARCH_X86, UC_MODE_16, UC_HOOK_CODE, UC_HOOK_INTR
from unicorn.x86_const import (UC_X86_REG_CS, UC_X86_REG_IP, UC_X86_REG_DS,
                              UC_X86_REG_SS, UC_X86_REG_SP, UC_X86_REG_AX,
                              UC_X86_REG_SI, UC_X86_REG_BX, UC_X86_REG_CX,
                              UC_X86_REG_DX, UC_X86_REG_DI, UC_X86_REG_BP,
                              UC_X86_REG_ES, UC_X86_REG_EFLAGS)

IMAGE_SHA256 = "8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4"
FUNCTION_OFFSET = 0xE49E
FUNCTION_BYTES = 29


class State(ctypes.Structure):
    _fields_ = [("cursor", ctypes.c_uint16), ("bytes", ctypes.c_uint8 * 256)]


class GuardedState(ctypes.Structure):
    _fields_ = [("prefix", ctypes.c_uint8 * 8), ("state", State),
                ("suffix", ctypes.c_uint8 * 8)]


def require(condition: bool, context) -> None:
    # Deliberately not an assert: comparisons must remain active under python -O.
    if not condition:
        raise RuntimeError(f"Differential invariant failed: {context}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    library = args.library.resolve()
    output = args.output.resolve()
    if not library.is_relative_to((ROOT / "analysis").resolve()):
        raise ValueError("Use a private analysis DLL")
    if output.is_relative_to((ROOT / "reference").resolve()) or output.exists():
        raise ValueError("Refusing reference/existing output")
    image = (ROOT / "analysis/derived/td2ega-v1/TD2EGA.image.bin").read_bytes()
    if hashlib.sha256(image).hexdigest() != IMAGE_SHA256:
        raise ValueError("Unadmitted recovered image")
    function = image[FUNCTION_OFFSET:FUNCTION_OFFSET + FUNCTION_BYTES]
    dll = ctypes.CDLL(str(library))
    step = dll.td2ega_byte_ring_step
    step.argtypes = [ctypes.POINTER(State)]
    step.restype = ctypes.c_uint16
    machine = Uc(UC_ARCH_X86, UC_MODE_16)
    machine.mem_map(0, 0x100000)
    cs, ip, ds, ss, sp = 0x1000, 0x0200, 0x3000, 0x5000, 0x8000
    code = cs * 16 + ip
    data = ds * 16 + 0x66E6
    sentinel = code + FUNCTION_BYTES
    machine.mem_write(code, function)
    instructions = {0, 1, 5, 9, 13, 17, 19, 21, 25, 27, 28}
    instruction_count = [0]

    def fetch(uc, address, size, _):
        if address - code not in instructions or address + size > sentinel:
            raise RuntimeError(f"Execution escaped admitted leaf at {address:x}")
        instruction_count[0] += 1

    def interrupt(*_):
        raise RuntimeError("Unexpected interrupt in pure leaf")

    machine.hook_add(UC_HOOK_CODE, fetch)
    machine.hook_add(UC_HOOK_INTR, interrupt)
    # Entire instruction bytes were statically reviewed: no IN/OUT opcodes or calls.
    preserved = {UC_X86_REG_SI: 0xBEEF, UC_X86_REG_BX: 0x1234, UC_X86_REG_CX: 0x2345,
                 UC_X86_REG_DX: 0x3456, UC_X86_REG_DI: 0x4567, UC_X86_REG_BP: 0x5678,
                 UC_X86_REG_ES: 0x6789}
    seed = random.Random(0x544432)
    total = 0

    def compare(cursor, byte, salt):
        nonlocal total
        ring = bytes((i * 37 + salt) & 255 for i in range(256))
        index = (cursor - 1) & 255
        ring = ring[:index] + bytes([byte]) + ring[index + 1:]
        guarded = GuardedState()
        guarded.prefix[:] = [0xA5] * 8
        guarded.suffix[:] = [0xA5] * 8
        guarded.state = State(cursor, (ctypes.c_uint8 * 256).from_buffer_copy(ring))
        state = guarded.state
        before = struct.pack("<H", cursor) + ring
        guard = b"\xA5" * 8
        machine.mem_write(data - 8, guard + before + guard)
        machine.mem_write(ss * 16 + sp, struct.pack("<HH", ip + FUNCTION_BYTES, cs))
        for register, value in preserved.items():
            machine.reg_write(register, value)
        for register, value in [(UC_X86_REG_CS, cs), (UC_X86_REG_IP, ip),
                                (UC_X86_REG_DS, ds), (UC_X86_REG_SS, ss),
                                (UC_X86_REG_SP, sp), (UC_X86_REG_AX, 0xABCD),
                                (UC_X86_REG_EFLAGS, 0x202)]:
            machine.reg_write(register, value)
        machine.emu_start(code, sentinel, count=32)
        expected_memory = bytes(machine.mem_read(data, 258))
        result = step(ctypes.byref(state))
        actual_memory = struct.pack("<H", state.cursor) + bytes(state.bytes)
        require(actual_memory == expected_memory, (cursor, byte, "memory"))
        require(result == machine.reg_read(UC_X86_REG_AX), (cursor, byte, "return AX"))
        require(machine.reg_read(UC_X86_REG_SP) == sp + 4, "guest far-return stack")
        require(machine.reg_read(UC_X86_REG_CS) == cs and machine.reg_read(UC_X86_REG_IP) == ip + FUNCTION_BYTES, "guest return target")
        require(machine.reg_read(UC_X86_REG_DS) == ds and machine.reg_read(UC_X86_REG_SS) == ss, "guest segments")
        require(bytes(machine.mem_read(data - 8, 8)) == guard, "guest prefix guard")
        require(bytes(machine.mem_read(data + 258, 8)) == guard, "guest suffix guard")
        require(bytes(guarded.prefix) == guard and bytes(guarded.suffix) == guard, "native C guards")
        require(all(machine.reg_read(reg) == value for reg, value in preserved.items()), "guest preserved registers")
        total += 1

    # Every ring index paired with every possible source byte, including wrap.
    for index in range(256):
        cursor = (index + 1) & 0xFFFF
        for byte in range(256):
            compare(cursor, byte, index)
    # Every 16-bit cursor, including all high-byte values and zero underflow.
    for cursor in range(65536):
        compare(cursor, (cursor * 73 + 19) & 255, cursor >> 8)
    # Independent varied buffers/bytes and sign-boundary values.
    for _ in range(512):
        compare(seed.randrange(65536), seed.randrange(256), seed.randrange(256))
    record = {"date": "2026-10-13", "function_id": "FN-EGA-000003", "result": "pass",
              "vectors": total, "original_function_instructions_executed": instruction_count[0],
              "image_sha256": IMAGE_SHA256, "function_image_range": [FUNCTION_OFFSET, FUNCTION_OFFSET + FUNCTION_BYTES],
              "function_sha256": hashlib.sha256(function).hexdigest(),
              "library_sha256": hashlib.sha256(library.read_bytes()).hexdigest(),
              "source_sha256": hashlib.sha256((ROOT / "src/recovered/td2ega_byte_ring.c").read_bytes()).hexdigest(),
              "validator_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "coverage": ["all 256 indices x all 256 byte values", "all 65536 cursor values", "512 seeded varied-state vectors"],
              "comparisons": ["native C vs guest: all 258 state bytes and AX result", "native state prefix/suffix guards", "guest contract: preserved registers/segments, far return/stack and adjacent guards"],
              "limits": "Isolated function semantics only. No whole game/DOS/device session, no caller-level meaning, no cycle timing, no core integration; C does not expose CPU flags."}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(record, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
