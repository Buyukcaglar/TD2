"""Independently recover TD2EGA's image by executing its original EXEPACK stub.

This is a CPU-only unpacker verification path, not a DOS emulator. It stops
before the final far jump into the application, permits only known stub fetches,
and denies interrupts and port I/O. It imports no project unpacking decoder.
Original and derived game bytes must remain outside the public source tree.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
from pathlib import Path
import struct
from typing import Callable


EXPECTED_SOURCE_SHA256 = "eb4f8e882fd79e884260b2285f38cc22673d45ddc5f601a5815bcce42d5a7182"
EXPECTED_STUB_SHA256 = "3c2ecf0c7854abfe0390cfa2482fc3941cf255546ce1629132eb62bb08f3d435"
WORKSPACE = Path(__file__).resolve().parents[2]
PRIVATE_ROOT = WORKSPACE / "analysis" / "independent"


class VerificationError(RuntimeError):
    """A verification invariant failed; no successful output may be published."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def is_inside(path: Path, parent: Path) -> bool:
    return path.resolve().is_relative_to(parent.resolve())


def check_paths(source: Path, output: Path) -> None:
    if is_inside(source, WORKSPACE / "reference"):
        raise VerificationError("Use the verified analysis working copy, not reference.")
    if not is_inside(source, WORKSPACE / "analysis" / "inputs" / "dos"):
        raise VerificationError("Source must be under analysis/inputs/dos.")
    if not is_inside(output, PRIVATE_ROOT):
        raise VerificationError("Derived output must stay under analysis/independent.")


def parse_pinned_input(data: bytes) -> dict:
    if sha256(data) != EXPECTED_SOURCE_SHA256:
        raise VerificationError("Source does not match the pinned TD2EGA.EXE hash.")
    h = struct.unpack_from("<14H", data)
    if h[0] != 0x5A4D or h[3] != 0 or h[4] != 0x20:
        raise VerificationError("Unexpected MZ signature, outer relocations, or header size.")
    declared = (h[2] - 1) * 512 + (h[1] or 512)
    if declared != len(data):
        raise VerificationError("MZ declared length differs from the source length.")
    stub_file = h[4] * 16 + h[11] * 16
    metadata = struct.unpack_from("<9H", data, stub_file)
    if h[10] != 0x12 or metadata[8] != 0x4252:
        raise VerificationError("Unexpected EXEPACK entry or signature.")
    if sha256(data[stub_file + 0x12:stub_file + 0x12D]) != EXPECTED_STUB_SHA256:
        raise VerificationError("Original loader instructions differ from the pinned stub.")
    if stub_file + metadata[3] != len(data):
        raise VerificationError("Internal packed tail does not end at EOF.")
    return {
        "header_size": h[4] * 16,
        "outer_cs": h[11], "outer_ip": h[10],
        "outer_ss": h[7], "outer_sp": h[8],
        "stub_file_offset": stub_file,
        "original_ip": metadata[0], "original_cs": metadata[1],
        "original_sp": metadata[4], "original_ss": metadata[5],
        "destination_paragraphs": metadata[6],
        "tail_size": metadata[3],
    }


class ExecutionFence:
    """Fail closed outside admitted code, before any application instruction."""

    def __init__(self, ranges: list[tuple[int, int]], stop_address: int,
                 budget: int, on_instruction: Callable | None = None):
        self.ranges = ranges
        self.stop_address = stop_address
        self.budget = budget
        self.count = 0
        self.stopped_before_transfer = False
        self.current_address: int | None = None
        self.on_instruction = on_instruction

    def code(self, uc, address: int, size: int, _user_data) -> None:
        self.current_address = address
        if address == self.stop_address:
            self.stopped_before_transfer = True
            uc.emu_stop()
            return
        if not any(lo <= address and address + size <= hi for lo, hi in self.ranges):
            raise VerificationError(f"Instruction fetch outside admitted loader at 0x{address:X}.")
        self.count += 1
        if self.count > self.budget:
            raise VerificationError("Loader instruction budget exhausted.")
        instruction = bytes(uc.mem_read(address, size))
        prefixes = {0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65, 0x66, 0x67, 0xF0, 0xF2, 0xF3}
        op_index = 0
        while op_index < len(instruction) and instruction[op_index] in prefixes:
            op_index += 1
        if op_index == len(instruction):
            raise VerificationError("Instruction contains only prefixes.")
        opcode = instruction[op_index]
        if opcode in {0xCC, 0xCD, 0xCE, 0xF1, 0xF4,
                      0xE4, 0xE5, 0xE6, 0xE7, 0xEC, 0xED, 0xEE, 0xEF}:
            raise VerificationError("Interrupt, halt, or port I/O instruction is forbidden.")
        if self.on_instruction is not None:
            self.on_instruction(uc, address, size)

    @staticmethod
    def interrupt(_uc, number: int, _user_data) -> None:
        raise VerificationError(f"Interrupt {number:X} is forbidden.")


def recover_with_original_loader(data: bytes, load_segment: int = 0x1000) -> tuple[bytes, bytes, dict]:
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_16, UC_HOOK_CODE, UC_HOOK_INTR, UC_HOOK_MEM_WRITE
    from unicorn.x86_const import (
        UC_X86_REG_AX, UC_X86_REG_BX, UC_X86_REG_CX, UC_X86_REG_DX,
        UC_X86_REG_SI, UC_X86_REG_DI, UC_X86_REG_CS, UC_X86_REG_IP,
        UC_X86_REG_DS, UC_X86_REG_ES, UC_X86_REG_SS, UC_X86_REG_SP,
        UC_X86_REG_EFLAGS,
    )

    m = parse_pinned_input(data)
    if not 0x1000 <= load_segment <= 0x7000:
        raise VerificationError("Load segment must avoid low-memory wraparound and exceed 64 KiB.")
    load_base = load_segment * 16
    image_size = m["destination_paragraphs"] * 16
    old_stub = load_base + m["outer_cs"] * 16
    new_stub = load_base + image_size
    memory_size = 0x110000
    if new_stub + m["tail_size"] >= memory_size:
        raise VerificationError("Relocated loader exceeds the mapped address space.")
    uc = Uc(UC_ARCH_X86, UC_MODE_16)
    uc.mem_map(0, memory_size)
    uc.mem_write(load_base, data[m["header_size"]:])
    registers = {
        UC_X86_REG_AX: 0, UC_X86_REG_BX: 0, UC_X86_REG_CX: 0, UC_X86_REG_DX: 0,
        UC_X86_REG_SI: 0, UC_X86_REG_DI: 0,
        UC_X86_REG_CS: load_segment + m["outer_cs"], UC_X86_REG_IP: m["outer_ip"],
        UC_X86_REG_DS: load_segment - 0x10, UC_X86_REG_ES: load_segment - 0x10,
        UC_X86_REG_SS: load_segment + m["outer_ss"], UC_X86_REG_SP: m["outer_sp"],
        UC_X86_REG_EFLAGS: 0x202,
    }
    for register, value in registers.items():
        uc.reg_write(register, value)
    snapshots: list[bytes] = []
    relocation_events: list[dict] = []

    def observe_instruction(engine, address: int, _size: int) -> None:
        if address == new_stub + 0x9E:
            if snapshots:
                raise VerificationError("Unexpected second relocation phase.")
            snapshots.append(bytes(engine.mem_read(load_base, image_size)))

    fence = ExecutionFence(
        [(old_stub + 0x12, old_stub + 0x38), (new_stub + 0x38, new_stub + 0x101)],
        new_stub + 0xFE, 2_000_000, observe_instruction,
    )

    def observe_write(engine, _access, address: int, size: int, value: int, _user_data) -> None:
        if fence.current_address in {new_stub + 0xBD, new_stub + 0xD6}:
            if not snapshots or size != 2 or not load_base <= address <= load_base + image_size - 2:
                raise VerificationError("Invalid actual relocation write.")
            before = struct.unpack("<H", bytes(engine.mem_read(address, 2)))[0]
            if value != (before + load_segment) & 0xFFFF:
                raise VerificationError("Relocation write does not add the program load segment.")
            relocation_events.append({
                "image_offset": address - load_base,
                "before": before, "after": value,
                "loader_instruction_offset": fence.current_address - new_stub,
            })

    uc.hook_add(UC_HOOK_CODE, fence.code)
    uc.hook_add(UC_HOOK_INTR, fence.interrupt)
    uc.hook_add(UC_HOOK_MEM_WRITE, observe_write)
    uc.emu_start(old_stub + m["outer_ip"], memory_size - 1, timeout=30_000_000)
    if not fence.stopped_before_transfer or len(snapshots) != 1:
        raise VerificationError(
            "Loader failed to reach the fenced final transfer: "
            f"hooks={fence.count}, last={fence.current_address!r}, snapshots={len(snapshots)}, "
            f"cs:ip={uc.reg_read(UC_X86_REG_CS):04X}:{uc.reg_read(UC_X86_REG_IP):04X}."
        )
    pre_relocation = snapshots[0]
    relocated = bytes(uc.mem_read(load_base, image_size))
    normalized = bytearray(relocated)
    for event in reversed(relocation_events):
        pos = event["image_offset"]
        word = struct.unpack_from("<H", normalized, pos)[0]
        struct.pack_into("<H", normalized, pos, (word - load_segment) & 0xFFFF)
    if bytes(normalized) != pre_relocation:
        raise VerificationError("Observed relocation normalization differs from the pre-relocation snapshot.")
    if len(relocation_events) != 1652:
        raise VerificationError("Unexpected EGA relocation count.")
    final_registers = {name: uc.reg_read(reg) for name, reg in {
        "cs": UC_X86_REG_CS, "ip": UC_X86_REG_IP,
        "ds": UC_X86_REG_DS, "es": UC_X86_REG_ES,
        "ss": UC_X86_REG_SS, "sp": UC_X86_REG_SP,
    }.items()}
    if final_registers["ss"] != load_segment + m["original_ss"] or final_registers["sp"] != m["original_sp"]:
        raise VerificationError("Loader did not restore the metadata-described application stack.")
    transfer = bytes(uc.mem_read(new_stub, 4))
    final_ip, final_cs = struct.unpack("<HH", transfer)
    if final_ip != m["original_ip"] or final_cs != load_segment + m["original_cs"]:
        raise VerificationError("Final transfer pointer does not match the recovered entry.")
    report = {
        "method": "original-exepack-stub-cpu-only-emulation",
        "source_sha256": sha256(data), "stub_sha256": EXPECTED_STUB_SHA256,
        "tool_sha256": sha256(Path(__file__).read_bytes()),
        "unicorn_version": importlib.metadata.version("unicorn"),
        "load_segment": load_segment, "image_size": image_size,
        "pre_relocation_sha256": sha256(pre_relocation),
        "relocated_image_sha256": sha256(relocated),
        "normalized_image_sha256": sha256(bytes(normalized)),
        "relocation_count": len(relocation_events),
        "relocation_offsets_in_execution_order": [e["image_offset"] for e in relocation_events],
        "relocation_events": relocation_events,
        "loader_hook_instruction_count": fence.count,
        "stopped_before_final_far_jump": True,
        "application_instructions_executed": 0,
        "interrupts_or_port_io_executed": 0,
        "final_loader_registers": final_registers,
        "application_entry": {"cs_relative": m["original_cs"], "ip": final_ip,
                              "image_offset": m["original_cs"] * 16 + final_ip},
        "metadata": m,
    }
    return pre_relocation, relocated, report


def write_exact(path: Path, content: bytes) -> None:
    if path.exists() and path.read_bytes() != content:
        raise VerificationError(f"Refusing to overwrite differing evidence: {path}")
    path.write_bytes(content)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--load-segment", type=lambda s: int(s, 0), default=0x1000)
    parser.add_argument("--compare-image", type=Path)
    args = parser.parse_args()
    check_paths(args.source, args.output_dir)
    before = args.source.read_bytes()
    image, relocated, report = recover_with_original_loader(before, args.load_segment)
    if args.source.read_bytes() != before:
        raise VerificationError("Working source changed during verification.")
    if args.compare_image:
        compared = args.compare_image.read_bytes()
        if compared != image:
            raise VerificationError("Independent image differs from the comparison image.")
        report["comparison"] = {"path": str(args.compare_image.resolve()),
                                "sha256": sha256(compared), "exact_match": True}
    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_exact(args.output_dir / "pre-relocation-image.bin", image)
    write_exact(args.output_dir / "relocated-image.bin", relocated)
    write_exact(args.output_dir / "verification.json", (json.dumps(report, indent=2) + "\n").encode())
    print(json.dumps({key: report[key] for key in (
        "method", "image_size", "pre_relocation_sha256", "relocation_count",
        "loader_hook_instruction_count", "application_instructions_executed",
    )}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
