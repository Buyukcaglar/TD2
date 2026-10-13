"""Bounded EXEPACK recovery for the admitted TD2 loader layout.

This is an analysis tool, not the game core. Original files are read only.
The supported 18-byte header and stub digest are established from TD2EGA.
Algorithm comparison: w4kfu/unEXEPACK unpack.c at commit
672f352ab6234090e730420d23eeeae05ac48cdc; project code is independently written.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_SOURCE_SHA256 = "eb4f8e882fd79e884260b2285f38cc22673d45ddc5f601a5815bcce42d5a7182"
STUB_SHA256 = "3c2ecf0c7854abfe0390cfa2482fc3941cf255546ce1629132eb62bb08f3d435"
MAX_IMAGE_BYTES = 0x100000
MZ_NAMES = ("signature", "last_page_bytes", "pages", "relocation_count",
            "header_paragraphs", "minimum_extra_paragraphs", "maximum_extra_paragraphs",
            "ss", "sp", "checksum", "ip", "cs", "relocation_table_offset", "overlay")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_mz(data: bytes) -> dict:
    if len(data) < 28:
        raise ValueError("Truncated MZ header")
    words = struct.unpack_from("<14H", data)
    header = dict(zip(MZ_NAMES, words))
    if data[:2] != b"MZ" or not header["pages"]:
        raise ValueError("Invalid MZ signature/page count")
    if header["last_page_bytes"] >= 512:
        raise ValueError("Invalid last-page length")
    declared = ((header["pages"] - 1) * 512 + header["last_page_bytes"]
                if header["last_page_bytes"] else header["pages"] * 512)
    start = header["header_paragraphs"] * 16
    if start < 28 or start > declared or declared != len(data):
        raise ValueError("MZ header/image boundaries do not match file")
    if header["relocation_table_offset"] + 4 * header["relocation_count"] > start:
        raise ValueError("Outer relocation table exceeds header")
    header.update({"declared_bytes": declared, "load_image_file_offset": start,
                   "load_image_bytes": declared - start})
    return header


def decode_backwards(packed: bytes, output_size: int) -> tuple[bytes, dict]:
    if not 0 < output_size <= MAX_IMAGE_BYTES or not packed:
        raise ValueError("Invalid packed/destination length")
    source = len(packed) - 1
    while source >= 0 and packed[source] == 0xFF:
        source -= 1
    padding = len(packed) - 1 - source
    output = bytearray(output_size)
    destination = output_size
    commands = []
    while True:
        if source < 2:
            raise ValueError("Missing/truncated EXEPACK command")
        command_end = source + 1
        opcode = packed[source]
        count = (packed[source - 1] << 8) | packed[source - 2]
        source -= 3
        kind = opcode & 0xFE
        if kind not in (0xB0, 0xB2):
            raise ValueError(f"Unsupported EXEPACK command 0x{opcode:02X}")
        if count > destination:
            raise ValueError("EXEPACK destination underflow")
        begin = destination - count
        if kind == 0xB0:
            if source < 0:
                raise ValueError("Missing fill byte")
            output[begin:destination] = bytes([packed[source]]) * count
            source -= 1
        else:
            if count > source + 1:
                raise ValueError("EXEPACK literal source underflow")
            output[begin:destination] = packed[source + 1 - count:source + 1]
            source -= count
        commands.append({"kind": "fill" if kind == 0xB0 else "literal",
                         "opcode": opcode, "count": count,
                         "packed_relative_range": [source + 1, command_end],
                         "output_relative_range": [begin, destination],
                         "final": bool(opcode & 1)})
        destination = begin
        if opcode & 1:
            break
    prefix_size = source + 1
    if prefix_size != destination:
        raise ValueError("Expanded bytes plus literal prefix do not fill declared image")
    output[:prefix_size] = packed[:prefix_size]
    return bytes(output), {"padding_ff_bytes": padding,
                           "uncompressed_prefix_bytes": prefix_size,
                           "command_count": len(commands),
                           "command_types": dict(Counter(c["kind"] for c in commands)),
                           "commands": commands}


def read_relocations(data: bytes, start: int, end: int, image_size: int) -> list[dict]:
    records = []
    pointer = start
    seen = set()
    for group in range(16):
        if pointer + 2 > end:
            raise ValueError("Truncated packed relocation group")
        count = struct.unpack_from("<H", data, pointer)[0]
        pointer += 2
        if pointer + 2 * count > end:
            raise ValueError("Packed relocation offsets exceed tail")
        for _ in range(count):
            offset = struct.unpack_from("<H", data, pointer)[0]
            segment = group * 0x1000
            relative = segment * 16 + offset
            if relative + 2 > image_size:
                raise ValueError("Relocation word exceeds unpacked image")
            if relative in seen:
                raise ValueError("Duplicate relocation is outside admitted layout")
            seen.add(relative)
            records.append({"segment": segment, "offset": offset,
                            "image_relative": relative,
                            "packed_file_offset": pointer})
            pointer += 2
    if pointer != end:
        raise ValueError("Unclassified packed relocation trailing bytes")
    return records


def recover(data: bytes) -> tuple[bytes, bytes, dict, list[dict]]:
    if sha256(data) != EXPECTED_SOURCE_SHA256:
        raise ValueError("Input is not the admitted TD2EGA.EXE")
    mz = read_mz(data)
    if mz["relocation_count"] or mz["ip"] != 0x12:
        raise ValueError("Unsupported outer loader header")
    start = mz["load_image_file_offset"]
    base = start + mz["cs"] * 16
    if base + 0x12D > len(data):
        raise ValueError("Truncated EXEPACK stub")
    meta = dict(zip(("original_ip", "original_cs", "load_segment_scratch",
                     "tail_bytes", "original_sp", "original_ss", "destination_paragraphs",
                     "skip_paragraphs", "signature"), struct.unpack_from("<9H", data, base)))
    if meta["signature"] != 0x4252 or meta["skip_paragraphs"] != 1:
        raise ValueError("Unsupported EXEPACK metadata variant")
    if meta["load_segment_scratch"] != 0:
        raise ValueError("Unexpected premodified loader scratch word")
    if sha256(data[base + 0x12:base + 0x12D]) != STUB_SHA256:
        raise ValueError("Unrecognized EXEPACK loader stub")
    tail_end = base + meta["tail_bytes"]
    if tail_end != len(data):
        raise ValueError("Unclassified bytes after supported EXEPACK tail")
    size = meta["destination_paragraphs"] * 16
    image, transform = decode_backwards(data[start:base], size)
    relocations = read_relocations(data, base + 0x12D, tail_end, size)
    entry = meta["original_cs"] * 16 + meta["original_ip"]
    packed_paragraphs = (mz["load_image_bytes"] + 15) // 16
    minimum_total = packed_paragraphs + mz["minimum_extra_paragraphs"]
    minimum_extra = minimum_total - meta["destination_paragraphs"]
    if minimum_extra < 0 or entry >= size:
        raise ValueError("Invalid recovered allocation/entry")
    if meta["original_ss"] * 16 + meta["original_sp"] > minimum_total * 16:
        raise ValueError("Recovered stack exceeds minimum allocation")
    maximum_extra = (0xFFFF if mz["maximum_extra_paragraphs"] == 0xFFFF else
                     packed_paragraphs + mz["maximum_extra_paragraphs"] - meta["destination_paragraphs"])
    if not 0 <= maximum_extra <= 0xFFFF:
        raise ValueError("Invalid maximum allocation")
    header_bytes = (28 + 4 * len(relocations) + 15) // 16 * 16
    total = header_bytes + size
    header = bytearray(header_bytes)
    struct.pack_into("<14H", header, 0, 0x5A4D, total % 512, (total + 511) // 512,
                     len(relocations), header_bytes // 16, minimum_extra, maximum_extra,
                     meta["original_ss"], meta["original_sp"], 0, meta["original_ip"],
                     meta["original_cs"], 28, 0)
    for index, relocation in enumerate(relocations):
        struct.pack_into("<HH", header, 28 + index * 4,
                         relocation["offset"], relocation["segment"])
    normalized = bytes(header) + image
    record = {"schema": 1, "target": "TD2EGA", "packed_sha256": sha256(data),
              "unpacked_image_bytes": size, "unpacked_image_sha256": sha256(image),
              "normalized_mz_bytes": len(normalized), "normalized_mz_sha256": sha256(normalized),
              "outer_mz": mz, "exepack_header": meta,
              "stub_sha256": STUB_SHA256, "stub_file_range": [base + 0x12, base + 0x12D],
              "packed_data_file_range": [start, base],
              "relocation_file_range": [base + 0x12D, tail_end],
              "relocation_count": len(relocations), "entry_image_relative": entry,
              "minimum_allocation_paragraphs": minimum_total,
              "normalized_minimum_extra_paragraphs": minimum_extra,
              "normalized_maximum_extra_paragraphs": maximum_extra,
              "normalized_header_bytes": header_bytes,
              "normalization": "New MZ header/relocation envelope; checksum zeroed; original allocation budget preserved. Not an original publisher EXE.",
              "transform": transform,
              "validation": "Decoder structural checks only; independent verification is a separate record."}
    read_mz(normalized)
    return image, normalized, record, relocations


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--record", required=True, type=Path)
    args = parser.parse_args()
    output = args.output_dir.resolve()
    record_path = args.record.resolve()
    if not output.is_relative_to((ROOT / "analysis").resolve()):
        raise ValueError("Payload output must stay under private analysis directory")
    if record_path.is_relative_to((ROOT / "reference").resolve()):
        raise ValueError("Refusing reference output")
    if output.exists() or record_path.exists():
        raise FileExistsError("Refusing to replace existing recovery artifacts")
    packed = args.input.read_bytes()
    if sha256(packed) != EXPECTED_SOURCE_SHA256:
        raise ValueError("CLI input is not the admitted TD2EGA.EXE; other targets require separate recovery")
    image, mz, record, relocations = recover(packed)
    record["input_path"] = args.input.resolve().relative_to(ROOT).as_posix()
    record["tool_sha256"] = sha256(Path(__file__).read_bytes())
    record["outputs"] = {"image": (output / "TD2EGA.image.bin").relative_to(ROOT).as_posix(),
                         "normalized_mz": (output / "TD2EGA.unpacked.exe").relative_to(ROOT).as_posix(),
                         "relocations": (output / "relocations.json").relative_to(ROOT).as_posix()}
    output.mkdir(parents=True)
    (output / "TD2EGA.image.bin").write_bytes(image)
    (output / "TD2EGA.unpacked.exe").write_bytes(mz)
    (output / "relocations.json").write_text(json.dumps(relocations, indent=2) + "\n", encoding="utf-8")
    record_path.parent.mkdir(parents=True, exist_ok=True)
    record_path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: record[k] for k in ("unpacked_image_bytes", "unpacked_image_sha256",
                     "relocation_count", "entry_image_relative", "normalized_minimum_extra_paragraphs")}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
