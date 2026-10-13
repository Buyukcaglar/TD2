"""Synthetic EXEPACK and MZ validation cases; no original payload fixtures."""
import struct
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from exepack import decode_backwards, read_mz, read_relocations


class ExepackTests(unittest.TestCase):
    def test_fill_terminated_and_prefix(self):
        image, record = decode_backwards(b"ABZ\x03\x00\xb1\xff\xff", 5)
        self.assertEqual(image, b"ABZZZ")
        self.assertEqual(record["padding_ff_bytes"], 2)
        self.assertEqual(record["uncompressed_prefix_bytes"], 2)

    def test_literal_then_fill_with_16_bit_count(self):
        packed = b"Q\x01\x01\xb1XYZ\x03\x00\xb2"
        image, _ = decode_backwards(packed, 260)
        self.assertEqual(image, b"Q" * 257 + b"XYZ")

    def test_terminated_literal_preserves_order(self):
        image, _ = decode_backwards(b"abc\x03\x00\xb3", 3)
        self.assertEqual(image, b"abc")

    def test_bad_streams_rejected(self):
        cases = [(b"\xff", 1), (b"X\x01\x00\xa1", 1),
                 (b"X\x02\x00\xb1", 1), (b"\x02\x00\xb3", 2),
                 (b"X\x01\x00\xb1", 2), (b"X\x01\x00\xb0", 1)]
        for packed, size in cases:
            with self.subTest(packed=packed, size=size), self.assertRaises(ValueError):
                decode_backwards(packed, size)

    def test_relocations_group_segments(self):
        data = struct.pack("<HHHH", 1, 2, 1, 4) + b"\0\0" * 14
        rows = read_relocations(data, 0, len(data), 0x10010)
        self.assertEqual([r["image_relative"] for r in rows], [2, 0x10004])

    def test_relocation_bounds_duplicates_and_trailer(self):
        for data, size in [(struct.pack("<HH", 1, 9) + b"\0\0" * 15, 10),
                           (struct.pack("<HHH", 2, 1, 1) + b"\0\0" * 15, 10),
                           (b"\0\0" * 16 + b"X", 10), (b"\0", 10)]:
            with self.subTest(data=data), self.assertRaises(ValueError):
                read_relocations(data, 0, len(data), size)

    def test_mz_exact_page_and_malformed(self):
        data = bytearray(512)
        struct.pack_into("<14H", data, 0, 0x5A4D, 0, 1, 0, 2, 0, 0, 0, 0, 0, 0, 0, 28, 0)
        self.assertEqual(read_mz(bytes(data))["declared_bytes"], 512)
        with self.assertRaises(ValueError):
            read_mz(bytes(data[:-1]))
        data[8:10] = b"\xff\xff"
        with self.assertRaises(ValueError):
            read_mz(bytes(data))


if __name__ == "__main__":
    unittest.main()
