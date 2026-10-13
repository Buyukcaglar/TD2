"""Synthetic fail-closed checks; no original or derived game fixture is used."""

import importlib.util
from pathlib import Path
import sys
import unittest

TOOL = Path(__file__).resolve().parents[2] / "tools" / "validation" / "verify_exepack_loader.py"
SPEC = importlib.util.spec_from_file_location("verify_exepack_loader", TOOL)
loader = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = loader
SPEC.loader.exec_module(loader)


class InputGuards(unittest.TestCase):
    def test_reference_input_rejected(self):
        with self.assertRaises(loader.VerificationError):
            loader.check_paths(loader.WORKSPACE / "reference/dos/TD2EGA.EXE", loader.PRIVATE_ROOT / "test")

    def test_public_output_rejected(self):
        with self.assertRaises(loader.VerificationError):
            loader.check_paths(loader.WORKSPACE / "analysis/inputs/dos/TD2EGA.EXE", loader.WORKSPACE / "docs")

    def test_unknown_input_rejected_before_emulation(self):
        with self.assertRaisesRegex(loader.VerificationError, "pinned"):
            loader.parse_pinned_input(b"MZ" + bytes(510))


class ExecutionGuards(unittest.TestCase):
    def run_code(self, code, ranges=None, stop=0x1004, budget=20):
        from unicorn import Uc, UC_ARCH_X86, UC_MODE_16, UC_HOOK_CODE, UC_HOOK_INTR
        uc = Uc(UC_ARCH_X86, UC_MODE_16)
        uc.mem_map(0, 0x10000)
        uc.mem_write(0x1000, code)
        fence = loader.ExecutionFence(ranges or [(0x1000, 0x1010)], stop, budget)
        uc.hook_add(UC_HOOK_CODE, fence.code)
        uc.hook_add(UC_HOOK_INTR, fence.interrupt)
        uc.emu_start(0x1000, 0xFFFF)
        return fence

    def test_stops_before_target_instruction(self):
        fence = self.run_code(b"\x90\x90\x90\x90\xCD\x21")
        self.assertTrue(fence.stopped_before_transfer)
        self.assertEqual(fence.count, 4)

    def test_interrupt_rejected(self):
        with self.assertRaisesRegex(loader.VerificationError, "forbidden"):
            self.run_code(b"\xCD\x21")

    def test_port_io_rejected(self):
        with self.assertRaisesRegex(loader.VerificationError, "forbidden"):
            self.run_code(b"\xEE")

    def test_prefixed_port_io_rejected(self):
        with self.assertRaisesRegex(loader.VerificationError, "forbidden"):
            self.run_code(b"\x2E\xEE")

    def test_fetch_outside_stub_rejected(self):
        with self.assertRaisesRegex(loader.VerificationError, "outside"):
            self.run_code(b"\x90\x90\x90", ranges=[(0x1000, 0x1001)])

    def test_instruction_budget_rejected(self):
        with self.assertRaisesRegex(loader.VerificationError, "budget"):
            self.run_code(b"\xEB\xFE", budget=5)


if __name__ == "__main__":
    unittest.main()
