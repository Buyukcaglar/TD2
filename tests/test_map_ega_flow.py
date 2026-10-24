"""Synthetic control-flow cases; no original executable bytes in fixtures."""
import sys
from pathlib import Path
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from map_ega_flow import discover


class FlowDiscoveryTests(unittest.TestCase):
    def test_conditional_and_unconditional_paths(self):
        # JZ +3; JMP +2; HLT(unreachable); RET; RET
        functions, decoded = discover(bytes.fromhex('7403eb02f4c3c3'),[(0,0)])
        self.assertEqual(set(decoded),{(0,0),(0,2),(0,5),(0,6)})
        self.assertEqual(len(functions),1)

    def test_far_call_preserves_target_segment(self):
        image=bytearray(32)
        image[:6]=bytes.fromhex('9a00000100cb')  # CALLF 0001:0000; RETF
        image[16]=0xcb
        functions,decoded=discover(bytes(image),[(0,0)])
        self.assertEqual(set(functions),{(0,0),(1,0)})
        self.assertEqual(functions[(0,0)]['calls'][0]['target'],'0001:0000')
        self.assertIn((1,0),decoded)

    def test_indirect_is_open_without_review(self):
        functions,decoded=discover(bytes.fromhex('ffe0c3'),[(0,0)])
        self.assertEqual(set(decoded),{(0,0)})
        self.assertEqual(functions[(0,0)]['indirect'][0]['operand'],'ax')

    def test_near_dispatch_keeps_shared_body(self):
        image=bytes.fromhex('ffe0f4c3')
        functions,decoded=discover(image,[(0,0)],{'0000:0000':{'targets':['0000:0003']}})
        self.assertEqual(set(functions),{(0,0)})
        self.assertEqual(set(decoded),{(0,0),(0,3)})

    def test_far_indirect_call_discovers_function_and_fallthrough(self):
        image=bytearray(32)
        image[:5]=bytes.fromhex('ff1e0000cb')
        image[16]=0xcb
        functions,decoded=discover(bytes(image),[(0,0)],{'0000:0000':{'targets':['0001:0000']}})
        self.assertEqual(set(functions),{(0,0),(1,0)})
        self.assertIn((0,4),decoded)

    def test_saved_far_return_does_not_consume_caller_body(self):
        image=bytes.fromhex('ff2e0000f4')
        functions,decoded=discover(image,[(0,0)],{'0000:0000':{'disposition':'saved_far_return','targets':['0000:0004']}})
        self.assertEqual(set(decoded),{(0,0)})

    def test_invalid_target_is_reported(self):
        functions,_=discover(bytes.fromhex('eb7f'),[(0,0)])
        self.assertEqual(functions[(0,0)]['issues'][0]['kind'],'outside_initialized_image')

    def test_backward_cycle_terminates(self):
        functions,decoded=discover(bytes.fromhex('ebfe'),[(0,0)])
        self.assertEqual(len(decoded),1)
        self.assertEqual(len(functions),1)


if __name__=='__main__':
    unittest.main()
