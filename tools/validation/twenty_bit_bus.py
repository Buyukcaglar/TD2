"""Explicit serialized 20-bit RAM profile for private Unicorn comparisons.

Both guest views share one host allocation. Keep the returned allocation alive
for the lifetime of the Uc instance. This selects an analysis address profile;
it does not qualify the historical CPU, A20 gate or hardware bus cycles.
"""
import ctypes as C
from unicorn import UC_PROT_ALL

def map_twenty_bit_ram(cpu):
    backing=(C.c_uint8*0x100000)()
    pointer=C.addressof(backing)
    cpu.mem_map_ptr(0,0x100000,UC_PROT_ALL,pointer)
    cpu.mem_map_ptr(0x100000,0x100000,UC_PROT_ALL,pointer)
    return backing
