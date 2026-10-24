#ifndef TD2EGA_WRITE_SPAN_H
#define TD2EGA_WRITE_SPAN_H
#include "td2ega_small_platform.h"
typedef struct td2ega_write_span_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint16_t return_kind,return_valid;
    uint32_t calls,services,bus_writes;
    td2ega_state_registers returned;
} td2ega_write_span_result;
/* Actual13A8:2600 near/inheritedBP-DS-DX-DI; own3saves, actualDOS40,
 * normalnearRET ornonlocalshared2558farRET/actual094A busmapper.
 * All16bitSP admittedinserialized20bitRAMprofile, includingADDSP8carry.
 * Native0rootreturn(kind0near/1far)/1rawmapperRET/2invalid/3budgets/
 * 4adapterfailure; return_valid1onlyrootoperation. OtherarithFLAGS
 * unexposed/knowncallerliveness reviewed. No realDOS/CPU-A20/caller/
 * storage/ownership/lifetime/IRQ/core/session/fidelity acceptance. */
void td2ega_write_span(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    const td2ega_state_registers *,uint32_t,uint32_t,
    td2ega_small_platform_service,void *,td2ega_write_span_result *);
#endif
