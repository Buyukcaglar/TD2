#ifndef TD2EGA_HEAP_WALK_H
#define TD2EGA_HEAP_WALK_H
#include "td2ega_block_align.h"
typedef struct td2ega_heap_walk_limits {
    uint32_t calls,iterations,align_calls,align_iterations;
    uint32_t tail_calls,wrapper_calls,adjust_calls,records,services;
} td2ega_heap_walk_limits;
typedef struct td2ega_heap_walk_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t calls,align_calls,tail_calls,wrapper_calls,adjust_calls;
    uint32_t services,records,iterations,child_iterations,bus_writes;
    uint16_t zero_flag,flags_valid;
    td2ega_state_registers returned;
} td2ega_heap_walk_result;
/* Actual13A8:26F1 near/inheritedBX-CX/currentDS/ES, actual280E/27D4/ZF,
 * rawwordheaders/byteupdates/CLD thenactualreturnedDF LODSW/DSswitches.
 * SP42..FFE0 preservesalign40. Native0rootRET/1rawchildRET/2invalid/
 * 3budgets/4adapterfailure; flags_valid1onlyrootRET. SuccessAXSI/DXDS,
 * CF-ZFfromDSvsSS; failureAXDX0/CF0-ZF1. No hostallocator normalization/
 * schema/capacity/ownership/CPU-A20/IRQ/core/realDOS/session acceptance. */
void td2ega_heap_walk(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    const td2ega_state_registers *,const td2ega_heap_walk_limits *,
    td2ega_small_platform_service,void *,td2ega_heap_walk_result *);
#endif
