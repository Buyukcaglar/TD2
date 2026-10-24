#ifndef TD2EGA_BLOCK_TAIL_H
#define TD2EGA_BLOCK_TAIL_H
#include "td2ega_block_wrapper.h"
typedef struct td2ega_block_tail_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t calls,child_far_calls,child_near_calls,services,records,bus_writes;
    uint16_t zero_flag,flags_valid;
    td2ega_state_registers returned;
} td2ega_block_tail_result;
/* Actual13A8:280E near/inheritedregister-context, actual2830requiredZF.
 * SP36..FFE0 preserveswrapper30. ActualSSsavedDX-CX/optionalDI-to-AX,
 * rawDSmetadata/SI-DIarithmetic, normalZFfromwrapperfailureorDECDX.
 * Native0rootnearRET/1rawchildRET/2invalid/3budgets/4adapterfailure.
 * flags_valid1onlyrootRET; caller27B0JE/2802JNE requirezero_flag.
 * No capacity/ownership/caller/lifetime/IRQ/core/realDOS/session admission. */
void td2ega_block_tail(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    const td2ega_state_registers *,td2ega_small_platform_service,void *,
    uint32_t,uint32_t,uint32_t,uint32_t,uint32_t,td2ega_block_tail_result *);
#endif
