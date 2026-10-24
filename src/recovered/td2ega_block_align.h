#ifndef TD2EGA_BLOCK_ALIGN_H
#define TD2EGA_BLOCK_ALIGN_H
#include "td2ega_block_tail.h"
typedef struct td2ega_block_align_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t calls,child_near_calls,child_far_calls,nested_calls;
    uint32_t services,records,iterations,bus_writes;
    uint16_t zero_flag,flags_valid;
    td2ega_state_registers returned;
} td2ega_block_align_result;
/* Actual13A8:27D4 near/inheritedregistercontext/actual280ErequiredZF,
 * SSsavedCX/ES6F36threshold/wordmask-overflow/retryusingactualreturnedDX.
 * SP40..FFE0 preserveschild36. Native0rootnearRET/1rawchildRET/2invalid/
 * 3CALL-loop-servicebudgets/4adapterfailure. Sharedservicebudget across
 * retries, perchildCALL-scanbudgets; normalflags_valid1/ZFfromchildJNE
 * success0orXORAXfailure1. Actual27B8JE requiresZF. No realDOS/CPU-A20/
 * capacity/ownership/lifetime/IRQ/core/session acceptance. */
void td2ega_block_align(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    const td2ega_state_registers *,td2ega_small_platform_service,void *,
    uint32_t,uint32_t,uint32_t,uint32_t,uint32_t,uint32_t,uint32_t,
    td2ega_block_align_result *);
#endif
