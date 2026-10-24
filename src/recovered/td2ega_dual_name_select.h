#ifndef TD2EGA_DUAL_NAME_SELECT_H
#define TD2EGA_DUAL_NAME_SELECT_H
#include "td2ega_string_memory.h"
typedef struct td2ega_dual_name_select_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t calls,operations,iterations,bus_writes;
    td2ega_state_registers returned;
} td2ega_dual_name_select_result;
/* Actual0000:0651 far/noargs/fullSS/twoqueries/stride30/signedIMUL-DXAX-CF/
 * mutablecount/lastmatches/fallback0-or1/actual2B40-2956/incomingDF.
 * SP28..FFE0 preserveschild16. Native0rootRET/1rawchildRET/2invalid/
 * 3CALL-childoperation-rootiterationbudget. No caller/schema/NUL-capacity/
 * allwriters/storage/ownership/lifetime/IRQ/core/session/fidelity acceptance. */
void td2ega_dual_name_select(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    const td2ega_state_registers *,uint32_t,uint32_t,uint32_t,
    td2ega_dual_name_select_result *);
#endif
