#ifndef TD2EGA_VIEW_LIMITS_H
#define TD2EGA_VIEW_LIMITS_H
#include "td2ega_state_loop.h"
typedef struct td2ega_view_limits_result {
    uint16_t status;
    uint32_t calls;
    td2ega_state_registers returned;
} td2ega_view_limits_result;
/* 268A readonlyAX/SI limit stage, plainnearRET; native0valid/2invalid status.
 * Original AX/CF outputs remaininreturnedregisters, notnativeCstatus. */
uint16_t td2ega_limit_value(const uint8_t *memory,uint32_t memory_bytes,
    const td2ega_state_registers *incoming,td2ega_state_registers *returned);
/* 2542 rawflag/owner/bound stage plusfouractual268A calls, plainnearRET.
 * SerializedcurrentDS/sharedaliases; data/code/liveSSframes separate.
 * No graphics/tableunits/actualcaller/state/resource/core admission. */
void td2ega_finish_limits(uint8_t *memory,uint32_t memory_bytes,
    const td2ega_state_registers *incoming,td2ega_view_limits_result *result);
#endif
