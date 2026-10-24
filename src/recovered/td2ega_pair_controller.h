#ifndef TD2EGA_PAIR_CONTROLLER_H
#define TD2EGA_PAIR_CONTROLLER_H
#include "td2ega_small_arithmetic.h"
typedef struct td2ega_pair_controller_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t calls,bus_writes;
    td2ega_state_registers returned;
} td2ega_pair_controller_result;
/* Actual06C9:595F near/noargs with up tothree actualnear5A25 calls.
 * SP18..FFE0 preserves frozenchild minimum16; actualSSframes/RET2.
 * Native0rootRET/1rawchildRET/2invalid/3beforeCALL prefix.
 * Rawpair words/angles/flags only; no units/collision/gameplay claim.
 * Caller/writer/lifetime/IRQ/core/resource/runtime gates separate. */
void td2ega_pair_controller(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    const td2ega_state_registers *,uint32_t,td2ega_pair_controller_result *);
#endif
