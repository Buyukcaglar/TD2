#ifndef TD2EGA_RECORD_SEQUENCE_H
#define TD2EGA_RECORD_SEQUENCE_H
#include "td2ega_record_math.h"
#include "td2ega_small_arithmetic.h"
typedef struct td2ega_record_sequence_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t calls,iterations,bus_writes;
    td2ega_state_registers returned;
} td2ega_record_sequence_result;
/* Actual06C9:5ADA far root plus actual5B5A/5C30 near callees, no SS args.
 * RootSP>=24 ensures each frozen childSP>=16. Actual SS saves/frames.
 * Native0rootfarRET/1rawchildnearRET/2invalid/3before-call-or-child-loop.
 * Raw source fields/rings and returned BP/FLAGS retained; no core admission. */
void td2ega_record_sequence(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    const td2ega_state_registers *,uint32_t,uint32_t,td2ega_record_sequence_result *);
#endif
