#ifndef TD2EGA_RECORD_MATH_H
#define TD2EGA_RECORD_MATH_H
#include "td2ega_state_loop.h"
typedef struct td2ega_record_math_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t iterations,bus_writes;
    td2ega_state_registers returned;
} td2ega_record_math_result;
/* Selectors 0=5299,1=5022,2=5446,3=4F92,4=5B5A, all near entries.
 * Raw DS records/fields and explicit DS:[BP+SI] operands, real SS saves/RET.
 * Native0return/2invalid/3before-loop budget; raw bounds can cycle.
 * No record units, complete writers/lifetime, gameplay/core acceptance. */
void td2ega_record_math(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    uint16_t,const td2ega_state_registers *,uint32_t,td2ega_record_math_result *);
#endif
