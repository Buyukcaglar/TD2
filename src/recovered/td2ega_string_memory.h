#ifndef TD2EGA_STRING_MEMORY_H
#define TD2EGA_STRING_MEMORY_H
#include "td2ega_state_loop.h"
typedef struct td2ega_string_memory_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t operations,bus_writes;
    td2ega_state_registers returned;
} td2ega_string_memory_result;
/* 0=2916 tail-copy,1=2956 copy,2=2988 compare,3=2B40 bytecase compare,
 * 4=2B82 fill, all in13A8. Raw currentDS near operands, incomingDF,
 * actual SS savedBP/far return and sequential byte/word accesses. Native
 * 0 far-return operation,2 invalid profile,3 before-element budget prefix.
 * Caller bounds/NUL/DF/otherFLAGS/lifetime/core acceptance separate. */
void td2ega_string_memory(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    uint16_t,const td2ega_state_registers *,uint32_t,
    td2ega_string_memory_result *);
#endif
