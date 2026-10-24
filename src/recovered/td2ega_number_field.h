#ifndef TD2EGA_NUMBER_FIELD_H
#define TD2EGA_NUMBER_FIELD_H
#include "td2ega_state_loop.h"
typedef struct td2ega_number_field_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t digits,bus_writes;
    td2ega_state_registers returned;
} td2ega_number_field_result;
/* Actual13A8:20F0 far/twoSSwords: outputnearoffset,inputnearoffset.
 * IncomingDF retained; explicit scalar reads, literalSSlocals/saves/RETF4.
 * Native0actualfarreturn/2invalid/3before213Cdigitbudget. Noformat/schema,
 * stringbound/caller/writer/lifetime/IRQ/core/session acceptance. */
void td2ega_number_field(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    const td2ega_state_registers *,uint32_t,td2ega_number_field_result *);
#endif
