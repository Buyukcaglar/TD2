#ifndef TD2EGA_RECORD_PROJECTION_H
#define TD2EGA_RECORD_PROJECTION_H
#include "td2ega_state_loop.h"
typedef struct td2ega_record_projection_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t records,bus_writes;
    td2ega_state_registers returned;
} td2ega_record_projection_result;
/* Actual06C9:0201/far/noargs. LiteralREP17STOSW/CLD/ES=DS,
 * two do-once8byte record loops/currentDS/orderedrereads/partialoutput.
 * Native0actualfarreturn/2invalid/3beforerecordbudget. BPactuallyclobbered.
 * No capacity/units/caller/writer/lifetime/IRQ/core/session acceptance. */
void td2ega_record_projection(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    const td2ega_state_registers *,uint32_t,td2ega_record_projection_result *);
#endif
