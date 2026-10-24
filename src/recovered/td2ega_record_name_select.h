#ifndef TD2EGA_RECORD_NAME_SELECT_H
#define TD2EGA_RECORD_NAME_SELECT_H
#include "td2ega_string_memory.h"
typedef struct td2ega_record_name_select_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t calls,operations,iterations,bus_writes;
    td2ega_state_registers returned;
} td2ega_record_name_select_result;
/* Actual0000:0730 far/noargs/fullSS/signedmutablecount/stride32-compare/
 * fallback-firstname/actual2B40-2956/incomingDF/finaluncleanedargs-MOVSPBP.
 * SP28..FFE0 preserveschildentry16. Native0rootRET/1rawchildRET/2invalid/
 * 3CALL-childoperation-rootiterationbudget. OtherarithFLAGSunexposed;
 * actualcallers/storage/writers/domain/capacity/lifetime/IRQ/core open. */
void td2ega_record_name_select(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    const td2ega_state_registers *,uint32_t,uint32_t,uint32_t,
    td2ega_record_name_select_result *);
#endif
