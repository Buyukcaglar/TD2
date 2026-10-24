#ifndef TD2EGA_BLOCK_REQUEST_H
#define TD2EGA_BLOCK_REQUEST_H
#include "td2ega_block_adjust.h"
typedef struct td2ega_block_request_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t calls,services,records,bus_writes;
    td2ega_state_registers returned;
} td2ega_block_request_result;
/* Actual13A8:2852 far/fiveavailableSSwords (BP+6..0E), actual28C0near
 * child/inheritedBP/fullSS, rawmode/cursor/fallbackDOS48 andreturnedstate.
 * SP12..FFE0 preserveschild0 throughsecondPUSHSI+CALL.
 * Native0actualrootfarRET/1rawchildnearRET/2invalid/3budget/4adapterfailure.
 * Sharedservicebudget; perchildscanbudget, oneactualnearCALLperpath.
 * No realDOS/INTframes/capacity/ownership/lifetime/IRQ/core/session claim. */
void td2ega_block_request(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    const td2ega_state_registers *,td2ega_small_platform_service,void *,
    uint32_t,uint32_t,uint32_t,td2ega_block_request_result *);
#endif
