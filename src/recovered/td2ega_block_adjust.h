#ifndef TD2EGA_BLOCK_ADJUST_H
#define TD2EGA_BLOCK_ADJUST_H
#include "td2ega_small_platform.h"
typedef struct td2ega_block_adjust_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t records,services,bus_writes;
    td2ega_state_registers returned;
} td2ega_block_adjust_result;
/* Actual13A8:28C0 near/inheritedBP; CXfromSS[BP+0E], DIrawrecordstart,
 * DXrawincrement; actualDS/SS/wordEA/returnedDOS4Aregisters andmetadata.
 * Native0actualnearRET/2invalid/3before-scan-or-INTbudget/4adapterfailure.
 * AdapterpreservesSS/SP/CS; syntheticboundary omitsrealINTframes/DOS.
 * No tabledomain/storage/caller/lifetime/IRQ/core/session acceptance. */
void td2ega_block_adjust(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    const td2ega_state_registers *,td2ega_small_platform_service,void *,
    uint32_t,uint32_t,td2ega_block_adjust_result *);
#endif
