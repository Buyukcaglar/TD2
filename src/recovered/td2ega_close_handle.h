#ifndef TD2EGA_CLOSE_HANDLE_H
#define TD2EGA_CLOSE_HANDLE_H
#include "td2ega_small_platform.h"
typedef struct td2ega_close_handle_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t services,error_calls,bus_writes;
    td2ega_state_registers returned;
} td2ega_close_handle_result;
/* Actual13A8:223E, oneSSword rawhandle. Unsignedlimit6DA2, DOS3E full
 * returnedGPR/BP/DS/CFIFDF, successclearbyte6DA4+returnedBX, actual094A.
 * PlainfarRET4/callercleansarg; rootSP20 preserves mapperSP16.
 * Native0rootRET/1rawmapperRET/2invalid/3beforeINT/4adapterfailure.
 * Syntheticservice omits realINTframes; noactualDOS/file/session claim.
 * Actualcaller/bounds/writers/lifetime/FLAGS/IRQ/core gates separate. */
void td2ega_close_handle(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    const td2ega_state_registers *,td2ega_small_platform_service,void *,
    uint32_t,td2ega_close_handle_result *);
#endif
