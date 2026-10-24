#ifndef TD2EGA_SEEK_HANDLE_H
#define TD2EGA_SEEK_HANDLE_H
#include "td2ega_small_platform.h"
typedef struct td2ega_seek_handle_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t services,error_calls,bus_writes;
    td2ega_state_registers returned;
} td2ega_seek_handle_result;
/* Actual13A8:225E/fourSSwords handle/low/high/rawmode, actual094A mapper.
 * FullreturnedDOS42 GPR/BP/DS/CFIFDF; SS/SP/CS preservedbyadapter.
 * Query/end/restore/finalseek sourceorder andignoredCF paths retained.
 * RootSP24 preservesmapperSP16. PlainfarRET4/callerclean8args.
 * Native0rootRET/1rawmapperRET/2invalid/3beforeINT/4adapterfailure.
 * ActualDOS/files/caller/writers/lifetime/IRQ/core acceptance separate. */
void td2ega_seek_handle(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    const td2ega_state_registers *,td2ega_small_platform_service,void *,
    uint32_t,td2ega_seek_handle_result *);
#endif
