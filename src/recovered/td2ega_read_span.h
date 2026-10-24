#ifndef TD2EGA_READ_SPAN_H
#define TD2EGA_READ_SPAN_H
#include "td2ega_small_platform.h"
typedef struct td2ega_read_span_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t calls,services,steps,bus_writes;
    td2ega_state_registers returned;
} td2ega_read_span_result;
/* Actual13A8:247C/far/SS[handle,nearDSbuffer,count]/fullSS/currentDSflags/
 * DOS3F-fullstate/textlookahead4400-3F-4201/fullstate/liveDS-vs-SSlocal/
 * currentDF LODSB/defaultDS[DI]writes/actual094A/shared0937farreturn.
 * CALL-service-LODSbudgets distinct. Native0rootRET/1rawmapperRETneverfollowed/
 * 2invalid/3budget/4service/5unqualifiedfourbytefarframepreRET.
 * No actualDOS/INTframes/storage-writers-lifetime-exclusion/core/resourcecodec/
 * historicalCPU-A20/session/gameplay/fidelity acceptance. */
void td2ega_read_span(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    const td2ega_state_registers *,uint32_t,uint32_t,uint32_t,
    td2ega_small_platform_service,void *,td2ega_read_span_result *);
#endif
