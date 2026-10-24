#ifndef TD2EGA_RAW_WRITE_H
#define TD2EGA_RAW_WRITE_H
#include "td2ega_small_platform.h"
typedef struct td2ega_raw_write_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t services,write_requests,successful_writes,bus_writes,error_calls;
    td2ega_state_registers returned;
} td2ega_raw_write_result;
/*0=7866/error-call policy,1=7874/close-on-error policy. FiveSSwords:
 *[nearFilename,bufferOffset,bufferSegment,lengthLow,lengthHigh]. Mutates
 * callerlengths beforewrites andbuffersegment aftersuccessfulwrites.
 * Native0farreturn/1raw16A7:0002callboundary/2invalid/3before-INTprefix/
 *4adapterfailure. Errorcallee body/not-returning behavior notadmitted.
 * SyntheticDOS serviceprofile preservesSS/SP/CS; noactualfile/INT/runtime,
 * resourceformat/IRQ/core/gameplay/fidelity acceptance. */
void td2ega_raw_write(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    uint16_t,const td2ega_state_registers *,td2ega_small_platform_service,
    void *,uint32_t,td2ega_raw_write_result *);
#endif
