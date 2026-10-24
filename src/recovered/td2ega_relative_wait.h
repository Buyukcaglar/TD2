#ifndef TD2EGA_RELATIVE_WAIT_H
#define TD2EGA_RELATIVE_WAIT_H
#include "td2ega_wait_roots.h"
typedef struct td2ega_relative_wait_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t reads,bus_writes;
    td2ega_state_registers returned;
} td2ega_relative_wait_result;
/*06C9:C6C5, twoSSwords rawlow/highoffset. ActualC692CLI/read/STI/RETF,
 * orderedSSlocaltarget ADD/ADC, thenunsignedhighANDlow comparisons (notlex).
 * ActualSSframes/aliases, normalplainfarRETF4/caller4bytescleanup.
 * Observeroptional memory-onlysyntheticcounterupdates beforeactualC692CLI;
 * NULLkeepsbusunchanged. Native0rootfarreturn/1rawchild/2invalid/3before-read/
 *4observerfailure. No Hz/timebase/realIRQ/session/core acceptance. */
void td2ega_relative_wait(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    const td2ega_state_registers *,td2ega_wait_roots_observer,void *,uint32_t,
    td2ega_relative_wait_result *);
#endif
