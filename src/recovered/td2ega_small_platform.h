#ifndef TD2EGA_SMALL_PLATFORM_H
#define TD2EGA_SMALL_PLATFORM_H
#include "td2ega_state_loop.h"
typedef struct td2ega_small_platform_request {
    uint16_t vector,site,segment,stack_segment,stack_sp;
    td2ega_state_registers incoming;
} td2ega_small_platform_request;
typedef int (*td2ega_small_platform_service)(void *,uint8_t *,
    const td2ega_small_platform_request *,td2ega_state_registers *);
typedef struct td2ega_small_platform_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t calls;
    td2ega_state_registers returned;
} td2ega_small_platform_result;
/* Selectors0=5D4E,1=5D74,2=13A8:2E2E,3=5D5B,4=5D2E.
 * Full returned GPR/BP/CFIFDF service state explicit; adapter preservesSS/SP/CS
 * control. Native0farreturn/2invalid/3callprefix/4adapterfailure distinct.
 * Synthetic service boundary omits real interrupt-entry frames/device delivery;
 * no actual DOS/BIOS/IRQ/timebase/session/core admission. */
void td2ega_small_platform(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    uint16_t,const td2ega_state_registers *,td2ega_small_platform_service,
    void *,uint32_t,td2ega_small_platform_result *);
#endif
