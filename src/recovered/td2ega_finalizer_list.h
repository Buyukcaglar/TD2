#ifndef TD2EGA_FINALIZER_LIST_H
#define TD2EGA_FINALIZER_LIST_H
#include "td2ega_state_loop.h"
typedef struct td2ega_finalizer_request {
    uint16_t site,target_segment,target_ip,stack_segment,stack_sp;
    td2ega_state_registers incoming;
} td2ega_finalizer_request;
typedef int (*td2ega_finalizer_service)(void *,uint8_t *,
    const td2ega_finalizer_request *,td2ega_state_registers *);
typedef struct td2ega_finalizer_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t iterations,calls,bus_writes;
    td2ega_state_registers returned;
} td2ega_finalizer_result;
/*13A8:060D: unsignedSI<DI, DI-=4, rawwordORskip, actualfar[DS:DI]
 * call with fullreturnedGPR/BP/CFIFDF/SSframes, thenrepeat; rootnearRET2.
 * Native0rootnearreturn/1rawchildfarreturn/2invalid/3before-recordprefix/
 *4adapterfailure. Arbitrarycallbackbodies/lifetime/writers/actualdomains/core
 * remainopen; serviceABI and syntheticreturns notoriginalcalleeproof. */
void td2ega_finalizer_list(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    const td2ega_state_registers *,td2ega_finalizer_service,void *,uint32_t,
    td2ega_finalizer_result *);
#endif
