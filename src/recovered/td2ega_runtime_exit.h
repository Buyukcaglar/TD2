#ifndef TD2EGA_RUNTIME_EXIT_H
#define TD2EGA_RUNTIME_EXIT_H
#include "td2ega_runtime_diagnostic.h"
#include "td2ega_runtime_vectors.h"
typedef struct td2ega_runtime_exit_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t operations,rows,services,callbacks,close_iterations,close_requests,bus_writes;
    td2ega_state_registers returned;
    td2ega_small_platform_request exit_request;
} td2ega_runtime_exit_result;
/*13A8:0599: twoactualempty060Dnearwalks, actual066Echecksum, fullAXtest/
 * optionalSSexitwordFF, raw15-count close loop, actual05E0nearcleanup, then
 * prepareINT21/AH4C. NoactualDOS exit andnoreturninvented afterrequest.
 * Native1rawchildreturn/2invalid/3budget/4adapter/5preparedprocess-exitboundary.
 * Actualcallee/target/writer/lifetime/FLAGS/core/runtime acceptance separate. */
void td2ega_runtime_exit(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    const td2ega_state_registers *,td2ega_small_platform_service,
    td2ega_finalizer_service,void *,uint32_t,td2ega_runtime_exit_result *);
#endif
