#ifndef TD2EGA_RUNTIME_VECTORS_H
#define TD2EGA_RUNTIME_VECTORS_H
#include "td2ega_small_platform.h"
#include "td2ega_finalizer_list.h"
typedef struct td2ega_runtime_vectors_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t operations,services,callbacks,bus_writes;
    td2ega_state_registers returned;
} td2ega_runtime_vectors_result;
/*13A8:05E0: optionalDS7076:7078farcall, saved-DS/LDS6D89/DOS2500,
 * restoredDS6DC6guard thenoptionalAL6DC7/LDS6DC8/DOS25. RootnearRET2.
 * ActualSS saves/frames, returnedDS/GPR/BP/CFIFDF andpostwritealiases retained.
 * Native0nearreturn/1rawchildfarreturn/2invalid/3beforeCALL-or-INT/4adapter.
 * NoactualDOS/vector/IRQ/session/core acceptance; writers/lifetime open. */
void td2ega_runtime_vectors(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    const td2ega_state_registers *,td2ega_small_platform_service,
    td2ega_finalizer_service,void *,uint32_t,td2ega_runtime_vectors_result *);
#endif
