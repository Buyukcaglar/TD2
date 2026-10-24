#ifndef TD2EGA_RUNTIME_WRAPPERS_H
#define TD2EGA_RUNTIME_WRAPPERS_H
#include "td2ega_scalar_state.h"
#include "td2ega_small_state.h"
typedef struct td2ega_runtime_wrappers_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t calls,bus_writes;
    td2ega_state_registers returned;
} td2ega_runtime_wrappers_result;
/*0=13A8:184A oneSSword, actual PUSHCS+nearCALL190E/RETF;
 *1=13A8:0DF0 oneSSnearrecord, actualfar2696/free-bit then ordered resets.
 * ActualSSframes/saves and returned childstate; minSP22/26 respectively.
 * Native0rootfarRET/1rawchild/2invalid/3beforechildCALL preparationboundary.
 * No host stream type/wholecaller/bounds/writer/lifetime/core acceptance. */
void td2ega_runtime_wrappers(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    uint16_t,const td2ega_state_registers *,uint32_t,td2ega_runtime_wrappers_result *);
#endif
