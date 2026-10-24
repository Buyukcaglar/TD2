#ifndef TD2EGA_PLANE_ROWS_H
#define TD2EGA_PLANE_ROWS_H
#include "td2ega_plane_span.h"
typedef struct td2ega_plane_rows_result {
    uint16_t status,current_sp,next_ip;
    uint32_t calls,iterations,writes,continuations;
    td2ega_state_registers returned;
} td2ega_plane_rows_result;
/* Actual284F+0C17. status0RET2,1rawnonlocaltargetoutside28BD,
 *2invalid,3nativecallbudget. DS0702==28BD followsactualrow-advancepath;
 *otherrawtargets returnedexplicitly. No range/count normalization. */
void td2ega_plane_rows(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    const td2ega_state_registers *,uint32_t,td2ega_plane_rows_result *);
#endif
