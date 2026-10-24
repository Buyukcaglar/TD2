#ifndef TD2EGA_PLANE_BYTE_COPY_H
#define TD2EGA_PLANE_BYTE_COPY_H
#include "td2ega_line_draw.h"
typedef struct td2ega_plane_byte_copy_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t work,ports,copies,rows,bus_writes;
    td2ega_state_registers returned;
} td2ega_plane_byte_copy_result;
/* ActualC784/far/sixSSwords/fullSSlocals/in-placeSAR3source-destX/
 * SAR3width/currentCSrow-plane-strides/DSA000/CLD/fourplanes/do-oncerows.
 * Work counts rowheads, byteOUT(kind1), byteCOPY(kind7). COPY arguments:
 * [sourceDS,sourceSI,destinationES,destinationDI,0], address=destination,
 * value=raw source snapshot. Adapterownsbyteeffect/preservesCPUstate.
 * Native0rootRET/2invalid/3workbudget/4adapter/5preRETqualification.
 * No clipping, capacities/allwriters/realdevice-selector-latches/renderer,
 * historicalCPU-A20/caller-storage-exclusion/core/session acceptance. */
void td2ega_plane_byte_copy(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    const td2ega_state_registers *,td2ega_line_draw_service,void *,
    uint32_t,td2ega_plane_byte_copy_result *);
#endif
