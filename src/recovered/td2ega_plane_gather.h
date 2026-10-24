#ifndef TD2EGA_PLANE_GATHER_H
#define TD2EGA_PLANE_GATHER_H
#include "td2ega_line_draw.h"
typedef struct td2ega_plane_gather_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t work,planes,ports,copies,rows,bus_writes;
    td2ega_state_registers returned;
} td2ega_plane_gather_result;
/* ActualAC40/far/SSmemberoffset-segment-x-y/fullSS/headerwrites/liveSSlocals/
 * DSA000/CLD/ESmember/headernibbles/currentCSselector/do-onceDEC-JGrows.
 * Work counts planeheads,rowheads,byteOUTkind1 andbyteCOPYkind7.
 * COPY args[sourceDS,SI,destES,DI,0]/addressdest/valueSourceSnapshot;
 * rawRAMadapterownsbyteeffects/preservesCPU. Native0rootRET/2invalid/
 * 3workbudget/4adapter/5preRETqualification. No memberformat-capacities/
 * allwriters-lifetime-exclusion/realreadmap-latches/renderer/CPU-A20/core/
 * resourcecodec/session/fidelity admission. */
void td2ega_plane_gather(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    const td2ega_state_registers *,td2ega_line_draw_service,void *,
    uint32_t,td2ega_plane_gather_result *);
#endif
