#ifndef TD2EGA_PLANE_SHIFT_STRIP_H
#define TD2EGA_PLANE_SHIFT_STRIP_H
#include "td2ega_line_draw.h"
typedef struct td2ega_plane_shift_strip_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t work,ports,copies,rows,planes,loads,reads,writes,bus_writes;
    td2ega_state_registers returned;
} td2ega_plane_shift_strip_result;
/* ActualAE62/fullSS/eightSSwords/x-y-width-height-stride-memberoff-seg-index/
 * DSA000-ESA000/CLD/firstREP-COPY/do-onceDECJGrows/optionalmemberbyteMULs/
 * zero-nibblewholeexit/secondLODS-read-write/LOOPwidth0wrap/globalwork.
 * Work counts rowheads,planeheads,byteOUT1,COPY7,LODS,byteRead2,byteWrite3.
 * COPY args[sourceDS,SI,destES,DI,0]/addressdest/valueSourceSnapshot.
 * RawRAMadapterownsbyteeffects/preservesCPU. Native0rootRET/2invalid/
 * 3workbudget/4adapter/5preRETqualification. No format-capacities-allwriters/
 * storage-lifetime-exclusion/realEGA-latches-renderer/CPU-A20/core/resource/
 * CGA/session/fidelity admission. */
void td2ega_plane_shift_strip(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    const td2ega_state_registers *,td2ega_line_draw_service,void *,
    uint32_t,td2ega_plane_shift_strip_result *);
#endif
