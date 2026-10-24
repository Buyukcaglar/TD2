#ifndef TD2EGA_PLANE_FILL_H
#define TD2EGA_PLANE_FILL_H
#include "td2ega_line_draw.h"
typedef struct td2ega_plane_fill_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t events,bytes,bus_writes;
    td2ega_state_registers returned;
} td2ega_plane_fill_result;
/* Actual06C9:840A far/oneSSwordfill/6byteOUTs/REP8000STOSB/incomingDF/fullSS.
 * Reuseskind1OUT/kind3devicebyteWrite adapter; ports/device effects preserve
 * GPR/flags, responseGPRignored. Adapterownsthedevicewrite; rawRAMfixture
 * writesq.address=q.value afterothermutations. No realEGA/rendereradmission.
 * All16bitSP/serialized20bitbus. Native0rootRET/2invalid/3eventbudget/
 * 4adapterfailure/5unqualifiedfarframeprefixbeforeRETwhenSP>FFFC.
 * Fullworkretainedforthoseinputs/nohistoricalCPUfaultclaim. Changedrootfar
 * wordswithboundedframe exposedafterRETneverfollowed. */
void td2ega_plane_fill(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    const td2ega_state_registers *,td2ega_line_draw_service,void *,
    uint32_t,td2ega_plane_fill_result *);
#endif
