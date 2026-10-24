#ifndef TD2EGA_FALLBACK_MODE_H
#define TD2EGA_FALLBACK_MODE_H
#include "td2ega_small_platform.h"
#include "td2ega_line_draw.h"
typedef struct td2ega_fallback_mode_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t events,services,ports,words,bus_writes;
    td2ega_state_registers returned;
} td2ega_fallback_mode_result;
/* Actual06C9:5F64 withinEGAexe/far/noargs/BDA0040:0010/BIOS10AX0004/
 * 27byteOUTs/currentDS12byteCRTCtable/CLD-REP4000wordwrites/B800/fullSS.
 * BIOSfullreturnedstate/syntheticnoINTframes; kind1byteOUT/kind4deviceword
 * write adapterpreservesCPUstate, rawRAMadapterownslittleendianwordeffect.
 * All16bitSPbody; native0boundedRET/2invalid/3eventbudget/4adapterfailure/
 * 5unqualifiedfarframeprefixSP>FFFC. No CGAedition/hardware/rendereradmission. */
void td2ega_fallback_mode(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    const td2ega_state_registers *,td2ega_small_platform_service,void *,
    td2ega_line_draw_service,void *,uint32_t,td2ega_fallback_mode_result *);
#endif
