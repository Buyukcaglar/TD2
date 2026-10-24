#ifndef TD2EGA_VIEW_FILL_H
#define TD2EGA_VIEW_FILL_H
#include "td2ega_line_draw.h"
typedef struct td2ega_view_fill_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t work,planes,rows,ports,byte_writes,word_writes,bus_writes;
    td2ega_state_registers returned;
} td2ega_view_fill_result;
/* Actual843E/far/oneSScolorword/fullSS/currentCSgeometry/DFretained/
 * softwarepackedIMUL-lowword-wordSTOS/softwarerows-mutatingSScolor/
 * hardwareports-liveES/width40BYTE-MUL orliverowwidth-byteSTOS.
 * Work counts softwareplaneheads,rowheads,byteOUT1,byteWrite3,wordWrite4.
 * RawRAMadapterownsstoreeffects/preservesCPU/wordvaluefullAX.
 * Native0rootRET/2invalid/3workbudget/4adapter/5preRETqualification.
 * No allwriters-geometry-capacities-storage-lifetime-exclusion/realEGA/
 * latches-renderer/CPU-A20/core/resource/CGA/session/fidelity admission. */
void td2ega_view_fill(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    const td2ega_state_registers *,td2ega_line_draw_service,void *,
    uint32_t,td2ega_view_fill_result *);
#endif
