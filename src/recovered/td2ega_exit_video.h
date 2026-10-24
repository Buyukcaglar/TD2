#ifndef TD2EGA_EXIT_VIDEO_H
#define TD2EGA_EXIT_VIDEO_H
#include "td2ega_video_reset.h"
typedef struct td2ega_exit_video_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t calls,events,services,ports,bytes,words,bus_writes;
    td2ega_state_registers returned;
} td2ega_exit_video_result;
/* Actual5FBC/far/noargs/PUSHDI/currentDS5E6E. Zero:actual642E-840A;
 * nonzero:BDA0410/27byteOUT-currentDS12tablebytes/CLD-16384wordeffects/
 * BIOS10AX0007fullstate; actualPOPDI/plainfarRET. GlobalCALL-eventbudgets.
 * Typeddevicekind1byteOUT/3byteWrite/4wordWrite preservesCPU/rawRAMadapter.
 * Native0rootRET/1rawchildRET/2invalid/3budget/4adapter/5preRETqualification.
 * No actualROM/controller/renderer/CPU-A20/caller/core/session acceptance. */
void td2ega_exit_video(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    const td2ega_state_registers *,td2ega_small_platform_service,void *,
    td2ega_line_draw_service,void *,uint32_t,uint32_t,td2ega_exit_video_result *);
#endif
