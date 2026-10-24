#ifndef TD2EGA_VIDEO_RESET_H
#define TD2EGA_VIDEO_RESET_H
#include "td2ega_plane_fill.h"
#include "td2ega_small_platform.h"
typedef struct td2ega_video_reset_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t calls,events,services,ports,bytes,bus_writes;
    td2ega_state_registers returned;
} td2ega_video_reset_result;
/* Actual06C9:642E far/noargs/XORAX-PUSH0/actual840A/fullSS-currentDF/
 * BDA0410mask/BIOS10AX0003fullstate thenAH0B-retainAL-BX0/fullstate.
 * Shareddevice-BIOSeventbudget/CALLbudget distinct. Native0boundedRET/
 * 1rawchildRET/2invalid/3budget/4adapter/5preRETqualification.
 * No actualROM-device-controller/renderer/CPU/core/session acceptance. */
void td2ega_video_reset(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    const td2ega_state_registers *,td2ega_small_platform_service,void *,
    td2ega_line_draw_service,void *,uint32_t,uint32_t,td2ega_video_reset_result *);
#endif
