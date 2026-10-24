#ifndef TD2EGA_VIDEO_INIT_H
#define TD2EGA_VIDEO_INIT_H
#include "td2ega_plane_fill.h"
#include "td2ega_small_platform.h"
typedef struct td2ega_video_init_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t calls,events,services,ports,bytes,bus_writes;
    td2ega_state_registers returned;
} td2ega_video_init_result;
/* Actual06C9:90E8 far/noargs/eightOUTs/actual840Aarg0/fullSS/BDA0410mask/
 * BIOS10AX000DthenAX1002/ESactualreturnedDS-DX6848/17byteBIOSinterface.
 * Globalshareddevice-BIOSeventbudget/CALLbudget distinct. AllSPbody,
 * native0boundedRET/1rawchildRET/2invalid/3budgets/4adapterfailure/
 * 5unqualifiedfourbytefarframebeforeRET/childqualificationpropagated.
 * No realBIOS/EGApalette-latch-renderer/CPU/caller/core/session acceptance. */
void td2ega_video_init(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    const td2ega_state_registers *,td2ega_small_platform_service,void *,
    td2ega_line_draw_service,void *,uint32_t,uint32_t,td2ega_video_init_result *);
#endif
