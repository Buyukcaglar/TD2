#ifndef TD2EGA_PIXEL_POINT_H
#define TD2EGA_PIXEL_POINT_H
#include "td2ega_line_draw.h"
typedef struct td2ega_pixel_point_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t events,reads,writes,ports,bus_writes;
    td2ega_state_registers returned;
} td2ega_pixel_point_result;
/* ActualBA3C/far/SSx-y-colorwords/fullSS/currentCSrow-plane/currentDSmask.
 * Devicekinds:2byteRead(response.valuelow8),3byteWrite,5wordOUT,
 * 6byteORtransaction(value=DLmask). DeviceadapterpreservesCPU/rawRAMprofile.
 * Native0actualrootRET/2invalid/3eventbudget/4adapter/5preRETqualification.
 * No clipping/coordinate bounds, allwriters, latches/hardware/renderer,
 * historicalCPU-A20/caller-storage-exclusion/core/session gate. */
void td2ega_pixel_point(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    const td2ega_state_registers *,td2ega_line_draw_service,void *,
    uint32_t,td2ega_pixel_point_result *);
#endif
