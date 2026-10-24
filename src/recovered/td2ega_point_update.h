#ifndef TD2EGA_POINT_UPDATE_H
#define TD2EGA_POINT_UPDATE_H
#include "td2ega_pixel_point.h"
typedef struct td2ega_point_update_limits {uint32_t calls,events;} td2ega_point_update_limits;
typedef struct td2ega_point_update_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t calls,events,reads,writes,ports,bus_writes;
    uint16_t zero_flag,flags_valid;
    td2ega_state_registers returned;
} td2ega_point_update_result;
/* Actual3AB8/near/registerSI-BX-DX/signedSUB-JGE/SAR5/currentDS2F50+BX/
 * literalold-newpixel SSframes/actualBA3C/globalCALL-eventbudgets.
 * Native0rootnearRET/1rawchildRET/2invalid/3budget/4adapter/5childqualification.
 * flags_valid1onlyrootRET/requiredZF; all16SPbody, childquadqualification.
 * No coordinate bounds/allwriters-device-latches-storage-lifetime-exclusion/
 * CPU-A20/core/renderer/resource/session/fidelity admission. */
void td2ega_point_update(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    const td2ega_state_registers *,const td2ega_point_update_limits *,
    td2ega_line_draw_service,void *,td2ega_point_update_result *);
#endif
