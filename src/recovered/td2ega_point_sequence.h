#ifndef TD2EGA_POINT_SEQUENCE_H
#define TD2EGA_POINT_SEQUENCE_H
#include "td2ega_point_update.h"
typedef struct td2ega_point_sequence_limits {uint32_t calls;td2ega_point_update_limits update;} td2ega_point_sequence_limits;
typedef struct td2ega_point_sequence_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t calls,point_calls,events,reads,writes,ports,bus_writes;
    uint16_t zero_flag,flags_valid;
    td2ega_state_registers returned;
} td2ega_point_sequence_result;
/* Actual3A91/near/currentDS52CA-52D2-52DA/BX0-2-4/DX0C-09-0E/
 * threeactual3AB8-nearframes/BA3C-farframes/fullSS/globalCALL-devicebudgets.
 * All16SPbody/native0rootnearRET/1rawchild/2invalid/3budget/4adapter/
 * 5childqualification. flags_valid1onlyrootRET/ZFfromactuallastchild.
 * No caller-allwriters-coordinatebounds-storage-capacity-lifetime-exclusion/
 * hardwarelatch-renderer/CPU-A20/core/resource/session/fidelity admission. */
void td2ega_point_sequence(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    const td2ega_state_registers *,const td2ega_point_sequence_limits *,
    td2ega_line_draw_service,void *,td2ega_point_sequence_result *);
#endif
