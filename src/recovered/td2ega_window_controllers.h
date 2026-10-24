#ifndef TD2EGA_WINDOW_CONTROLLERS_H
#define TD2EGA_WINDOW_CONTROLLERS_H
#include "td2ega_sample_adjust.h"
#include "td2ega_sim_primitives.h"
typedef struct td2ega_window_controllers_limits {uint32_t guard_calls,sample_calls;td2ega_sample_adjust_limits child;} td2ega_window_controllers_limits;
typedef struct td2ega_window_controllers_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t guard_calls,sample_calls,child_calls,control_calls,bus_writes;
    uint16_t zero_flag,flags_valid;
    td2ega_state_registers returned;
} td2ega_window_controllers_result;
/* entry0=4AFA/window-and-state, SP0..FFFE; entry1=4B5D/conditional
 * guard/sample, SP22..FFE0 ensuresactual4A2Echildentry20.
 * Actualnear frames/fullSS/frozeninterval andsample C; native0rootRET,
 * 1rawchildRET/2invalid/3budget; normalZFonly. No allwriters/fullcaller/
 * table-resource-capacity/sharedsource-IRQ-lifetime/core acceptance. */
void td2ega_window_controllers(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,uint16_t,
    const td2ega_state_registers *,const td2ega_window_controllers_limits *,
    td2ega_window_controllers_result *);
#endif
