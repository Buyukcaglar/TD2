#ifndef TD2EGA_THRESHOLD_TRANSITION_H
#define TD2EGA_THRESHOLD_TRANSITION_H
#include "td2ega_control_bus.h"
typedef struct td2ega_threshold_transition_limits {uint32_t rows,control_calls;} td2ega_threshold_transition_limits;
typedef struct td2ega_threshold_transition_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t rows,control_calls,bus_writes;
    uint16_t zero_flag,flags_valid;
    td2ega_state_registers returned;
} td2ega_threshold_transition_result;
/* Actual4B9A near/noargs/fullSS/currentDS/signedthresholds/indexed8byte
 * interpolation/actual45FC-4612. SP20..FFE0. rows caps4C3Eheads.
 * Native0rootRET/1rawcontrolRET/2invalid/3budget/4preIDIVfaultprefix.
 * NormalZF only; no wholecaller/writers-tablecapacity/lifetime/core proof. */
void td2ega_threshold_transition(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    const td2ega_state_registers *,const td2ega_threshold_transition_limits *,
    td2ega_threshold_transition_result *);
#endif
