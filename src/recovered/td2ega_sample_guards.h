#ifndef TD2EGA_SAMPLE_GUARDS_H
#define TD2EGA_SAMPLE_GUARDS_H
#include "td2ega_sample_adjust.h"
#include "td2ega_sim_primitives.h"
typedef struct td2ega_sample_guards_limits {uint32_t guard_calls;td2ega_sample_adjust_limits sample;} td2ega_sample_guards_limits;
typedef struct td2ega_sample_guards_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t guard_calls,sample_calls,control_calls,bus_writes;
    uint16_t zero_flag,flags_valid;
    td2ega_state_registers returned;
} td2ega_sample_guards_result;
/* entry0=49E7/1=4A19, near/noargs/SP20..FFE0. Actual4D26SSframes,
 * frozen interval arithmetic and4A2E tail composition; global guard cap2/1.
 * Native0rootRET/1rawchildRET/2invalid/3budget. NormalZF only.
 * No actualcaller index/writer/IRQ/core/RNG-purpose/runtime acceptance. */
void td2ega_sample_guards(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,uint16_t,
    const td2ega_state_registers *,const td2ega_sample_guards_limits *,
    td2ega_sample_guards_result *);
#endif
