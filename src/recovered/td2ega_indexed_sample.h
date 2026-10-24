#ifndef TD2EGA_INDEXED_SAMPLE_H
#define TD2EGA_INDEXED_SAMPLE_H
#include "td2ega_sample_adjust.h"
#include "td2ega_sim_primitives.h"
typedef struct td2ega_indexed_sample_limits {uint32_t guard_calls,sample_calls;td2ega_sample_adjust_limits child;} td2ega_indexed_sample_limits;
typedef struct td2ega_indexed_sample_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t guard_calls,sample_calls,child_calls,control_calls,bus_writes;
    uint16_t zero_flag,flags_valid;
    td2ega_state_registers returned;
} td2ega_indexed_sample_result;
/* Actual4C85 near/noargs/SP22..FFE0/currentDS/inline-or-ESwidth/
 * byteDIV5-keepsAHremainder/signedbyteIMUL50/actual4D26 andnear4A2E/
 * cachedprechildBP>=20 postchildstate2. Native0rootRET/1rawchildRET/
 * 2invalid/3budget; normalZFonly. No validobject-capacities/allwriters/
 * completecaller-sharedsource-IRQ-lifetime-core/resource/runtime acceptance. */
void td2ega_indexed_sample(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    const td2ega_state_registers *,const td2ega_indexed_sample_limits *,
    td2ega_indexed_sample_result *);
#endif
