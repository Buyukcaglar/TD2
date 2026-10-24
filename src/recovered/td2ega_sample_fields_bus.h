#ifndef TD2EGA_SAMPLE_FIELDS_BUS_H
#define TD2EGA_SAMPLE_FIELDS_BUS_H
#include "td2ega_state_loop.h"
typedef struct td2ega_sample_fields_bus_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t bus_writes;
    uint16_t zero_flag,flags_valid;
    td2ega_state_registers returned;
} td2ega_sample_fields_bus_result;
/* Additional fullSS near interfaces: 0=412C,1=4639. CurrentDS fields and
 * actualSS rootword; no own saves/args/calls. SP0..FFFE. Native0 reportsRET
 * operation/actualcoordinates;2 invalidbeforeeffects. CFZFIFDF explicit.
 * Prior group APIs remain separately bounded. No whole403B/IRQ/core admission. */
void td2ega_sample_fields_bus(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    uint16_t,const td2ega_state_registers *,td2ega_sample_fields_bus_result *);
#endif
