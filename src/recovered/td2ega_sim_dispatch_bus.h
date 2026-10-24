#ifndef TD2EGA_SIM_DISPATCH_BUS_H
#define TD2EGA_SIM_DISPATCH_BUS_H
#include "td2ega_state_loop.h"

typedef struct td2ega_sim_dispatch_bus_result {
    uint16_t status, current_sp, next_segment, next_ip;
    uint32_t bus_writes;
    uint16_t zero_flag, flags_valid;
    td2ega_state_registers returned;
} td2ega_sim_dispatch_bus_result;

/* Entries 0..10: 4929,4947,494D,495D,499A,49C9,49CF,49D5,49DB,49E1,4A18.
 * Literal near bodies, current DS and independent SS; actual return word.
 * Input ZF is required for bodies that leave arithmetic flags unchanged.
 * Native 0 means an original RET operation, including changed coordinates;
 * 2 means invalid interface, before effects. SP 0..FFFE. Only CF/ZF/IF/DF
 * are admitted; the 491D target domain, owners and interrupt policy are open. */
void td2ega_sim_dispatch_bus(uint8_t *, uint32_t, uint16_t, uint16_t,
    uint16_t, uint16_t, const td2ega_state_registers *, uint16_t,
    td2ega_sim_dispatch_bus_result *);
#endif
