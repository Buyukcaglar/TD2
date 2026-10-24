#ifndef TD2EGA_SIM_CONTROLLER_H
#define TD2EGA_SIM_CONTROLLER_H
#include "td2ega_window_controllers.h"
#include "td2ega_threshold_transition.h"
#include "td2ega_indexed_sample.h"
#include "td2ega_sample_guards.h"
#include "td2ega_table_scalar.h"
#include "td2ega_sim_dispatch_bus.h"

typedef struct td2ega_sim_controller_limits {
    uint32_t iterations, rows, ring_calls, guard_calls, sample_calls,
             child_calls, control_calls, dispatch_calls;
} td2ega_sim_controller_limits;
typedef struct td2ega_sim_controller_result {
    uint16_t status, current_sp, next_segment, next_ip;
    uint32_t iterations, rows, ring_calls, guard_calls, sample_calls,
             child_calls, control_calls, dispatch_calls, direct_calls, bus_writes;
    uint16_t zero_flag, flags_valid, unresolved_target, reserved;
    td2ega_state_registers returned;
} td2ega_sim_controller_result;

/* Whole 06C9:4674 near body and actual reviewed callees, serialized 20bit RAM.
 * SP24..FFE0; current DS and inherited SS independent. Limits are cumulative:
 * iterations at46CA; rows at4735 and child4C3E; direct ring calls; guard calls;
 * actual parent near4A2E calls; nested4A2E children; inner4612; known491D calls.
 * Native0 original rootRET, 1 rawchildRET neverfollowed, 2 invalidbeforeeffects,
 * 3 budgetprefix, 4 beforechildIDIVfault, 6 unknown491Dtarget beforeCALL.
 * No validselector/allwriters/IRQ-exclusion/ownership/lifetime/core acceptance.
 */
void td2ega_sim_controller(uint8_t *, uint32_t, uint16_t, uint16_t, uint16_t,
    const td2ega_state_registers *, const td2ega_sim_controller_limits *,
    td2ega_sim_controller_result *);
#endif
