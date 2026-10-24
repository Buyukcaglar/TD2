#ifndef TD2EGA_STATE_TICK_BUS_H
#define TD2EGA_STATE_TICK_BUS_H
#include "td2ega_sample_fields_bus.h"
#include "td2ega_input_update_bus.h"
#include "td2ega_control_controllers.h"
#include "td2ega_field_controller.h"
#include "td2ega_secondary_fields.h"
#include "td2ega_sim_controller.h"
#include "td2ega_mode_controller.h"
#include "td2ega_record_controller.h"
#include "td2ega_pair_controller.h"

typedef struct td2ega_state_tick_bus_limits {
    uint32_t root_calls,control_calls,control_nested_calls,math_calls,
             math_iterations,mode_calls,mode_nested_calls,mode_iterations,
             record_steps,record_calls,pair_calls;
    td2ega_sim_controller_limits simulation;
    td2ega_input_poll_bus_limits input;
} td2ega_state_tick_bus_limits;
typedef struct td2ega_state_tick_bus_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t root_calls,bus_writes;
    uint16_t stage,raw_target,mode_exit_kind,reserved;
    td2ega_state_registers returned;
} td2ega_state_tick_bus_result;
/* WIP whole06C9:403B/far/noargs withactualSS/componentbodies. SP46..FFE0
 * coversroot8savedbytes+nearCALL2+modechild36. PUSHDS-ES-DI-BP before
 * principalDS-ES assignment, currentSS untouched; actualsavedwords restored.
 * Native0rootRETFactualcoordinates/1rawchildneverfollowed/2invalid/
 * 3budget/otherchildprefix statuses preserved withstage/raw_target metadata.
 * Limits arepercomponentinvocation, root_calls countsown11possibleCALLs.
 * 53A6exit_kind1 alreadyretiresnonlocalPOPAX/RET to403B; neveraddanotherRET.
 * Incomingunused420Aarithbits materializedonlyafterfirstCMP livenessproof;
 * motionfullFLAGS stillfeedactual6601INT16frame withinthatcomponent.
 * NoactualIRQ/writer-lifetime/complete-state-machine/core/gameacceptance.
 */
void td2ega_state_tick_bus(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    const td2ega_state_registers *,const td2ega_mutable_control *,
    const td2ega_state_tick_bus_limits *,const td2ega_input_poll_bus_services *,
    td2ega_state_tick_bus_result *);
#endif
