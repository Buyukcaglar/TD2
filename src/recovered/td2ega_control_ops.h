#ifndef TD2EGA_CONTROL_OPS_H
#define TD2EGA_CONTROL_OPS_H
#include "td2ega_sim_targets.h"
#include "td2ega_sim_primitives.h"

typedef struct td2ega_small_control_result {
    uint16_t status, target, di, direction;
    td2ega_sim_target_result registers;
} td2ega_small_control_result;

/* Complete near controls with full sharedgroup and disjoint result, serialized
 * field effects separate from original live stack/code. No physical units.
 * ScannerES may differ fromDS; its target table remains inDS and all selected
 * words must be44BF/44C5/44D2 for native admission. Unknown targets diagnose2.
 */
void td2ega_small_control_dispatch(uint8_t *group, const uint8_t *es_view,
    const td2ega_sim_target_result *incoming, uint16_t incoming_di,
    uint16_t incoming_direction, td2ega_small_control_result *result);
void td2ega_decelerate_target(uint8_t *group,
    const td2ega_sim_target_result *incoming, td2ega_sim_target_result *result);
void td2ega_decelerate_fixed(uint8_t *group,
    const td2ega_sim_target_result *incoming, td2ega_sim_target_result *result);
void td2ega_adjust_scaled_target(uint8_t *group,
    const td2ega_sim_target_result *incoming, td2ega_sim_target_result *result);
void td2ega_update_limit_counter(uint8_t *group,
    const td2ega_sim_target_result *incoming, td2ega_sim_target_result *result);
void td2ega_update_interval_state(uint8_t *group,
    const td2ega_sim_target_result *incoming, td2ega_sim_target_result *result);
#endif
