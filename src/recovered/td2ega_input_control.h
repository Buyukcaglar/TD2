#ifndef TD2EGA_INPUT_CONTROL_H
#define TD2EGA_INPUT_CONTROL_H
#include "td2ega_sim_targets.h"
#include "td2ega_mutable_control.h"
#include "td2ega_sim_primitives.h"
typedef struct td2ega_input_control_result {
    td2ega_sim_target_result registers;
    uint16_t bp;
    uint16_t status; /* 0 success, 2 unsupported native branch-form input. */
} td2ega_input_control_result;
/* Complete near4281/43C3 with actual4612/4441 native composition. Full shared
 * group, serialized field effects separate from original live stack/code and
 * disjoint native result. Register byte halves and indexed aliases retained.
 * 4281 clobbers original BP;43C3 preserves incoming BP. No physical units.
 */
/* code_state admits initial JA or prepared JNE at42AD explicitly. */
void td2ega_update_input_control(uint8_t *group,
    const td2ega_mutable_control *code_state,
    const td2ega_sim_target_result *incoming, uint16_t incoming_bp,
    td2ega_input_control_result *result);
void td2ega_advance_control_pair(uint8_t *group,
    const td2ega_sim_target_result *incoming, uint16_t incoming_bp,
    td2ega_input_control_result *result);
#endif
