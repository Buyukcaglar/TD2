#ifndef TD2EGA_SIM_TARGETS_H
#define TD2EGA_SIM_TARGETS_H
#include <stdint.h>

typedef struct td2ega_sim_target_result { uint16_t ax, bx, cx, dx; } td2ega_sim_target_result;
/* Complete near entries412C/4441/4588. Full shared64KiB group, serialized
 * and disjoint from original stack/code and native result. External tables
 * remain caller-loaded bytes; the332A store precedes its indexed table read.
 * No original physical units are inferred from the numeric constants.
 */
void td2ega_update_sample_targets(uint8_t *group, uint16_t incoming_dx,
    td2ega_sim_target_result *result);
void td2ega_compare_target_delta(uint8_t *group, uint16_t incoming_bx,
    uint16_t incoming_cx, uint16_t incoming_dx, td2ega_sim_target_result *result);
void td2ega_adjust_target(uint8_t *group, uint16_t incoming_bx,
    uint16_t incoming_cx, uint16_t incoming_dx, td2ega_sim_target_result *result);
#endif
