#ifndef TD2EGA_SIM_PRIMITIVES_H
#define TD2EGA_SIM_PRIMITIVES_H
#include <stdint.h>

/* Compatibility data view only: no original instructions are stored/executed.
 * Requires valid64KiB data and disjoint field/stack/result writes. The curve
 * helper uses original BP-based SS stores and therefore requires DS=SS.
 * Field names remain provisional; numeric arithmetic comes from instructions. */
typedef struct td2ega_product_result {
    uint16_t applied, product_low, clamped_high, old_target;
} td2ega_product_result;
typedef struct td2ega_curve_result {
    uint16_t index, half, shifted, mixed_word;
} td2ega_curve_result;

void td2ega_sum_eight_samples(uint8_t *group);
void td2ega_clamp_product_target(uint8_t *group, td2ega_product_result *result);
uint16_t td2ega_signed_interval_overlap(uint16_t center, uint16_t radius,
                                        uint16_t minimum, uint16_t maximum,
                                        uint16_t *lower);
void td2ega_snapshot_stage_one(uint8_t *group);
void td2ega_snapshot_stage_two(uint8_t *group);
void td2ega_arm_transition_50(uint8_t *group, uint16_t record_base);
void td2ega_arm_transition_3c(uint8_t *group, uint16_t record_base);
void td2ega_update_curve_record(uint8_t *group, uint16_t input,
                                td2ega_curve_result *result);
/* flag0/1/2 map original37F7/37F6/37F8. Returns2 for invalid native selector. */
uint16_t td2ega_toggle_control_bit(uint8_t *group, uint16_t flag);
void td2ega_raise_byte_threshold(uint8_t *group);
void td2ega_lower_byte_threshold(uint8_t *group);
void td2ega_clear_transition(uint8_t *group);
#endif
