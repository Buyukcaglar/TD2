#include "td2ega_sim_primitives.h"

static uint16_t word(const uint8_t *group, uint16_t offset)
{
    return (uint16_t)((uint16_t)group[offset] | ((uint16_t)group[(uint32_t)offset + 1] << 8));
}

static void store(uint8_t *group, uint16_t offset, uint16_t value)
{
    group[offset] = (uint8_t)value;
    group[(uint32_t)offset + 1] = (uint8_t)(value >> 8);
}

static int32_t signed_word(uint16_t value)
{
    return value < 32768 ? (int32_t)value : (int32_t)value - 65536;
}

void td2ega_sum_eight_samples(uint8_t *group)
{
    int32_t sum = 0;
    unsigned i;
    for (i = 0; i < 8; i++) {
        uint8_t value = group[0x335d + i];
        sum += value < 128 ? (int32_t)value : (int32_t)value - 256;
    }
    store(group, 0x30e4, (uint16_t)sum);
    store(group, 0x30e6, word(group, 0x52ce));
}

void td2ega_clamp_product_target(uint8_t *group, td2ega_product_result *result)
{
    uint32_t product;
    *result = (td2ega_product_result){0};
    if (group[0x2f56] == 0) return;
    result->applied = 1;
    result->old_target = word(group, 0x332c);
    group[0x2f5b] = 1;
    product = (uint32_t)word(group, 0x3328) * word(group, 0x52ce);
    result->product_low = (uint16_t)product;
    result->clamped_high = (uint16_t)(product >> 16);
    if (result->clamped_high < 0x320) result->clamped_high = 0x320;
    store(group, 0x332c, result->clamped_high);
}

uint16_t td2ega_signed_interval_overlap(uint16_t center, uint16_t radius,
                                        uint16_t minimum, uint16_t maximum,
                                        uint16_t *lower)
{
    uint16_t low = (uint16_t)(center - radius);
    uint16_t high = (uint16_t)(center + radius);
    *lower = low;
    return (uint16_t)(signed_word(low) <= signed_word(maximum) &&
                       signed_word(high) >= signed_word(minimum));
}

void td2ega_snapshot_stage_one(uint8_t *group)
{
    group[0x3371] = 1;
    if (word(group, 0x9410) == 0) return;
    store(group, 0x3356, word(group, 0x331e));
    store(group, 0x3358, word(group, 0x942e));
    group[0x33d5] = 1;
}

void td2ega_snapshot_stage_two(uint8_t *group)
{
    group[0x3371] = 2;
}

void td2ega_arm_transition_50(uint8_t *group, uint16_t record_base)
{
    if (word(group, 0x52da) == 0)
        store(group, 0x52da, (uint16_t)(record_base + 0x50u));
}

void td2ega_arm_transition_3c(uint8_t *group, uint16_t record_base)
{
    uint16_t sample, target;
    if (word(group, 0x52da) != 0) return;
    sample = word(group, 0x52ce);
    if (sample <= 0x3200) return;
    store(group, 0x3354, sample);
    target = (uint16_t)(record_base + 0x3cu);
    store(group, 0x52da, target);
    store(group, 0x52de, 0);
    group[0x33b7] = 8;
    /* Read AFTER preceding writes, retaining aliases into those fields. */
    store(group, 0x52dc, (group[target] & 0x80) != 0 ? 0x320 : 0x190);
}

void td2ega_update_curve_record(uint8_t *group, uint16_t input,
                                td2ega_curve_result *result)
{
    uint16_t half = (uint16_t)(input >> 1);
    uint16_t shifted = (uint16_t)(half - 0x16u);
    uint16_t scaled = (uint16_t)((uint32_t)shifted * 5u);
    uint16_t index = (uint16_t)((group[0x533e] + 0x45u) & 0x7f);
    uint8_t value;
    group[0x368a + index] = (uint8_t)scaled;
    value = group[(uint16_t)(0x37ddu + half)];
    group[0x370a + index] = value;
    result->index = index;
    result->half = half;
    result->shifted = shifted;
    result->mixed_word = (uint16_t)((scaled & 0xff00u) | value);
}

uint16_t td2ega_toggle_control_bit(uint8_t *group, uint16_t flag)
{
    uint16_t offset;
    if (flag > 2) return 2;
    offset = flag == 0 ? 0x37f7 : flag == 1 ? 0x37f6 : 0x37f8;
    group[offset] ^= 1;
    return 0;
}

void td2ega_raise_byte_threshold(uint8_t *group)
{
    group[0x337a] = (uint8_t)(group[0x337a] + 0x10u);
}

void td2ega_lower_byte_threshold(uint8_t *group)
{
    group[0x337a] = (uint8_t)(group[0x337a] - 0x10u);
}

void td2ega_clear_transition(uint8_t *group)
{
    store(group, 0x52da, 0);
    group[0x33b6] = 0;
    group[0x33b7] = 0;
    group[0x33b8] = 0;
    group[0x33ba] = 0;
}
