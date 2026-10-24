#include "td2ega_directory_batch.h"
#include <stddef.h>

static void store_word(uint8_t *group, uint16_t offset, uint16_t value)
{
    group[offset] = (uint8_t)value;
    group[(uint32_t)offset + UINT32_C(1)] = (uint8_t)(value >> 8);
}

void td2ega_directory_batch(const uint8_t *source, uint32_t source_bytes,
    uint16_t source_segment, uint16_t source_offset, uint8_t *group,
    uint32_t group_bytes, uint16_t selector_offset, uint16_t output_offset,
    uint16_t required, uint16_t incoming_ax, uint16_t incoming_dx,
    uint32_t max_selectors, uint32_t max_comparisons,
    td2ega_directory_batch_result *result)
{
    uint32_t invocations = 0;
    if (result == NULL) return;
    *result = (td2ega_directory_batch_result){0};
    result->status = 2; result->selector_offset = selector_offset;
    result->offset = incoming_ax; result->segment = incoming_dx;
    if (source == NULL || group == NULL || group_bytes < UINT32_C(65537)) return;
    while (group[result->selector_offset] != 0) {
        uint16_t at;
        td2ega_directory_result selected;
        if (invocations >= max_selectors || result->selector_offset > UINT16_C(0xfffc)) return;
        ++invocations;
        td2ega_directory_find(source, source_bytes, source_segment, source_offset,
            group + result->selector_offset, required, max_comparisons, &selected);
        result->comparisons += selected.comparisons;
        if (selected.status != 0) { result->status = selected.status; return; }
        at = (uint16_t)(output_offset + (uint16_t)(result->completed * UINT16_C(4)));
        result->completed = (uint16_t)(result->completed + UINT16_C(1));
        result->offset = selected.offset; result->segment = selected.segment;
        store_word(group, at, selected.offset);
        store_word(group, (uint16_t)(at + UINT16_C(2)), selected.segment);
        result->selector_offset = (uint16_t)(result->selector_offset + UINT16_C(4));
    }
    result->status = 0;
}
