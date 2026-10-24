#include "td2ega_directory.h"
#include <stddef.h>

static int word(const uint8_t *source, uint32_t bytes, uint16_t offset, uint16_t *value)
{
    if ((uint32_t)offset + UINT32_C(2) > bytes) return 0;
    *value = (uint16_t)((uint16_t)source[offset] | ((uint16_t)source[(uint32_t)offset + 1] << 8));
    return 1;
}

void td2ega_directory_find(const uint8_t *source, uint32_t source_bytes,
    uint16_t source_segment, uint16_t source_offset, uint8_t selector[4],
    uint16_t required, uint32_t max_comparisons, td2ega_directory_result *result)
{
    uint16_t count, original_count, record, index = 0;
    uint16_t byte;
    if (result == NULL) return;
    *result = (td2ega_directory_result){0};
    result->status = 2;
    if (source == NULL || selector == NULL) return;
    for (byte = 0; byte < UINT16_C(4); ++byte) {
        if (selector[byte] == 0) {
            do { selector[byte++] = UINT8_C(0x20); } while (byte < UINT16_C(4));
            break;
        }
    }
    if (!word(source, source_bytes, (uint16_t)(source_offset + UINT16_C(4)), &count)) return;
    record = (uint16_t)(source_offset + UINT16_C(6));
    for (;;) {
        int matches = 1;
        if (result->comparisons >= max_comparisons) return;
        ++result->comparisons;
        for (byte = 0; byte < UINT16_C(4); ++byte) {
            uint16_t at = (uint16_t)(record + byte);
            uint8_t value;
            if ((uint32_t)at >= source_bytes) return;
            value = source[at];
            if (value != selector[byte]) {
                matches = value == 0 && selector[byte] == UINT8_C(0x20);
                break;
            }
        }
        if (matches) {
            uint16_t low, high;
            uint16_t size, table;
            uint32_t physical;
            /* Reread after selector publication/comparison as original does. */
            if (!word(source, source_bytes, (uint16_t)(source_offset + UINT16_C(4)), &original_count)) return;
            table = (uint16_t)(record + (uint16_t)(original_count * UINT16_C(4)));
            if (!word(source, source_bytes, table, &low) ||
                !word(source, source_bytes, (uint16_t)(table + UINT16_C(2)), &high)) return;
            size = (uint16_t)((uint16_t)(original_count * UINT16_C(8)) + UINT16_C(6));
            /* The original adds source_segment*16 and size, then a32-bit
             * relative value. It does not add source_offset to this base. */
            physical = (uint32_t)source_segment * UINT32_C(16) + size;
            physical += (uint32_t)low | ((uint32_t)high << 16);
            result->offset = (uint16_t)(physical & UINT32_C(15));
            result->segment = (uint16_t)(physical >> 4);
            result->matched_index = index; result->found = 1;
            result->status = 0; return;
        }
        record = (uint16_t)(record + UINT16_C(4));
        ++index;
        /* DEC/JGE uses SF==OF, including the8000->7FFF overflow case.
         * Continuation is equivalent to old signed count >0. */
        if (count == 0 || count >= UINT16_C(0x8000)) break;
        count = (uint16_t)(count - UINT16_C(1));
    }
    result->status = required != 0 ? 1 : 0;
}
