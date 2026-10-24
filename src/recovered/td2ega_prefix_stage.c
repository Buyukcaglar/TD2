#include "td2ega_prefix_stage.h"

/* Provenance: admitted TD2EGA06C9:[7C16,7D5E).
 * Keep16bit table arithmetic, last nonzero threshold, LSB-first input bits,
 * optional byte-delta accumulation and the original lowword-zero count edge.
 * Tables are local only under the admitted serialized/nonreentrant contract.
 */
enum TD2EgaPrefixStageStatus td2ega_prefix_stage(const uint8_t *source,
    uint32_t source_bytes, uint8_t *destination, uint32_t destination_bytes,
    TD2EgaPrefixStageResult *result)
{
    uint16_t offsets[16];
    uint16_t thresholds[16];
    uint8_t symbols[256];
    uint16_t lengths;
    uint16_t code_end = UINT16_C(0);
    uint16_t last_threshold = UINT16_C(0);
    uint16_t symbol_count = UINT16_C(0);
    uint16_t level;
    uint32_t cursor;
    uint32_t count;
    uint32_t written;
    uint8_t delta;
    uint8_t previous = UINT8_C(0);
    uint8_t bits = UINT8_C(0);
    uint8_t bits_left = UINT8_C(0);
    result->reported_bytes = UINT32_C(0);
    result->written_bytes = UINT32_C(0);
    result->consumed_bytes = UINT32_C(0);
    if (source_bytes < UINT32_C(5)) {
        return TD2EGA_PREFIX_STAGE_INPUT_SHORT;
    }
    result->reported_bytes = (uint32_t)source[1] |
        ((uint32_t)source[2] << 8) | ((uint32_t)source[3] << 16);
    lengths = (uint16_t)(source[4] & UINT8_C(0x7f));
    delta = (uint8_t)(source[4] & UINT8_C(0x80));
    if (lengths == UINT16_C(0) || lengths > UINT16_C(16)) {
        return TD2EGA_PREFIX_STAGE_INVALID_TABLE;
    }
    if (source_bytes - UINT32_C(5) < lengths) {
        return TD2EGA_PREFIX_STAGE_INPUT_SHORT;
    }
    for (level = UINT16_C(0); level < lengths; ++level) {
        uint16_t added = source[UINT32_C(5) + level];
        code_end = (uint16_t)(code_end * UINT16_C(2));
        offsets[level] = (uint16_t)(symbol_count - code_end);
        code_end = (uint16_t)(code_end + added);
        if (added != UINT16_C(0)) {
            last_threshold = code_end;
        }
        thresholds[level] = last_threshold;
        if (symbol_count + added > UINT16_C(256)) {
            return TD2EGA_PREFIX_STAGE_INVALID_TABLE;
        }
        symbol_count = (uint16_t)(symbol_count + added);
    }
    cursor = UINT32_C(5) + lengths;
    if (source_bytes - cursor < symbol_count) {
        return TD2EGA_PREFIX_STAGE_INPUT_SHORT;
    }
    for (level = UINT16_C(0); level < symbol_count; ++level) {
        symbols[level] = source[cursor + level];
    }
    cursor += symbol_count;
    count = result->reported_bytes;
    if ((count & UINT32_C(0xffff)) == UINT32_C(0)) {
        count += UINT32_C(0x10000);
    }
    if (count > destination_bytes) {
        return TD2EGA_PREFIX_STAGE_OUTPUT_SHORT;
    }
    for (written = UINT32_C(0); written < count; ++written) {
        uint16_t code = UINT16_C(0);
        uint16_t index = UINT16_C(0);
        int found = 0;
        for (level = UINT16_C(0); level < lengths; ++level) {
            if (bits_left == UINT8_C(0)) {
                if (cursor == source_bytes) {
                    result->consumed_bytes = cursor;
                    return TD2EGA_PREFIX_STAGE_INPUT_SHORT;
                }
                bits = source[cursor];
                ++cursor;
                bits_left = UINT8_C(8);
            }
            code = (uint16_t)((code * UINT16_C(2)) | (bits & UINT8_C(1)));
            bits = (uint8_t)(bits >> 1);
            --bits_left;
            if (code < thresholds[level]) {
                index = (uint16_t)(code + offsets[level]);
                found = 1;
                break;
            }
        }
        if (!found || index >= symbol_count) {
            result->consumed_bytes = cursor;
            return TD2EGA_PREFIX_STAGE_INVALID_TABLE;
        }
        previous = (uint8_t)(symbols[index] + (delta ? previous : UINT8_C(0)));
        destination[written] = previous;
        result->written_bytes = written + UINT32_C(1);
    }
    result->consumed_bytes = cursor;
    return TD2EGA_PREFIX_STAGE_OK;
}
