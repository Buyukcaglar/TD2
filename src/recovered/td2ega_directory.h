#ifndef TD2EGA_DIRECTORY_H
#define TD2EGA_DIRECTORY_H
#include <stdint.h>

typedef struct td2ega_directory_result {
    uint16_t status; /* 0 normal, 1 required-name fatal prefix, 2 native bounds/work */
    uint16_t found, offset, segment, matched_index;
    uint32_t comparisons;
} td2ega_directory_result;

/* Original6E4E optional /6E59 required, one native entry with explicit policy.
 * source is the ordinary physical window at original source_segment:0.
 * It supplies every actual original near-offset byte/word access. A word at
 * FFFF may use byte10000 when source_bytes permits it. Four selector bytes
 * are a nonwrapping original group view, potentially aliasing source.
 * result is disjoint; source/selector storage is exclusive/serialized.
 * Explicit work/bounds diagnostics do not represent original error paths.
 */
void td2ega_directory_find(const uint8_t *source, uint32_t source_bytes,
    uint16_t source_segment, uint16_t source_offset, uint8_t selector[4],
    uint16_t required, uint32_t max_comparisons, td2ega_directory_result *result);
#endif
