#ifndef TD2EGA_DIRECTORY_BATCH_H
#define TD2EGA_DIRECTORY_BATCH_H
#include "td2ega_directory.h"

typedef struct td2ega_directory_batch_result {
    uint16_t status, selector_offset, offset, segment, completed;
    uint32_t comparisons;
} td2ega_directory_batch_result;

/* Original16EB:000A required /004C optional list callers. Original DS is
 * the principal group for this admitted profile; SS frames are disjoint.
 * group supplies a64KiB near view plus adjacent byte for wordatFFFF.
 * Each invoked selector is a nonwrapping4-byte span; selector/output/source
 * aliases are retained through shared views. Native result is disjoint.
 * completed and selector_offset expose original local/caller-arg changes.
 */
void td2ega_directory_batch(const uint8_t *source, uint32_t source_bytes,
    uint16_t source_segment, uint16_t source_offset, uint8_t *group,
    uint32_t group_bytes, uint16_t selector_offset, uint16_t output_offset,
    uint16_t required, uint16_t incoming_ax, uint16_t incoming_dx,
    uint32_t max_selectors, uint32_t max_comparisons,
    td2ega_directory_batch_result *result);
#endif
