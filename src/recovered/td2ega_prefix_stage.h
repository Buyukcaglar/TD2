#ifndef TD2EGA_PREFIX_STAGE_H
#define TD2EGA_PREFIX_STAGE_H
#include <stdint.h>

enum TD2EgaPrefixStageStatus {
    TD2EGA_PREFIX_STAGE_OK = 0,
    TD2EGA_PREFIX_STAGE_INVALID_TABLE = 1,
    TD2EGA_PREFIX_STAGE_INPUT_SHORT = 2,
    TD2EGA_PREFIX_STAGE_OUTPUT_SHORT = 3
};
typedef struct TD2EgaPrefixStageResult {
    uint32_t reported_bytes;
    uint32_t written_bytes;
    uint32_t consumed_bytes;
} TD2EgaPrefixStageResult;

/* Original7C16 bounded byte-producing stage, not a complete file loader.
 * Header/table prefix must not wrap the original near source offset; counts
 * fit16 table rows/256 symbols and every selected code resolves within them.
 * Actual original linear source/output ranges avoid physical/segment wrap,
 * live code/stack and shared scratch reentry. Native source/output may overlap
 * as original storage does; result is disjoint. Diagnostic statuses are native
 * bounds checks outside original error equivalence and may follow writes.
 * A declared lowword0 writes an extra65536 bytes before original termination;
 * reported_bytes still preserves the declared24-bit return value.
 */
enum TD2EgaPrefixStageStatus td2ega_prefix_stage(const uint8_t *source,
    uint32_t source_bytes, uint8_t *destination, uint32_t destination_bytes,
    TD2EgaPrefixStageResult *result);
#endif
