#ifndef TD2EGA_RUN_STAGE_H
#define TD2EGA_RUN_STAGE_H
#include <stdint.h>

enum TD2EgaRunStageStatus {
    TD2EGA_RUN_STAGE_OK = 0,
    TD2EGA_RUN_STAGE_INVALID_PROFILE = 1,
    TD2EGA_RUN_STAGE_OUT_OF_POOL = 2,
    TD2EGA_RUN_STAGE_WORK_LIMIT = 3
};
typedef struct TD2EgaRunStageResult {
    uint16_t offset;
    uint16_t segment;
    uint16_t source_argument_offset;
    uint16_t source_argument_segment;
    uint32_t first_stage_reported_bytes;
    uint32_t first_stage_writes;
    uint32_t final_stage_writes;
} TD2EgaRunStageResult;

/* Original6B02 bounded ordinary-memory contract, including6C6E/6B97/7030.
 * Original caller DS=SS, header prefix is nonwrapping, marker count1..11;
 * pool is stable/exclusive and disjoint from live code/stack/result. Every
 * original physical access/move must fit it. Result returns far0:destination
 * plus explicit argument-copy/count observations. Original destination offset
 * argument is ignored. Preserve16bit data-pointer wrap and counter effects.
 * Native profile/bounds/work diagnostics are outside original error behavior;
 * they can leave partial writes. work_limit bounds byte accesses/copy work.
 */
enum TD2EgaRunStageStatus td2ega_run_stage(uint8_t *pool, uint32_t pool_bytes,
    uint16_t origin, uint16_t source_offset, uint16_t source_segment,
    uint16_t destination_segment, uint16_t allocation_paragraphs,
    uint32_t work_limit, TD2EgaRunStageResult *result);
#endif
