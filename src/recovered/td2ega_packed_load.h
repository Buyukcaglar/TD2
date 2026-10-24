#ifndef TD2EGA_PACKED_LOAD_H
#define TD2EGA_PACKED_LOAD_H
#include "td2ega_named_raw.h"
#include "td2ega_prefix_stage.h"
#include "td2ega_run_stage.h"

typedef struct td2ega_packed_result {
    uint16_t status; /* 0 normal, 1 original fatal prefix, 2 native diagnostic */
    uint16_t stage; /* 0 acquire, 1 header, 2 allocate, 3 size, 4 raw, 5 codec */
    uint16_t acquire_event, allocation_event, offset, segment;
    uint16_t allocation_paragraphs, raw_segment, passes, last_codec;
    uint16_t final_si, final_di, codec_status;
    td2ega_metadata_result header, metadata;
    td2ega_raw_result raw;
} td2ega_packed_result;

/* Original6D50, serialized component contracts. DS=SS principal group for
 * header/codec scratch. Explicit seeds represent uninitialized original
 * header bytes and BP-0A; incomingSI/DI preserve the observed ADDSP8 shift.
 * Every actual source/read/output/copy must fit the admitted exclusive pool.
 * Native bounds/work/profile diagnostics do not model original failures.
 */
void td2ega_packed_load(TD2EgaCacheArena *arena, uint8_t *pool,
    uint32_t pool_bytes, uint16_t origin, const uint8_t *name,
    uint32_t name_available, uint16_t filename_segment, uint16_t filename_offset,
    td2ega_metadata_service metadata_service, td2ega_raw_service raw_service,
    void *context, const uint8_t header_seed[4], uint16_t local_seed,
    uint16_t incoming_si, uint16_t incoming_di, uint32_t max_reads,
    uint32_t codec_work_limit, td2ega_packed_result *result);
#endif
