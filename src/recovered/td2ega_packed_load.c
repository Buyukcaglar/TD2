#include "td2ega_packed_load.h"
#include "td2ega_paragraph_copy.h"
#include <stddef.h>

static int coordinate(uint32_t bytes, uint16_t origin, uint16_t segment,
                      uint16_t offset, uint32_t *at)
{
    uint32_t physical = (uint32_t)segment * UINT32_C(16) + offset;
    uint32_t start = (uint32_t)origin * UINT32_C(16);
    if (physical < start || physical - start >= bytes) return 0;
    *at = physical - start;
    return 1;
}

void td2ega_packed_load(TD2EgaCacheArena *arena, uint8_t *pool,
    uint32_t pool_bytes, uint16_t origin, const uint8_t *name,
    uint32_t name_available, uint16_t filename_segment, uint16_t filename_offset,
    td2ega_metadata_service metadata_service, td2ega_raw_service raw_service,
    void *context, const uint8_t header_seed[4], uint16_t local_seed,
    uint16_t incoming_si, uint16_t incoming_di, uint32_t max_reads,
    uint32_t codec_work_limit, td2ega_packed_result *result)
{
    uint16_t segment = 0, source, source_offset = 0, remaining = 1;
    uint16_t allocated_segment, local = local_seed;
    uint32_t at, destination, count;
    enum TD2EgaCacheAcquireEvent acquired;
    enum TD2EgaCacheAllocateEvent allocated;
    if (result == NULL) return;
    *result = (td2ega_packed_result){0};
    result->status = 2;
    if (arena == NULL || pool == NULL || name == NULL || header_seed == NULL) return;
    acquired = td2ega_cache_acquire(arena, pool, pool_bytes, origin, name, name_available, &segment);
    result->acquire_event = (uint16_t)acquired;
    if (acquired == TD2EGA_CACHE_ACQUIRE_INVALID_NATIVE_INPUT) return;
    if (segment != 0) {
        result->segment = segment;
        result->final_si = incoming_si; result->final_di = incoming_di;
        result->status = 0; return;
    }
    result->stage = 1;
    td2ega_header_paragraphs(metadata_service, context, filename_offset, header_seed, &result->header);
    if (result->header.status != 0) { result->status = result->header.status; return; }
    result->allocation_paragraphs = (uint16_t)(result->header.paragraphs + UINT16_C(1));
    result->stage = 2;
    allocated = td2ega_cache_allocate(arena, name, name_available, result->allocation_paragraphs, &segment);
    result->allocation_event = (uint16_t)allocated;
    if (allocated != TD2EGA_CACHE_ALLOCATED) {
        result->status = allocated == TD2EGA_CACHE_INVALID_NATIVE_INPUT ? 2 : 1; return;
    }
    allocated_segment = segment;
    result->stage = 3;
    td2ega_file_paragraphs(metadata_service, context, filename_offset, &result->metadata);
    if (result->metadata.status != 0) { result->status = result->metadata.status; return; }
    source = (uint16_t)(allocated_segment + result->allocation_paragraphs - result->metadata.paragraphs);
    result->raw_segment = source;
    result->stage = 4;
    td2ega_raw_load(raw_service, context, filename_segment, filename_offset, 0, source, max_reads, &result->raw);
    if (result->raw.status != 0) { result->status = result->raw.status; return; }
    result->stage = 5;
    if (!coordinate(pool_bytes, origin, source, 0, &at)) return;
    if ((pool[at] & UINT8_C(0x80)) != 0) {
        remaining = (uint16_t)(pool[at] & UINT8_C(0x7f)); source_offset = 4;
    }
    for (;;) {
        uint8_t codec;
        if (!coordinate(pool_bytes, origin, source, source_offset, &at)) return;
        codec = pool[at];
        if (codec != UINT8_C(1) && codec != UINT8_C(2)) { result->status = 1; return; }
        result->last_codec = codec;
        if (codec == UINT8_C(1)) {
            TD2EgaRunStageResult decoded;
            enum TD2EgaRunStageStatus status = td2ega_run_stage(pool, pool_bytes, origin,
                source_offset, source, allocated_segment, result->allocation_paragraphs, codec_work_limit, &decoded);
            result->codec_status = (uint16_t)status;
            if (status != TD2EGA_RUN_STAGE_OK) return;
            result->offset = decoded.offset; result->segment = decoded.segment;
        } else {
            TD2EgaPrefixStageResult decoded;
            enum TD2EgaPrefixStageStatus status;
            if (!coordinate(pool_bytes, origin, allocated_segment, 0, &destination)) return;
            status = td2ega_prefix_stage(pool + at, pool_bytes - at,
                pool + destination, pool_bytes - destination, &decoded);
            result->codec_status = (uint16_t)status;
            if (status != TD2EGA_PREFIX_STAGE_OK) return;
            result->offset = (uint16_t)decoded.reported_bytes;
            result->segment = (uint16_t)(decoded.reported_bytes >> 16);
        }
        ++result->passes;
        remaining = (uint16_t)(remaining - UINT16_C(1));
        if (remaining == 0 || remaining >= UINT16_C(0x8000)) break;
        count = (uint32_t)result->offset | ((uint32_t)result->segment << 16);
        count = (count >> 4) + ((count & UINT32_C(15)) != 0 ? UINT32_C(1) : UINT32_C(0));
        local = (uint16_t)(allocated_segment + result->allocation_paragraphs - (uint16_t)count);
        if (!td2ega_paragraph_copy_backward(pool, pool_bytes, origin, allocated_segment, local, (uint16_t)count)) return;
        source = local; source_offset = 0;
    }
    result->final_di = incoming_si; result->final_si = local;
    result->status = 0;
}
