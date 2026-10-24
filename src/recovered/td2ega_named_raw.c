#include "td2ega_named_raw.h"
#include <stddef.h>

void td2ega_named_raw_load(TD2EgaCacheArena *arena, uint8_t *pool,
    uint32_t pool_bytes, uint16_t origin, const uint8_t *name,
    uint32_t name_available, uint16_t filename_segment, uint16_t filename_offset,
    td2ega_metadata_service metadata_service, td2ega_raw_service raw_service,
    void *context, uint32_t max_reads, td2ega_named_raw_result *result)
{
    uint16_t segment = 0;
    enum TD2EgaCacheAcquireEvent acquired;
    enum TD2EgaCacheAllocateEvent allocated;
    if (result == NULL) return;
    *result = (td2ega_named_raw_result){0};
    result->status = 2;
    if (arena == NULL || pool == NULL || name == NULL) return;
    acquired = td2ega_cache_acquire(arena, pool, pool_bytes, origin,
                                   name, name_available, &segment);
    result->acquire_event = (uint16_t)acquired;
    if (acquired == TD2EGA_CACHE_ACQUIRE_INVALID_NATIVE_INPUT) return;
    /* Original OR DX,DX decides the early return, even if an acquire event
     * already changed ownership and returned segment zero. */
    if (segment != 0) {
        result->segment = segment;
        result->status = 0;
        return;
    }
    result->stage = 1;
    td2ega_file_paragraphs(metadata_service, context, filename_offset, &result->metadata);
    if (result->metadata.status != 0) {
        result->status = result->metadata.status;
        return;
    }
    result->stage = 2;
    allocated = td2ega_cache_allocate(arena, name, name_available,
                                     result->metadata.paragraphs, &segment);
    result->allocation_event = (uint16_t)allocated;
    if (allocated != TD2EGA_CACHE_ALLOCATED) {
        result->status = allocated == TD2EGA_CACHE_INVALID_NATIVE_INPUT ? 2 : 1;
        return;
    }
    result->stage = 3;
    td2ega_raw_load(raw_service, context, filename_segment, filename_offset,
                    0, segment, max_reads, &result->raw);
    result->status = result->raw.status;
    if (result->status == 0) {
        result->offset = result->raw.return_offset;
        result->segment = result->raw.return_segment;
    }
}
