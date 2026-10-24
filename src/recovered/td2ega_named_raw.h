#ifndef TD2EGA_NAMED_RAW_H
#define TD2EGA_NAMED_RAW_H
#include "td2ega_cache_acquire.h"
#include "td2ega_file_paragraphs.h"
#include "td2ega_raw_load.h"

typedef struct td2ega_named_raw_result {
    uint16_t status; /* 0 normal, 1 original fatal-prefix, 2 native diagnostic */
    uint16_t stage;  /* 0 acquire, 1 file size, 2 allocate, 3 raw read */
    uint16_t acquire_event, allocation_event, offset, segment;
    td2ega_metadata_result metadata;
    td2ega_raw_result raw;
} td2ega_named_raw_result;

/* Complete6D18 composition under component preconditions. Filename bytes,
 * arena, pool and result are valid/disjoint; services refer to the same
 * original filename coordinates. No stable pointer token survives moves. */
void td2ega_named_raw_load(TD2EgaCacheArena *arena, uint8_t *pool,
    uint32_t pool_bytes, uint16_t origin, const uint8_t *name,
    uint32_t name_available, uint16_t filename_segment, uint16_t filename_offset,
    td2ega_metadata_service metadata_service, td2ega_raw_service raw_service,
    void *context, uint32_t max_reads, td2ega_named_raw_result *result);
#endif
