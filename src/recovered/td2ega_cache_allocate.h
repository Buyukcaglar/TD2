#ifndef TD2EGA_CACHE_ALLOCATE_H
#define TD2EGA_CACHE_ALLOCATE_H
#include "td2ega_cache_query.h"

#define TD2EGA_CACHE_ENTRIES 50
typedef struct TD2EgaCacheArena {
    TD2EgaCacheEntry entries[TD2EGA_CACHE_ENTRIES];
    uint16_t active_top;
    uint16_t cached_first;
} TD2EgaCacheArena;

enum TD2EgaCacheAllocateEvent {
    TD2EGA_CACHE_ALLOCATED = 0,
    TD2EGA_CACHE_DESCRIPTOR_FAILURE = 1,
    TD2EGA_CACHE_SEGMENT_FAILURE = 2,
    TD2EGA_CACHE_INVALID_NATIVE_INPUT = 3
};

/* Metadata-only original70A3 contract. arena/name/output must be disjoint.
 * Name must terminate without wrapping and supply twelve bytes at basename.
 * A failure event preserves the original mutations before the fatal call;
 * no cleanup, payload allocation or DOS action is performed here.
 * allocated_segment is written only on success. Zero offset is implicit.
 */
enum TD2EgaCacheAllocateEvent td2ega_cache_allocate(
    TD2EgaCacheArena *arena, const uint8_t *name, uint32_t available,
    uint16_t paragraphs, uint16_t *allocated_segment);
#endif
