#include "td2ega_cache_allocate.h"
#include "td2ega_filename.h"

/* Provenance: admitted TD2EGA06C9:[70A3,7147), plus7083 dependency.
 * Deliberately preserve unsigned16-bit segment addition and the descriptor
 * advance which does not clear the skipped cached status. This models only
 * the prefix up to the external fatal call on failure, not its cleanup.
 */
enum TD2EgaCacheAllocateEvent td2ega_cache_allocate(
    TD2EgaCacheArena *arena, const uint8_t *name, uint32_t available,
    uint16_t paragraphs, uint16_t *allocated_segment)
{
    uint16_t base;
    uint16_t next;
    uint16_t segment;
    uint16_t end_segment;
    uint16_t byte;
    TD2EgaCacheEntry *entry;
    if (arena->active_top >= UINT16_C(49) ||
        arena->cached_first <= arena->active_top ||
        arena->cached_first > UINT16_C(49) ||
        !td2ega_basename_offset(name, available, &base) ||
        (uint32_t)base + UINT32_C(12) > available) {
        return TD2EGA_CACHE_INVALID_NATIVE_INPUT;
    }
    segment = (uint16_t)(arena->entries[arena->active_top].segment +
                         arena->entries[arena->active_top].paragraphs);
    next = (uint16_t)(arena->active_top + UINT16_C(1));
    if (arena->cached_first <= next) {
        if (arena->cached_first == UINT16_C(49)) {
            return TD2EGA_CACHE_DESCRIPTOR_FAILURE;
        }
        ++arena->cached_first;
    }
    arena->active_top = next;
    entry = &arena->entries[next];
    for (byte = UINT16_C(0); byte < UINT16_C(12); ++byte) {
        entry->name[byte] = name[(uint32_t)base + byte];
    }
    entry->segment = segment;
    entry->paragraphs = paragraphs;
    entry->status = UINT16_C(2);
    end_segment = (uint16_t)(segment + paragraphs);
    while (end_segment > arena->entries[arena->cached_first].segment) {
        if (arena->cached_first == UINT16_C(49)) {
            return TD2EGA_CACHE_SEGMENT_FAILURE;
        }
        arena->entries[arena->cached_first].status = UINT16_C(0);
        ++arena->cached_first;
    }
    *allocated_segment = segment;
    return TD2EGA_CACHE_ALLOCATED;
}
