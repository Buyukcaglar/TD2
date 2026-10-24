#include "td2ega_cache_acquire.h"
#include "td2ega_cache_compact.h"
#include "td2ega_filename.h"
#include "td2ega_paragraph_copy.h"

static int matches(const TD2EgaCacheEntry *entry, const uint8_t *name)
{
    uint16_t byte;
    for (byte = UINT16_C(0); byte < UINT16_C(12); ++byte) {
        uint8_t requested = name[byte];
        if (requested == UINT8_C(0)) {
            return entry->name[byte] == UINT8_C(0) ||
                   entry->name[byte] == UINT8_C(0x2e);
        }
        if (entry->name[byte] != requested) {
            return 0;
        }
    }
    return 1;
}

/* Provenance: admitted TD2EGA06C9:[71B4,7273). Query, move, evict, compact;
 * original source pointer is captured before its descriptor is overwritten.
 */
enum TD2EgaCacheAcquireEvent td2ega_cache_acquire(TD2EgaCacheArena *arena,
    uint8_t *pool, uint32_t pool_bytes, uint16_t origin,
    const uint8_t *name, uint32_t name_available, uint16_t *segment)
{
    uint16_t base;
    uint16_t index;
    uint16_t active;
    uint16_t source_segment;
    uint16_t destination_segment;
    uint16_t paragraphs;
    uint16_t end_segment;
    uint16_t byte;
    if (arena->active_top >= arena->cached_first ||
        arena->cached_first > UINT16_C(49) ||
        !td2ega_basename_offset(name, name_available, &base)) {
        return TD2EGA_CACHE_ACQUIRE_INVALID_NATIVE_INPUT;
    }
    index = arena->cached_first;
    do {
        if (arena->entries[index].status == UINT16_C(0)) {
            return TD2EGA_CACHE_MISS;
        }
        if (matches(&arena->entries[index], name + base)) {
            break;
        }
        ++index;
    } while (index < UINT16_C(49));
    if (index >= UINT16_C(49)) {
        /* A matching end sentinel is outside the admitted resource domain. */
        if (arena->cached_first == UINT16_C(49) &&
            matches(&arena->entries[49], name + base)) {
            return TD2EGA_CACHE_ACQUIRE_INVALID_NATIVE_INPUT;
        }
        return TD2EGA_CACHE_MISS;
    }
    active = (uint16_t)(arena->active_top + UINT16_C(1));
    if (active >= UINT16_C(49)) {
        return TD2EGA_CACHE_ACQUIRE_INVALID_NATIVE_INPUT;
    }
    source_segment = arena->entries[index].segment;
    paragraphs = arena->entries[index].paragraphs;
    destination_segment = (uint16_t)(arena->entries[arena->active_top].segment +
                                     arena->entries[arena->active_top].paragraphs);
    end_segment = (uint16_t)(destination_segment + paragraphs);
    if ((uint32_t)destination_segment + paragraphs > UINT32_C(0x10000) ||
        end_segment > arena->entries[49].segment) {
        return TD2EGA_CACHE_ACQUIRE_INVALID_NATIVE_INPUT;
    }
    arena->active_top = active;
    arena->entries[index].status = UINT16_C(0);
    arena->entries[active].segment = destination_segment;
    arena->entries[active].paragraphs = paragraphs;
    arena->entries[active].status = UINT16_C(2);
    for (byte = UINT16_C(0); byte < UINT16_C(12); ++byte) {
        arena->entries[active].name[byte] = arena->entries[index].name[byte];
    }
    if (active == arena->cached_first) {
        ++arena->cached_first;
    }
    if (!td2ega_paragraph_copy_forward(pool, pool_bytes, origin,
                                      source_segment, destination_segment, paragraphs)) {
        return TD2EGA_CACHE_ACQUIRE_INVALID_NATIVE_INPUT;
    }
    while (end_segment > arena->entries[arena->cached_first].segment) {
        arena->entries[arena->cached_first].status = UINT16_C(0);
        ++arena->cached_first;
    }
    if (!td2ega_cache_compact(arena, pool, pool_bytes, origin)) {
        return TD2EGA_CACHE_ACQUIRE_INVALID_NATIVE_INPUT;
    }
    *segment = arena->entries[active].segment;
    return TD2EGA_CACHE_ACQUIRED;
}
