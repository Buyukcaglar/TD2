#include "td2ega_cache_discard.h"

/* Provenance: admitted TD2EGA06C9:[7490,74D4). */
enum TD2EgaCacheDiscardEvent td2ega_cache_discard(
    TD2EgaCacheArena *arena, uint16_t segment)
{
    uint16_t index;
    if (arena->active_top >= UINT16_C(49) ||
        arena->entries[0].status == UINT16_C(0)) {
        return TD2EGA_CACHE_DISCARD_INVALID_NATIVE_INPUT;
    }
    index = arena->active_top;
    while (index != UINT16_C(0)) {
        if (arena->entries[index].segment == segment) {
            arena->entries[index].status = UINT16_C(0);
            if (index == arena->active_top) {
                do {
                    --index;
                } while (arena->entries[index].status == UINT16_C(0));
                arena->active_top = index;
            }
            return TD2EGA_CACHE_DISCARDED;
        }
        --index;
    }
    return TD2EGA_CACHE_UNKNOWN_SEGMENT;
}
