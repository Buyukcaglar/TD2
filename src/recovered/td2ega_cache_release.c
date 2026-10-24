#include "td2ega_cache_release.h"
#include "td2ega_paragraph_copy.h"

static int valid_arena(const TD2EgaCacheArena *arena)
{
    return arena->active_top < arena->cached_first &&
           arena->cached_first <= UINT16_C(49) &&
           arena->entries[0].status != UINT16_C(0);
}
static uint16_t find_segment(const TD2EgaCacheArena *arena, uint16_t segment)
{
    uint16_t index = arena->active_top;
    while (index != UINT16_C(0) && arena->entries[index].segment != segment) {
        --index;
    }
    return index;
}
static void trim_top(TD2EgaCacheArena *arena, uint16_t index)
{
    if (index == arena->active_top) {
        do {
            --index;
        } while (arena->entries[index].status == UINT16_C(0));
        arena->active_top = index;
    }
}
static void copy_name(TD2EgaCacheEntry *destination,
                      const TD2EgaCacheEntry *source)
{
    uint16_t byte;
    for (byte = UINT16_C(0); byte < UINT16_C(12); ++byte) {
        destination->name[byte] = source->name[byte];
    }
}

/* Original06C9:[72C6,736B). */
enum TD2EgaCacheReleaseEvent td2ega_cache_release_fast(TD2EgaCacheArena *arena,
    uint8_t *pool, uint32_t pool_bytes, uint16_t origin,
    uint16_t offset, uint16_t segment, TD2EgaFarStorage *result)
{
    uint16_t index;
    uint16_t returned_segment = UINT16_C(0);
    uint16_t gap;
    if (!valid_arena(arena)) {
        return TD2EGA_CACHE_RELEASE_INVALID_NATIVE_INPUT;
    }
    index = find_segment(arena, segment);
    if (index == UINT16_C(0)) {
        return TD2EGA_CACHE_RELEASE_UNKNOWN_SEGMENT;
    }
    arena->entries[index].status = UINT16_C(0);
    gap = (uint16_t)(arena->entries[arena->cached_first].segment -
                    arena->entries[arena->active_top].segment -
                    arena->entries[arena->active_top].paragraphs);
    if (index == arena->active_top || gap >= arena->entries[index].paragraphs) {
        uint16_t size = arena->entries[index].paragraphs;
        uint16_t from = arena->entries[index].segment;
        uint16_t destination = (uint16_t)(arena->cached_first - UINT16_C(1));
        returned_segment = (uint16_t)(arena->entries[arena->cached_first].segment - size);
        arena->cached_first = destination;
        arena->entries[destination].segment = returned_segment;
        arena->entries[destination].paragraphs = size;
        arena->entries[destination].status = UINT16_C(1);
        copy_name(&arena->entries[destination], &arena->entries[index]);
        if (!td2ega_paragraph_copy_backward(pool, pool_bytes, origin,
                                            from, returned_segment, size)) {
            return TD2EGA_CACHE_RELEASE_INVALID_NATIVE_INPUT;
        }
    }
    trim_top(arena, index);
    result->offset = offset;
    result->segment = returned_segment;
    return TD2EGA_CACHE_RELEASED;
}

/* Original06C9:[736B,7490). Preserve strict gap>size, all status values when
 * shifting rows, late source-segment read and original DX0 after caching.
 */
enum TD2EgaCacheReleaseEvent td2ega_cache_release_shift(TD2EgaCacheArena *arena,
    uint8_t *pool, uint32_t pool_bytes, uint16_t origin,
    uint16_t offset, uint16_t segment, TD2EgaFarStorage *result)
{
    uint16_t index;
    uint16_t gap;
    if (!valid_arena(arena)) {
        return TD2EGA_CACHE_RELEASE_INVALID_NATIVE_INPUT;
    }
    index = find_segment(arena, segment);
    if (index == UINT16_C(0)) {
        return TD2EGA_CACHE_RELEASE_UNKNOWN_SEGMENT;
    }
    arena->entries[index].status = UINT16_C(0);
    gap = (uint16_t)(arena->entries[49].segment -
                    arena->entries[arena->active_top].segment -
                    arena->entries[arena->active_top].paragraphs);
    if (index == arena->active_top || gap > arena->entries[index].paragraphs) {
        uint16_t active_end = (uint16_t)(arena->entries[arena->active_top].segment +
                                         arena->entries[arena->active_top].paragraphs);
        uint16_t row = arena->cached_first;
        int shifted = 0;
        while (row != UINT16_C(49)) {
            uint16_t to = (uint16_t)(arena->entries[row].segment -
                                     arena->entries[index].paragraphs);
            uint16_t destination = (uint16_t)(row - UINT16_C(1));
            if (active_end <= to && destination != arena->active_top) {
                uint16_t size;
                uint16_t from;
                if (!shifted) {
                    arena->cached_first = destination;
                    shifted = 1;
                }
                arena->entries[destination].status = arena->entries[row].status;
                arena->entries[destination].paragraphs = arena->entries[row].paragraphs;
                size = arena->entries[row].paragraphs;
                arena->entries[destination].segment = to;
                from = arena->entries[row].segment;
                copy_name(&arena->entries[destination], &arena->entries[row]);
                if (!td2ega_paragraph_copy_forward(pool, pool_bytes, origin,
                                                   from, to, size)) {
                    return TD2EGA_CACHE_RELEASE_INVALID_NATIVE_INPUT;
                }
            }
            ++row;
        }
        {
            uint16_t size = arena->entries[index].paragraphs;
            uint16_t to = (uint16_t)(arena->entries[49].segment - size);
            uint16_t from;
            if (!shifted) {
                arena->cached_first = UINT16_C(48);
            }
            arena->entries[48].paragraphs = size;
            arena->entries[48].segment = to;
            /* Original7455 reads source after7451 wrote destination. This
             * aliases when the released row itself is48; do not snapshot it
             * earlier or replace the resulting identity copy by assumption.
             */
            from = arena->entries[index].segment;
            arena->entries[48].status = UINT16_C(1);
            copy_name(&arena->entries[48], &arena->entries[index]);
            if (!td2ega_paragraph_copy_backward(pool, pool_bytes, origin,
                                                from, to, size)) {
                return TD2EGA_CACHE_RELEASE_INVALID_NATIVE_INPUT;
            }
        }
    }
    trim_top(arena, index);
    result->offset = offset;
    result->segment = UINT16_C(0);
    return TD2EGA_CACHE_RELEASED;
}
