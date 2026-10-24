#include "td2ega_cache_compact.h"
#include "td2ega_paragraph_copy.h"

/* Provenance: admitted TD2EGA06C9:[7147,71B4). Sentinel is visited first.
 * Preserve status bit0, the uint16 accumulated hole sizes, descriptor write
 * order and backward payload copy. Old nonretained rows are not globally
 * cleared, and names/sizes outside the new cached boundary remain stale.
 */
int td2ega_cache_compact(TD2EgaCacheArena *arena, uint8_t *pool,
                        uint32_t pool_bytes, uint16_t origin)
{
    int32_t source_index = INT32_C(49);
    int32_t destination_index = INT32_C(49);
    uint16_t holes = UINT16_C(0);
    if (arena->cached_first == UINT16_C(0) ||
        arena->cached_first > UINT16_C(49) ||
        arena->active_top >= arena->cached_first ||
        (arena->entries[49].status & UINT16_C(1)) == UINT16_C(0) ||
        arena->entries[49].paragraphs != UINT16_C(0)) {
        return 0;
    }
    do {
        TD2EgaCacheEntry *source = &arena->entries[source_index];
        if ((source->status & UINT16_C(1)) == UINT16_C(0)) {
            holes = (uint16_t)(holes + source->paragraphs);
        } else {
            if (holes != UINT16_C(0)) {
                uint16_t size = source->paragraphs;
                uint16_t from = source->segment;
                uint16_t to = (uint16_t)(
                    arena->entries[destination_index + INT32_C(1)].segment - size);
                uint16_t status;
                uint16_t byte;
                TD2EgaCacheEntry *destination = &arena->entries[destination_index];
                destination->paragraphs = size;
                destination->segment = to;
                status = source->status;
                source->status = UINT16_C(0);
                destination->status = status;
                for (byte = UINT16_C(0); byte < UINT16_C(12); ++byte) {
                    destination->name[byte] = source->name[byte];
                }
                if (!td2ega_paragraph_copy_backward(pool, pool_bytes, origin,
                                                    from, to, size)) {
                    return 0;
                }
            }
            --destination_index;
        }
        --source_index;
    } while (source_index >= arena->cached_first);
    arena->cached_first = (uint16_t)(destination_index + INT32_C(1));
    return 1;
}
