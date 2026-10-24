#include "td2ega_paragraph_copy.h"

static int valid_ranges(uint32_t pool_bytes, uint16_t origin,
    uint16_t source, uint16_t destination, uint16_t paragraphs)
{
    uint32_t source_end = (uint32_t)source + paragraphs;
    uint32_t destination_end = (uint32_t)destination + paragraphs;
    uint32_t pool_origin = (uint32_t)origin * UINT32_C(16);
    uint32_t pool_end;
    if (pool_bytes > UINT32_C(0x100000) - pool_origin) {
        return 0;
    }
    pool_end = pool_origin + pool_bytes;
    return source >= origin &&
           destination >= origin && source_end <= UINT32_C(0x10000) &&
           destination_end <= UINT32_C(0x10000) &&
           source_end * UINT32_C(16) <= pool_end &&
           destination_end * UINT32_C(16) <= pool_end;
}

/* Original06C9:[6FE8,7030): REP MOVSW chunks, ascending word order. */
int td2ega_paragraph_copy_forward(uint8_t *pool, uint32_t pool_bytes,
    uint16_t origin, uint16_t source, uint16_t destination,
    uint16_t paragraphs)
{
    uint32_t from;
    uint32_t to;
    uint32_t left;
    if (!valid_ranges(pool_bytes, origin, source, destination, paragraphs)) {
        return 0;
    }
    from = ((uint32_t)source - origin) * UINT32_C(16);
    to = ((uint32_t)destination - origin) * UINT32_C(16);
    left = (uint32_t)paragraphs * UINT32_C(8);
    while (left != UINT32_C(0)) {
        uint8_t low = pool[from];
        uint8_t high = pool[from + UINT32_C(1)];
        pool[to] = low;
        pool[to + UINT32_C(1)] = high;
        from += UINT32_C(2);
        to += UINT32_C(2);
        --left;
    }
    return 1;
}

/* Original06C9:[7030,7083): STD/REP MOVSW chunks, descending word order.
 * Within the admitted nonwrapping pool, chunk boundaries change segment
 * registers but not the linear sequence of source/destination word pairs.
 */
int td2ega_paragraph_copy_backward(uint8_t *pool, uint32_t pool_bytes,
    uint16_t origin, uint16_t source, uint16_t destination,
    uint16_t paragraphs)
{
    uint32_t from;
    uint32_t to;
    uint32_t left;
    if (!valid_ranges(pool_bytes, origin, source, destination, paragraphs)) {
        return 0;
    }
    from = ((uint32_t)source - origin + paragraphs) * UINT32_C(16);
    to = ((uint32_t)destination - origin + paragraphs) * UINT32_C(16);
    left = (uint32_t)paragraphs * UINT32_C(8);
    while (left != UINT32_C(0)) {
        uint8_t low;
        uint8_t high;
        from -= UINT32_C(2);
        to -= UINT32_C(2);
        low = pool[from];
        high = pool[from + UINT32_C(1)];
        pool[to] = low;
        pool[to + UINT32_C(1)] = high;
        --left;
    }
    return 1;
}
