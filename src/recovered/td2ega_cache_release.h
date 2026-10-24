#ifndef TD2EGA_CACHE_RELEASE_H
#define TD2EGA_CACHE_RELEASE_H
#include "td2ega_cache_allocate.h"

typedef struct TD2EgaFarStorage {
    uint16_t offset;
    uint16_t segment;
} TD2EgaFarStorage;
enum TD2EgaCacheReleaseEvent {
    TD2EGA_CACHE_RELEASED = 0,
    TD2EGA_CACHE_RELEASE_UNKNOWN_SEGMENT = 1,
    TD2EGA_CACHE_RELEASE_INVALID_NATIVE_INPUT = 2
};
/* Original72C6 and736B prefixes through normal return or external fatal call.
 * Stable exclusively owned50row arena, nonzero leftsentinel, active<cached,
 * and every generated move must fit the disjoint external byte pool. Output
 * is disjoint from arena/pool. Native diagnostic2 can follow partial changes.
 * Fast policy can return a new cached segment; shifting policy always returns
 * segment0, even when it caches the block. Both preserve the supplied offset.
 */
enum TD2EgaCacheReleaseEvent td2ega_cache_release_fast(TD2EgaCacheArena *arena,
    uint8_t *pool, uint32_t pool_bytes, uint16_t origin,
    uint16_t offset, uint16_t segment, TD2EgaFarStorage *result);
enum TD2EgaCacheReleaseEvent td2ega_cache_release_shift(TD2EgaCacheArena *arena,
    uint8_t *pool, uint32_t pool_bytes, uint16_t origin,
    uint16_t offset, uint16_t segment, TD2EgaFarStorage *result);
#endif
