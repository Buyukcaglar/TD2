#ifndef TD2EGA_CACHE_ACQUIRE_H
#define TD2EGA_CACHE_ACQUIRE_H
#include "td2ega_cache_allocate.h"

enum TD2EgaCacheAcquireEvent {
    TD2EGA_CACHE_MISS = 0,
    TD2EGA_CACHE_ACQUIRED = 1,
    TD2EGA_CACHE_ACQUIRE_INVALID_NATIVE_INPUT = 2
};
/* Original71B4 moving acquisition under an admitted arena/pool contract.
 * Terminated nonwrapping name, arena, pool and output are disjoint/stable;
 * sentinels0/49, active_top<cached_first and all moves fit the external pool.
 * A match must select a real cached row, not the right sentinel. Enough
 * segment space and an interior descriptor must exist. Native diagnostic2
 * is outside original equivalence and may follow partial metadata changes.
 */
enum TD2EgaCacheAcquireEvent td2ega_cache_acquire(TD2EgaCacheArena *arena,
    uint8_t *pool, uint32_t pool_bytes, uint16_t origin,
    const uint8_t *name, uint32_t name_available, uint16_t *segment);
#endif
