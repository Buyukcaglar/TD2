#ifndef TD2EGA_CACHE_COMPACT_H
#define TD2EGA_CACHE_COMPACT_H
#include "td2ega_cache_allocate.h"

/* Original7147 cache-side compaction. Status bit0 determines retention.
 * Sentinel49 has odd status and size0; 0<cached_first<=49, with active_top
 * below it. Every generated move must fit the external paragraph pool and
 * avoid live code/stack/metadata. Arena and pool are exclusively owned.
 * Returns1 on completion. Native bounds diagnostic0 is outside original
 * equivalence and may follow partial metadata changes; it is not rollback.
 */
int td2ega_cache_compact(TD2EgaCacheArena *arena, uint8_t *pool,
                        uint32_t pool_bytes, uint16_t origin);
#endif
