#ifndef TD2EGA_CACHE_QUERY_H
#define TD2EGA_CACHE_QUERY_H

#include <stdint.h>

/* Internal metadata fields, never a direct overlay on original file bytes. */
typedef struct TD2EgaCacheEntry {
    uint8_t name[12];
    uint16_t paragraphs;
    uint16_t segment;
    uint16_t status;
} TD2EgaCacheEntry;

/* Original06C9:7273: readonly name/existence query.
 * entries supplies entry_count readable objects and remains stable during
 * the call. first<=end<entry_count; normally scan[first,end), but first=end
 * checks that sentinel once. A status0 entry aborts the search immediately.
 * name is a terminated, nonwrapping DOS byte span (see filename helper).
 * Returns1 on match,0 otherwise. Invalid native bounds/spans return0 as an
 * explicit diagnostic outside the admitted original-input contract.
 */
uint16_t td2ega_cache_name_present(const TD2EgaCacheEntry *entries,
                                 uint16_t entry_count, uint16_t first,
                                 uint16_t end, const uint8_t *name,
                                 uint32_t name_available);

#endif
