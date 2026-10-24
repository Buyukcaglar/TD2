#include "td2ega_cache_query.h"
#include "td2ega_filename.h"

/* Provenance: admitted TD2EGA image06C9:[7273,72C6).
 * Preserve the original early stop at the first status0 descriptor, byte-
 * sensitive name comparison and the special empty-cache sentinel check.
 * This is a query only, not the moving/acquiring operation at71B4.
 */
uint16_t td2ega_cache_name_present(const TD2EgaCacheEntry *entries,
                                 uint16_t entry_count, uint16_t first,
                                 uint16_t end, const uint8_t *name,
                                 uint32_t name_available)
{
    uint16_t base;
    uint16_t index = first;

    if (first > end || end >= entry_count ||
        !td2ega_basename_offset(name, name_available, &base)) {
        return UINT16_C(0);
    }
    do {
        uint16_t byte;
        int matched = 1;
        const TD2EgaCacheEntry *entry = &entries[index];
        if (entry->status == UINT16_C(0)) {
            return UINT16_C(0);
        }
        for (byte = 0; byte < UINT16_C(12); ++byte) {
            uint8_t requested = name[(uint32_t)base + byte];
            if (requested == UINT8_C(0)) {
                matched = entry->name[byte] == UINT8_C(0) ||
                          entry->name[byte] == UINT8_C(0x2e);
                break;
            }
            if (requested != entry->name[byte]) {
                matched = 0;
                break;
            }
        }
        if (matched) {
            return UINT16_C(1);
        }
        ++index;
    } while (index < end);
    return UINT16_C(0);
}
