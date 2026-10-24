#ifndef TD2EGA_CACHE_DISCARD_H
#define TD2EGA_CACHE_DISCARD_H
#include "td2ega_cache_allocate.h"

enum TD2EgaCacheDiscardEvent {
    TD2EGA_CACHE_DISCARDED = 0,
    TD2EGA_CACHE_UNKNOWN_SEGMENT = 1,
    TD2EGA_CACHE_DISCARD_INVALID_NATIVE_INPUT = 2
};
/* Original7490 through normal return or external fatal-call boundary.
 * The original offset argument is ignored. Search includes free interior
 * rows, excludes the left sentinel and chooses the highest matching row.
 * A nonzero left-sentinel status bounds trimming. No payload is moved.
 */
enum TD2EgaCacheDiscardEvent td2ega_cache_discard(
    TD2EgaCacheArena *arena, uint16_t segment);
#endif
