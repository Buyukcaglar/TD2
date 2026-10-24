#ifndef TD2EGA_FILENAME_H
#define TD2EGA_FILENAME_H

#include <stdint.h>

/* FN-EGA-000181, 06C9:7083: byte-oriented DOS basename scan.
 * name points to available readable bytes; offset is a valid output pointer.
 * Supported original-contract inputs terminate within a nonwrapping16-bit
 * span. Returns1 and the relative position after the last ':' or '\\'.
 * Offset0 is valid. No case folding or forward-slash normalization occurs.
 * Returns0/offset0 on missing terminator or a span larger than64KiB; this is
 * an explicit native diagnostic outside the admitted original-input domain.
 */
int td2ega_basename_offset(const uint8_t *name, uint32_t available,
                          uint16_t *offset);

#endif
