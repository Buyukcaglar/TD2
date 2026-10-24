#include "td2ega_filename.h"

/* Instruction provenance: admitted TD2EGA image
 * 8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4,
 * module06C9:[7083,70A3). Only the algorithm is reconstructed here.
 * Near-pointer result AX becomes a relative byte offset in the C interface;
 * original filename bytes and all filesystem/media policy remain external.
 */
int td2ega_basename_offset(const uint8_t *name, uint32_t available,
                          uint16_t *offset)
{
    uint16_t after_separator = 0;
    uint32_t cursor;

    *offset = 0;
    if (available > UINT32_C(65536)) {
        return 0;
    }
    for (cursor = 0; cursor < available; ++cursor) {
        uint8_t byte = name[cursor];
        if (byte == UINT8_C(0)) {
            *offset = after_separator;
            return 1;
        }
        if (byte == UINT8_C(0x3a) || byte == UINT8_C(0x5c)) {
            /* A separator at65535 cannot have a following terminator within
             * the supported span. Truncation is defined; that case fails. */
            after_separator = (uint16_t)(cursor + UINT32_C(1));
        }
    }
    return 0;
}
