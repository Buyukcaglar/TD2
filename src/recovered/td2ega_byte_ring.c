#include "td2ega_byte_ring.h"

/* Source: TD2EGA image sha256 8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4
 * Module-relative 06C9:780E, image range [0xE49E,0xE4BB).
 * CMP AL,0x80 supplies carry to RCL: the incoming bit is 1 for old<128.
 * The new interface exposes observed AX. Original C return type/use is unknown.
 * See docs/recovery/td2ega-byte-ring.md for contract and validation scope.
 */
uint16_t td2ega_byte_ring_step(TD2EgaByteRing *state)
{
    uint32_t decremented = (uint32_t)state->cursor - UINT32_C(1);
    state->cursor = (uint16_t)decremented;
    uint16_t index = (uint16_t)(state->cursor & UINT16_C(0x00ff));
    uint8_t before = state->bytes[index];
    uint8_t after = (uint8_t)(((uint32_t)before << 1) |
                            (before < UINT8_C(0x80) ? UINT32_C(1) : UINT32_C(0)));
    state->bytes[index] = after;
    return (uint16_t)after;
}
