#ifndef TD2EGA_BYTE_RING_H
#define TD2EGA_BYTE_RING_H

#include <stdint.h>

/* FN-EGA-000003: instruction contract recovered; higher-level purpose unknown.
 * This state contains caller-loaded bytes, never original game data in code.
 * Not integrated into a playable game core.
 */
typedef struct TD2EgaByteRing {
    uint16_t cursor;
    uint8_t bytes[256];
} TD2EgaByteRing;

/* Requires a valid non-null state. Returns the updated byte, zero extended. */
uint16_t td2ega_byte_ring_step(TD2EgaByteRing *state);

#endif
