#ifndef TD2EGA_PARAGRAPH_COPY_H
#define TD2EGA_PARAGRAPH_COPY_H
#include <stdint.h>

/* External byte pool, not original executable instructions or file overlay.
 * origin is the original segment represented by pool[0]. Source/destination
 * paragraph ranges must not wrap a segment word or leave the supplied pool.
 * The pool is disjoint from live code, stack and API metadata. Direction is
 * semantically significant even for an unsafe overlap; no memmove choice is
 * made automatically. Returns1 on admitted bounds,0 without writes otherwise.
 * Native status diagnostics are separate from the original register result.
 */
int td2ega_paragraph_copy_forward(uint8_t *pool, uint32_t pool_bytes,
    uint16_t origin, uint16_t source, uint16_t destination,
    uint16_t paragraphs);
int td2ega_paragraph_copy_backward(uint8_t *pool, uint32_t pool_bytes,
    uint16_t origin, uint16_t source, uint16_t destination,
    uint16_t paragraphs);
#endif
