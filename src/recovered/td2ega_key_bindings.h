#ifndef TD2EGA_KEY_BINDINGS_H
#define TD2EGA_KEY_BINDINGS_H
#include <stdint.h>

typedef struct td2ega_key_binding_result {
    uint16_t status, wrote, extended_read, write_offset, ax, bx;
} td2ega_key_binding_result;

typedef struct td2ega_key_install_result {
    uint16_t status, writes, ax, bx, dx;
} td2ega_key_install_result;

/* Original6585. Literal signed key comparison is retained: negative words
 * with nonzero lowbyte can write outside the intended table. The segment
 * argument is ignored by the original. Full group view and disjoint result;
 * serialized/exclusive storage, no active stack/code aliases.
 */
void td2ega_key_binding(uint8_t *group, uint32_t group_bytes, uint16_t key,
    uint16_t callback_offset, uint16_t callback_segment,
    td2ega_key_binding_result *result);

/* Complete16FC:0002, six small constant-key invocations of6585. */
void td2ega_key_install(uint8_t *group, uint32_t group_bytes,
    uint16_t original_callback_segment, td2ega_key_install_result *result);
#endif
