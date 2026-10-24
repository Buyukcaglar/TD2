#include "td2ega_key_bindings.h"
#include <stddef.h>

void td2ega_key_binding(uint8_t *group, uint32_t group_bytes, uint16_t key,
    uint16_t callback_offset, uint16_t callback_segment,
    td2ega_key_binding_result *result)
{
    uint16_t index;
    (void)callback_segment;
    if (result == NULL) return;
    *result = (td2ega_key_binding_result){0};
    result->status = 2; result->ax = callback_offset; result->bx = key;
    if (group == NULL || group_bytes < UINT32_C(65536)) return;
    result->status = 0;
    if ((key & UINT16_C(0xff)) != 0) {
        /* CMP BX,007F / JG is signed, not an unsigned range check. */
        if (key <= UINT16_C(0x7f) || key >= UINT16_C(0x8000)) {
            index = (uint16_t)(key * UINT16_C(2));
            result->bx = index;
            result->write_offset = (uint16_t)(UINT16_C(0x6048) + index);
            group[result->write_offset] = (uint8_t)callback_offset;
            group[(uint32_t)result->write_offset + 1] = (uint8_t)(callback_offset >> 8);
            result->wrote = 1;
        }
    } else {
        result->bx = (uint16_t)(key >> 8);
        if (result->bx <= UINT16_C(0x84)) {
            /* This path reads a fixed extended slot; it does not bind it. */
            result->bx = (uint16_t)((uint16_t)group[UINT16_C(0x624c)] |
                ((uint16_t)group[UINT16_C(0x624d)] << 8));
            result->extended_read = 1;
        }
    }
}

void td2ega_key_install(uint8_t *group, uint32_t group_bytes,
    uint16_t original_callback_segment, td2ega_key_install_result *result)
{
    static const uint16_t keys[6] = {0x0a, 0x0b, 0x10, 0x11, 0x13, 0x18};
    static const uint16_t offsets[6] = {0x645a, 0x646f, 0x6508, 0x64c7, 0x6488, 0x6518};
    uint16_t index;
    if (result == NULL) return;
    *result = (td2ega_key_install_result){0}; result->status = 2;
    if (group == NULL || group_bytes < UINT32_C(65536)) return;
    for (index = 0; index < UINT16_C(6); ++index) {
        td2ega_key_binding_result bound;
        td2ega_key_binding(group, group_bytes, keys[index], offsets[index], original_callback_segment, &bound);
        result->writes = (uint16_t)(result->writes + bound.wrote);
        result->ax = bound.ax; result->bx = bound.bx;
    }
    result->dx = original_callback_segment; result->status = 0;
}
