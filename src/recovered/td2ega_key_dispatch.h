#ifndef TD2EGA_KEY_DISPATCH_H
#define TD2EGA_KEY_DISPATCH_H
#include <stdint.h>

typedef struct td2ega_key_registers { uint16_t ax, bx, cx, dx, interrupts_enabled, direction; } td2ega_key_registers;
typedef struct td2ega_key_request { uint16_t segment, offset; td2ega_key_registers registers; } td2ega_key_request;
typedef int (*td2ega_key_callback)(void *context, uint8_t *group,
    const td2ega_key_request *request, td2ega_key_registers *returned);
typedef struct td2ega_key_dispatch_result {
    uint16_t status, argument, called, callback_offset, callback_segment;
    td2ega_key_registers registers;
} td2ega_key_dispatch_result;

/* Complete6528 under explicit far-callback adapter profile. Full group is
 * stable/serialized and disjoint from active original stack/code/result.
 * Callback preserves original DS/SS/ES and far frame, may mutate group and
 * returned BX/CX/DX/IF/DF; original dispatcher restores its saved SI/DI.
 * original_callback_segment is relocated6C9. Adapter fault diagnostic is
 * outside original behavior and can retain the raised guard.
 */
void td2ega_key_dispatch(uint8_t *group, uint32_t group_bytes, uint16_t key,
    uint16_t original_callback_segment, const td2ega_key_registers *incoming,
    td2ega_key_callback callback, void *context, td2ega_key_dispatch_result *result);
#endif
