#include "td2ega_key_dispatch.h"
#include <stddef.h>

void td2ega_key_dispatch(uint8_t *g, uint32_t group_bytes, uint16_t key,
    uint16_t original_callback_segment, const td2ega_key_registers *incoming,
    td2ega_key_callback callback, void *context, td2ega_key_dispatch_result *r)
{
    uint16_t index, at;
    td2ega_key_request request;
    td2ega_key_registers returned;
    if (r == NULL) return;
    *r = (td2ega_key_dispatch_result){0}; r->status = 2; r->argument = key;
    if (g == NULL || group_bytes < UINT32_C(65536) || incoming == NULL) return;
    r->registers = *incoming;
    /* CLI precedes either guard path; both paths execute STI. */
    r->registers.interrupts_enabled = 0;
    if (g[UINT16_C(0x6252)] != 0) {
        r->registers.interrupts_enabled = 1; r->status = 0; return;
    }
    g[UINT16_C(0x6252)] = 1;
    r->registers.interrupts_enabled = 1;
    if ((key & UINT16_C(0xff)) != 0) {
        index = (uint16_t)(key & UINT16_C(0x7f)); r->argument = index;
        at = (uint16_t)(UINT16_C(0x6048) + index * UINT16_C(2));
    } else {
        index = (uint16_t)(key >> 8);
        if (index > UINT16_C(0x84)) index = UINT16_C(0x84);
        at = (uint16_t)(UINT16_C(0x6148) + index * UINT16_C(2));
    }
    r->registers.bx = (uint16_t)((uint16_t)g[at] | ((uint16_t)g[(uint32_t)at + 1] << 8));
    if (r->registers.bx == 0) {
        r->registers.ax = r->argument; g[UINT16_C(0x6252)] = 0;
        r->status = 0; return;
    }
    r->callback_offset = r->registers.bx; r->callback_segment = original_callback_segment;
    r->registers.ax = original_callback_segment;
    request = (td2ega_key_request){original_callback_segment, r->callback_offset, r->registers};
    if (callback == NULL || !callback(context, g, &request, &returned)) return;
    r->called = 1; r->registers = returned;
    r->registers.ax = 0; g[UINT16_C(0x6252)] = 0; r->status = 0;
}
