#include "td2ega_find_nth.h"
#include <stddef.h>

static int32_t signed_word(uint16_t value)
{
    return value < UINT16_C(0x8000) ? (int32_t)value : (int32_t)value - INT32_C(65536);
}
void td2ega_find_nth(uint8_t *g, uint32_t bytes, uint16_t ds,
    uint16_t filename, uint16_t ordinal,
    const td2ega_sim_target_result *incoming, uint16_t es, uint16_t direction,
    td2ega_find_service service, void *context, uint32_t max_next_calls,
    td2ega_find_nth_result *r)
{
    td2ega_find_result found;
    uint16_t last;
    if (r == NULL) return;
    *r = (td2ega_find_nth_result){0}; r->status = 2;
    if (incoming == NULL) return;
    td2ega_find_first(g,bytes,ds,filename,incoming,es,direction,service,context,&found);
    r->registers = found.registers; r->es = found.es; r->direction = found.direction;
    if (found.status != 0) return;
    last = r->registers.ax; r->index = 1;
    for (;;) {
        r->registers.ax = ordinal;
        if (signed_word(r->index) >= signed_word(ordinal)) break;
        if (r->next_calls >= max_next_calls) return;
        td2ega_find_next(g,bytes,ds,&r->registers,r->es,r->direction,service,context,&found);
        r->registers = found.registers; r->es = found.es; r->direction = found.direction;
        ++r->next_calls;
        if (found.status != 0) return;
        last = r->registers.ax;
        if (last == 0) break;
        r->index = (uint16_t)(r->index + UINT16_C(1));
    }
    r->registers.ax = last; r->status = 0;
}
