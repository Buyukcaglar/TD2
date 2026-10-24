#include "td2ega_input_poll.h"
#include <stddef.h>

static int begin(uint8_t *g, uint32_t bytes, const td2ega_input_services *s,
    const td2ega_key_registers *incoming, td2ega_input_result *r)
{
    if (r == NULL) return 0;
    *r = (td2ega_input_result){0}; r->status = 2;
    if (g == NULL || bytes < UINT32_C(65536) || s == NULL || incoming == NULL) return 0;
    r->registers = *incoming; return 1;
}
static int bios(const td2ega_input_services *s, uint16_t operation,
    td2ega_input_result *r, uint16_t *zero)
{
    td2ega_bios_key_request request;
    td2ega_bios_key_response response;
    r->registers.ax = (uint16_t)((r->registers.ax & UINT16_C(0xff)) | (operation << 8));
    request = (td2ega_bios_key_request){operation,r->registers.ax,
        r->registers.interrupts_enabled,r->registers.direction};
    if (s->bios == NULL || !s->bios(s->bios_context, &request, &response)) return 0;
    if (response.zero > 1 || response.interrupts_enabled > 1 || response.direction > 1) return 0;
    r->registers.ax = response.ax; *zero = response.zero;
    r->registers.interrupts_enabled = response.interrupts_enabled;
    r->registers.direction = response.direction;
    if (operation == 1) ++r->bios_probes; else ++r->bios_reads;
    return 1;
}
static int dispatch(uint8_t *g, uint32_t bytes, const td2ega_input_services *s,
    td2ega_input_result *r)
{
    td2ega_key_dispatch_result selected;
    r->dispatch_used = 1;
    td2ega_key_dispatch(g, bytes, r->registers.ax, s->callback_segment,
        &r->registers, s->callback, s->callback_context, &selected);
    r->registers = selected.registers; r->dispatch_argument = selected.argument;
    r->status = selected.status; return selected.status == 0;
}
static int port(uint8_t *g, uint32_t bytes, const td2ega_input_services *s,
    td2ega_input_result *r)
{
    td2ega_gameport_result sampled;
    r->gameport_used = 1;
    td2ega_gameport_sample(g, bytes, s->port, s->port_context,
        r->registers.bx,r->registers.cx,r->registers.dx,
        r->registers.interrupts_enabled,s->max_gameport_reads,&sampled);
    r->registers.ax = sampled.ax; r->registers.bx = sampled.bx;
    r->registers.cx = sampled.cx; r->registers.dx = sampled.dx;
    r->registers.interrupts_enabled = sampled.interrupts_enabled;
    r->gameport_reads = sampled.reads; r->status = sampled.status;
    return sampled.status == 0;
}
void td2ega_input_poll(uint8_t *g, uint32_t bytes,
    const td2ega_input_services *s, const td2ega_key_registers *incoming,
    td2ega_input_result *r)
{
    uint16_t zero;
    if (!begin(g,bytes,s,incoming,r) || !bios(s,1,r,&zero)) return;
    if (zero == 0) {
        if (!bios(s,0,r,&zero) || !dispatch(g,bytes,s,r)) return;
    } else {
        if (!port(g,bytes,s,r)) return;
        r->registers.bx = r->registers.ax;
        if ((r->registers.ax & UINT16_C(0x30)) != 0) r->registers.ax = UINT16_C(0xd);
        else {
            uint16_t at;
            r->registers.bx = (uint16_t)((r->registers.bx & UINT16_C(0xf)) * UINT16_C(2));
            at = (uint16_t)(UINT16_C(0x6254) + r->registers.bx);
            r->registers.ax = (uint16_t)((uint16_t)g[at] | ((uint16_t)g[(uint32_t)at + 1] << 8));
        }
        if (r->registers.ax == (uint16_t)((uint16_t)g[UINT16_C(0x6274)] |
            ((uint16_t)g[UINT16_C(0x6275)] << 8))) r->registers.ax = 0;
        else {
            g[UINT16_C(0x6274)] = (uint8_t)r->registers.ax;
            g[UINT16_C(0x6275)] = (uint8_t)(r->registers.ax >> 8);
        }
    }
    r->status = 0;
}
void td2ega_input_consume_if_stack_group(uint8_t *g, uint32_t bytes,
    const td2ega_input_services *s, const td2ega_key_registers *incoming,
    td2ega_input_result *r)
{
    uint16_t zero;
    if (!begin(g,bytes,s,incoming,r) || !bios(s,1,r,&zero)) return;
    if (zero != 0) r->registers.ax = 0;
    else {
        r->registers.bx = s->original_ss; r->registers.cx = s->original_ds;
        if (s->original_ss == s->original_ds) {
            if (!bios(s,0,r,&zero) || !dispatch(g,bytes,s,r)) return;
        }
    }
    r->status = 0;
}
void td2ega_input_direction_bits(uint8_t *g, uint32_t bytes,
    const td2ega_input_services *s, const td2ega_key_registers *incoming,
    td2ega_input_result *r)
{
    static const uint16_t at[10] = {0x62f3,0x62d6,0x6301,0x6302,0x6303,0x6307,0x630b,0x630a,0x6309,0x6305};
    static const uint16_t bits[10] = {0x10,0x20,9,1,5,4,6,2,10,8};
    uint16_t index;
    if (!begin(g,bytes,s,incoming,r)) return;
    r->registers.ax = 0;
    for (index = 0; index < UINT16_C(10); ++index) if (g[at[index]] != 0) r->registers.ax |= bits[index];
    if (r->registers.ax == 0 && !port(g,bytes,s,r)) return;
    r->status = 0;
}
