#include "td2ega_find_files.h"
#include <stddef.h>

static uint16_t word(const uint8_t *g, uint16_t at)
{
    return (uint16_t)((uint16_t)g[at] | ((uint16_t)g[(uint32_t)at + 1] << 8));
}
static void put_word(uint8_t *g, uint16_t at, uint16_t value)
{
    g[at] = (uint8_t)value; g[(uint32_t)at + 1] = (uint8_t)(value >> 8);
}
static int service_call(uint8_t *g, uint16_t ds, uint16_t operation,
    td2ega_find_service service, void *context, td2ega_find_result *r, uint16_t *carry)
{
    td2ega_find_request request = {operation,r->registers.ax,r->registers.cx,
        r->registers.dx,ds,0x5dee,g+UINT16_C(0x5dee)};
    td2ega_find_response response;
    if (service == NULL || !service(context,&request,&response)) return 0;
    r->registers.ax = response.ax; *carry = response.carry; return 1;
}
static void replace_name(uint8_t *g, uint16_t ds, td2ega_find_result *r)
{
    uint16_t index, destination = word(g,UINT16_C(0x5dec));
    r->replacement_offset = destination; r->es = ds; r->direction = 0;
    for (index = 0; index < UINT16_C(13); ++index) {
        uint8_t value = g[UINT16_C(0x5e0c)+index];
        g[destination] = value; destination = (uint16_t)(destination + UINT16_C(1));
    }
    r->registers.cx = 0; r->registers.ax = UINT16_C(0x5d88);
    r->found = 1; r->status = 0;
}
static int begin(uint8_t *g, uint32_t bytes, const td2ega_sim_target_result *incoming,
    uint16_t es, uint16_t direction, td2ega_find_result *r)
{
    if (r == NULL) return 0;
    *r = (td2ega_find_result){0}; r->status = 2;
    if (g == NULL || bytes < UINT32_C(65536) || incoming == NULL) return 0;
    r->registers = *incoming; r->es = es; r->direction = direction; return 1;
}
void td2ega_find_first(uint8_t *g, uint32_t bytes, uint16_t ds,
    uint16_t filename, const td2ega_sim_target_result *incoming,
    uint16_t es, uint16_t direction, td2ega_find_service service, void *context,
    td2ega_find_result *r)
{
    uint16_t carry, source = filename, destination = UINT16_C(0x5d88);
    if (!begin(g,bytes,incoming,es,direction,r)) return;
    r->registers.dx = UINT16_C(0x5dee);
    r->registers.ax = (uint16_t)((r->registers.ax & UINT16_C(0xff)) | UINT16_C(0x1a00));
    if (!service_call(g,ds,0,service,context,r,&carry)) return;
    r->registers.dx = filename;
    r->registers.cx = (uint16_t)((r->registers.cx & UINT16_C(0xff00)) | UINT16_C(6));
    r->registers.ax = (uint16_t)((r->registers.ax & UINT16_C(0xff)) | UINT16_C(0x4e00));
    if (!service_call(g,ds,1,service,context,r,&carry)) return;
    if (carry != 0) { r->registers.ax = 0; r->status = 0; return; }
    put_word(g,UINT16_C(0x5dec),destination);
    while (r->prefix_copied < UINT16_C(0x57)) {
        uint8_t value = g[source];
        g[destination] = value; source = (uint16_t)(source + UINT16_C(1));
        destination = (uint16_t)(destination + UINT16_C(1)); ++r->prefix_copied;
        if (value == 0) break;
        if (value == UINT8_C(0x3a) || value == UINT8_C(0x5c)) put_word(g,UINT16_C(0x5dec),destination);
    }
    replace_name(g,ds,r);
}
void td2ega_find_next(uint8_t *g, uint32_t bytes, uint16_t ds,
    const td2ega_sim_target_result *incoming, uint16_t es, uint16_t direction,
    td2ega_find_service service, void *context, td2ega_find_result *r)
{
    uint16_t carry;
    if (!begin(g,bytes,incoming,es,direction,r)) return;
    r->registers.dx = UINT16_C(0x5dee);
    r->registers.ax = (uint16_t)((r->registers.ax & UINT16_C(0xff)) | UINT16_C(0x1a00));
    if (!service_call(g,ds,0,service,context,r,&carry)) return;
    r->registers.ax = (uint16_t)((r->registers.ax & UINT16_C(0xff)) | UINT16_C(0x4f00));
    if (!service_call(g,ds,2,service,context,r,&carry)) return;
    if (carry != 0) { r->registers.ax = 0; r->status = 0; return; }
    replace_name(g,ds,r);
}
