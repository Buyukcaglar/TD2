#include "td2ega_pool_setup.h"
#include <stddef.h>

static uint16_t word(const uint8_t *g, uint16_t at)
{
    return (uint16_t)((uint16_t)g[at] | ((uint16_t)g[(uint32_t)at + 1] << 8));
}
static void put_word(uint8_t *g, uint16_t at, uint16_t value)
{
    g[at] = (uint8_t)value; g[(uint32_t)at + 1] = (uint8_t)(value >> 8);
}
static int call_service(td2ega_pool_service service, void *context,
    uint16_t operation, td2ega_pool_result *r)
{
    td2ega_pool_request request = {operation,r->registers.ax,r->registers.bx,r->es};
    td2ega_pool_response response;
    if (service == NULL || !service(context,&request,&response)) return 0;
    r->registers.ax = response.ax; r->registers.bx = response.bx;
    /* CF is not tested by any original branch in this setup sequence. */
    return 1;
}
void td2ega_pool_setup(uint8_t *g, uint32_t bytes,
    uint16_t cs, uint16_t ds, uint16_t requested_end,
    const td2ega_sim_target_result *incoming, uint16_t incoming_es,
    td2ega_pool_service service, void *context, uint32_t max_clears,
    td2ega_pool_result *r)
{
    uint16_t pointer;
    if (r == NULL) return;
    *r = (td2ega_pool_result){0}; r->status = 2;
    if (g == NULL || bytes < UINT32_C(65537) || incoming == NULL) return;
    r->registers = *incoming; r->es = incoming_es;
    put_word(g,UINT16_C(0x68de),cs); put_word(g,UINT16_C(0x68e0),ds);
    if (word(g,UINT16_C(0x68da)) == 0) {
        r->registers.bx = UINT16_C(0x64);
        r->registers.ax = (uint16_t)((r->registers.ax & UINT16_C(0xff)) | UINT16_C(0x4800));
        if (!call_service(service,context,0,r)) return;
        pointer = word(g,UINT16_C(0x6c66));
        put_word(g,(uint16_t)(pointer + UINT16_C(0xe)),r->registers.ax);
        put_word(g,UINT16_C(0x68dc),r->registers.ax); r->es = r->registers.ax;
        r->registers.bx = (uint16_t)(requested_end - word(g,(uint16_t)(pointer + UINT16_C(0xe))));
        r->stage = 1;
        r->registers.ax = (uint16_t)((r->registers.ax & UINT16_C(0xff)) | UINT16_C(0x4a00));
        if (!call_service(service,context,1,r)) return;
        r->stage = 2;
        r->registers.ax = (uint16_t)((r->registers.ax & UINT16_C(0xff)) | UINT16_C(0x4a00));
        if (!call_service(service,context,1,r)) return;
        r->registers.ax = (uint16_t)(word(g,UINT16_C(0x68dc)) + r->registers.bx);
        pointer = word(g,UINT16_C(0x6c6c));
        put_word(g,(uint16_t)(pointer + UINT16_C(0xe)),r->registers.ax);
        put_word(g,UINT16_C(0x68da),r->registers.ax);
    }
    r->stage = 3;
    pointer = word(g,UINT16_C(0x6c6c)); put_word(g,UINT16_C(0x6c6a),pointer);
    pointer = word(g,UINT16_C(0x6c66)); put_word(g,UINT16_C(0x6c68),pointer);
    for (;;) {
        pointer = (uint16_t)(pointer + UINT16_C(0x12));
        if (pointer == word(g,UINT16_C(0x6c6c))) break;
        if (r->cleared >= max_clears) return;
        put_word(g,(uint16_t)(pointer + UINT16_C(0x10)),0); ++r->cleared;
    }
    r->status = 0; r->stage = 4;
}
void td2ega_pool_setup_fixed(uint8_t *g, uint32_t bytes,
    uint16_t cs, uint16_t ds, const td2ega_sim_target_result *incoming,
    uint16_t incoming_es, td2ega_pool_service service, void *context,
    uint32_t max_clears, td2ega_pool_result *r)
{
    td2ega_sim_target_result local = *incoming; local.ax = UINT16_C(0xa000);
    td2ega_pool_setup(g,bytes,cs,ds,UINT16_C(0xa000),&local,incoming_es,service,context,max_clears,r);
}
void td2ega_pool_remaining(const uint8_t *g,
    const td2ega_sim_target_result *incoming, td2ega_sim_target_result *r)
{
    uint16_t pointer = word(g,UINT16_C(0x6c6c));
    *r = *incoming; r->ax = word(g,(uint16_t)(pointer + UINT16_C(0xe)));
    r->bx = word(g,UINT16_C(0x6c68));
    r->ax = (uint16_t)(r->ax - word(g,(uint16_t)(r->bx + UINT16_C(0xe))));
    r->ax = (uint16_t)(r->ax - word(g,(uint16_t)(r->bx + UINT16_C(0xc))));
}
