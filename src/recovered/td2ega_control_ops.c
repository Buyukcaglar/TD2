#include "td2ega_control_ops.h"

static uint16_t word(const uint8_t *g, uint16_t at)
{
    return (uint16_t)((uint16_t)g[at] | ((uint16_t)g[(uint32_t)at + 1] << 8));
}
static void put_word(uint8_t *g, uint16_t at, uint16_t value)
{
    g[at] = (uint8_t)value; g[(uint32_t)at + 1] = (uint8_t)(value >> 8);
}
static int32_t signed_word(uint16_t v)
{
    return v < UINT16_C(0x8000) ? (int32_t)v : (int32_t)v - INT32_C(65536);
}
void td2ega_small_control_dispatch(uint8_t *g, const uint8_t *es,
    const td2ega_sim_target_result *incoming, uint16_t incoming_di,
    uint16_t incoming_direction, td2ega_small_control_result *r)
{
    uint16_t scanned;
    *r = (td2ega_small_control_result){0}; r->registers = *incoming;
    r->di = incoming_di; r->direction = incoming_direction;
    if (incoming->ax == 0) return;
    r->direction = 0;
    for (scanned = 0; scanned < UINT16_C(5); ++scanned) {
        r->di = (uint16_t)(UINT16_C(0x33da) - scanned - UINT16_C(1));
        r->registers.cx = (uint16_t)(UINT16_C(4) - scanned);
        if (es[(uint16_t)(UINT16_C(0x33da) - scanned)] == (uint8_t)incoming->ax) {
            r->registers.cx = (uint16_t)(r->registers.cx * UINT16_C(2));
            r->registers.bx = r->registers.cx;
            r->target = word(g, (uint16_t)(UINT16_C(0x33dc) + r->registers.bx));
            if (r->target == UINT16_C(0x44bf)) g[UINT16_C(0x5490)] = UINT8_C(0xff);
            else if (r->target == UINT16_C(0x44c5)) {
                if (g[UINT16_C(0x90a8)] == 0) g[UINT16_C(0x33af)] ^= UINT8_C(1);
            } else if (r->target == UINT16_C(0x44d2)) g[UINT16_C(0x2f58)] ^= UINT8_C(1);
            else r->status = 2;
            return;
        }
    }
}
void td2ega_decelerate_target(uint8_t *g,
    const td2ega_sim_target_result *incoming, td2ega_sim_target_result *r)
{
    uint16_t old = word(g, UINT16_C(0x52ce));
    td2ega_product_result product;
    *r = *incoming; r->ax = old >= incoming->dx ? (uint16_t)(old - incoming->dx) : 0;
    r->bx = (uint16_t)(old - r->ax);
    if (r->bx == 0) return;
    put_word(g, UINT16_C(0x52ce), r->ax);
    td2ega_clamp_product_target(g, &product);
    if (product.applied != 0) {
        r->ax = product.product_low; r->dx = product.clamped_high; r->cx = product.old_target;
    }
}
void td2ega_decelerate_fixed(uint8_t *g,
    const td2ega_sim_target_result *incoming, td2ega_sim_target_result *r)
{
    td2ega_sim_target_result local = *incoming; local.dx = UINT16_C(0x640);
    td2ega_decelerate_target(g, &local, r);
}
void td2ega_adjust_scaled_target(uint8_t *g,
    const td2ega_sim_target_result *incoming, td2ega_sim_target_result *r)
{
    uint16_t old;
    if (g[UINT16_C(0x336c)] == UINT8_C(0xff)) {
        /* MOVAX,640 at45BF is overwritten in45FC; DX remains caller input. */
        td2ega_decelerate_target(g,incoming,r); return;
    }
    *r = *incoming; old = word(g, UINT16_C(0x52ce)); r->ax = old;
    r->bx = (uint16_t)((old >> 8) >> 2); r->cx = g[UINT16_C(0x324a) + r->bx];
    if (r->dx == 0) r->cx = (uint16_t)(r->cx * UINT16_C(2));
    r->dx = (uint16_t)(r->dx - r->cx);
    if (r->dx == 0) return;
    if (r->dx >= UINT16_C(0x8000)) {
        r->dx = (uint16_t)(UINT16_C(0) - r->dx); r->ax = (uint16_t)(old - r->dx);
        if (old < r->dx) return;
    } else r->ax = (uint16_t)(old + r->dx);
    put_word(g, UINT16_C(0x52ce), r->ax); g[UINT16_C(0x2f5b)] = 1;
}
void td2ega_update_limit_counter(uint8_t *g,
    const td2ega_sim_target_result *incoming, td2ega_sim_target_result *r)
{
    uint8_t old = g[UINT16_C(0x33b3)], low = old;
    *r = *incoming; r->ax = word(g, UINT16_C(0x332c));
    if (r->ax < word(g, UINT16_C(0x23aa))) {
        low = (uint8_t)(old - UINT8_C(1));
        /* DEC/JL includes80->7F overflow: only prior signed byte >0 stores. */
        if (old != 0 && old < UINT8_C(0x80)) g[UINT16_C(0x33b3)] = low;
    } else {
        int trigger = r->ax > word(g, UINT16_C(0x23a8));
        if (!trigger) {
            low = (uint8_t)(old + UINT8_C(1));
            trigger = low >= UINT8_C(0x1e);
            if (!trigger) g[UINT16_C(0x33b3)] = low;
        }
        if (trigger) {
            if (r->ax >= word(g, UINT16_C(0x23a8))) r->ax = word(g, UINT16_C(0x23a8));
            put_word(g, UINT16_C(0x332c), r->ax); g[UINT16_C(0x5490)] = 3;
        }
    }
    r->bx = (uint16_t)((incoming->bx & UINT16_C(0xff00)) | low);
}
void td2ega_update_interval_state(uint8_t *g,
    const td2ega_sim_target_result *incoming, td2ega_sim_target_result *r)
{
    uint8_t mode;
    *r = *incoming; r->ax = (uint16_t)(word(g, UINT16_C(0x52cc)) + UINT16_C(0x28));
    put_word(g, UINT16_C(0x3332), r->ax); r->bx = (uint16_t)(r->ax - UINT16_C(0x5a));
    put_word(g, UINT16_C(0x3334), r->bx); r->bx = (uint16_t)(r->bx + UINT16_C(0xb4));
    put_word(g, UINT16_C(0x3336), r->bx); mode = g[UINT16_C(0x3371)];
    r->cx = (uint16_t)((r->cx & UINT16_C(0xff00)) | mode);
    if (mode == 0 || mode >= UINT8_C(0x80)) return;
    if (mode == 1) {
        if (g[UINT16_C(0x33d5)] != 0) {
            if (g[UINT16_C(0x52cf)] <= UINT8_C(5)) g[UINT16_C(0x5490)] = 1;
            return;
        }
        if (signed_word(r->ax) >= INT32_C(0x258)) put_word(g, UINT16_C(0x52cc), UINT16_C(0x230));
    }
    if (g[UINT16_C(0x52cf)] > UINT8_C(5)) return;
    g[UINT16_C(0x5490)] = mode == 2 ? UINT8_C(4) : signed_word(r->ax) < INT32_C(0x64) ? UINT8_C(9) : UINT8_C(1);
}
