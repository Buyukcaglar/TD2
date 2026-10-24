#include "td2ega_input_control.h"

static uint16_t word(const uint8_t *g, uint16_t at)
{
    return (uint16_t)((uint16_t)g[at] | ((uint16_t)g[(uint32_t)at + 1] << 8));
}
static void put_word(uint8_t *g, uint16_t at, uint16_t value)
{
    g[at] = (uint8_t)value; g[(uint32_t)at + 1] = (uint8_t)(value >> 8);
}
static uint16_t lo(uint16_t word_value, uint8_t value)
{
    return (uint16_t)((word_value & UINT16_C(0xff00)) | value);
}
static uint16_t hi(uint16_t word_value, uint8_t value)
{
    return (uint16_t)((word_value & UINT16_C(0xff)) | ((uint16_t)value << 8));
}
static int32_t signed_word(uint16_t v)
{
    return v < UINT16_C(0x8000) ? (int32_t)v : (int32_t)v - INT32_C(65536);
}
static void product_delta(uint8_t *g, td2ega_sim_target_result *r)
{
    td2ega_product_result product;
    td2ega_clamp_product_target(g,&product);
    if (product.applied != 0) {
        r->ax = product.product_low; r->dx = product.clamped_high; r->cx = product.old_target;
    }
    td2ega_compare_target_delta(g,r->bx,r->cx,r->dx,r);
}
void td2ega_advance_control_pair(uint8_t *g,
    const td2ega_sim_target_result *incoming, uint16_t incoming_bp,
    td2ega_input_control_result *out)
{
    td2ega_sim_target_result r = *incoming;
    g[UINT16_C(0x2f5a)] = 1; g[UINT16_C(0x336b)] = 1;
    r.ax = word(g,UINT16_C(0x2f4c)); r.bx = word(g,UINT16_C(0x2f4e));
    if (r.ax == word(g,UINT16_C(0x3324))) {
        if (signed_word(r.bx) < signed_word(word(g,UINT16_C(0x3326)))) r.bx = (uint16_t)(r.bx + UINT16_C(6));
        else if (r.bx != word(g,UINT16_C(0x3326))) r.bx = (uint16_t)(r.bx - UINT16_C(6));
    } else if (r.bx == word(g,UINT16_C(0x23c8))) {
        r.ax = signed_word(r.ax) < signed_word(word(g,UINT16_C(0x3324))) ?
            (uint16_t)(r.ax + UINT16_C(6)) : (uint16_t)(r.ax - UINT16_C(6));
    } else r.bx = signed_word(r.bx) > signed_word(word(g,UINT16_C(0x23c8))) ?
        (uint16_t)(r.bx - UINT16_C(6)) : (uint16_t)(r.bx + UINT16_C(6));
    put_word(g,UINT16_C(0x2f4c),r.ax); put_word(g,UINT16_C(0x2f4e),r.bx);
    if (r.ax == word(g,UINT16_C(0x3324)) && r.bx == word(g,UINT16_C(0x3326)) &&
        (g[UINT16_C(0x33b0)] & UINT8_C(0x30)) == 0) {
        uint8_t high = (uint8_t)(r.bx >> 8);
        g[UINT16_C(0x3365)] = high; g[UINT16_C(0x3366)] = high;
        g[UINT16_C(0x336c)] = 1; r.bx = lo(r.bx,g[UINT16_C(0x2f56)]);
        if ((uint8_t)r.bx != high) {
            r.bx = (uint16_t)(r.bx * UINT16_C(2));
            r.ax = word(g,(uint16_t)(UINT16_C(0x23b8) + r.bx));
            put_word(g,UINT16_C(0x3328),r.ax); product_delta(g,&r);
        }
    }
    out->registers = r; out->bp = incoming_bp; out->status = 0;
}
void td2ega_update_input_control(uint8_t *g,
    const td2ega_mutable_control *code_state,
    const td2ega_sim_target_result *incoming, uint16_t incoming_bp,
    td2ega_input_control_result *out)
{
    td2ega_sim_target_result r = *incoming;
    uint16_t bp = word(g,UINT16_C(0x332c));
    uint8_t dl = g[UINT16_C(0x3365)], dh = g[UINT16_C(0x3366)];
    int automatic;
    out->registers = r; out->bp = incoming_bp; out->status = 2;
    if (code_state == 0 || (code_state->branch_42ad != TD2EGA_BRANCH_UNSIGNED_GT &&
        code_state->branch_42ad != TD2EGA_BRANCH_NOT_EQUAL)) return;
    r.dx = (uint16_t)((uint16_t)dl | ((uint16_t)dh << 8));
    r.ax = lo(r.ax,g[UINT16_C(0x33b0)]);
    if (g[UINT16_C(0x33d5)] != 0) {
        r.bx = (uint16_t)(r.ax & UINT16_C(0xf));
        r.cx = lo(r.cx,g[UINT16_C(0x339d) + r.bx]);
        g[UINT16_C(0x336d)] = (uint8_t)r.cx; r.ax = lo(r.ax,5); automatic = 1;
    } else {
        if (code_state->branch_42ad == TD2EGA_BRANCH_NOT_EQUAL ?
            word(g,UINT16_C(0x8a9a)) == UINT16_C(1) :
            word(g,UINT16_C(0x8a9a)) <= UINT16_C(1)) {
            put_word(g,UINT16_C(0x3352),0); r.ax = lo(r.ax,1); g[UINT16_C(0x2f59)] = UINT8_C(0xa);
            if (dl == 0) {
                if (bp > word(g,UINT16_C(0x23aa))) r.ax |= UINT16_C(0x10);
                else if (bp <= word(g,UINT16_C(0x23ae)) && g[UINT16_C(0x2f56)] > 1) r.ax = lo(r.ax,UINT8_C(0x15));
            }
        }
        r.bx = (uint16_t)(r.ax & UINT16_C(0xf));
        r.cx = lo(r.cx,g[UINT16_C(0x339d) + r.bx]); g[UINT16_C(0x336d)] = (uint8_t)r.cx;
        r.cx = lo(r.cx,g[UINT16_C(0x33a6) + r.bx]);
        if ((uint8_t)r.cx >= UINT8_C(0x80)) g[UINT16_C(0x336c)] = (uint8_t)r.cx;
        automatic = g[UINT16_C(0x90a8)] != 0;
    }
    if (automatic && dl == 0) {
        if (bp >= word(g,UINT16_C(0x23ac))) {
            r.ax = hi(r.ax,g[UINT16_C(0x2f56)]);
            if ((uint8_t)(r.ax >> 8) != g[UINT16_C(0x23a6)]) { r.ax = lo(r.ax,UINT8_C(0x11)); r.bx = lo(r.bx,1); }
        } else if (g[UINT16_C(0x2f56)] > 1 && bp <= word(g,UINT16_C(0x23ae))) {
            r.ax = lo(r.ax,UINT8_C(0x15)); r.bx = lo(r.bx,5);
        }
    }
    if ((r.ax & UINT16_C(0x30)) == 0) {
        if (dh != 0 && dl == 0) { g[UINT16_C(0x3366)] = 0; product_delta(g,&r); }
        else {
            g[UINT16_C(0x3367)] = 0;
            if (dh == 0) { r.ax = lo(r.ax,g[(uint16_t)(UINT16_C(0x33a6) + r.bx)]); g[UINT16_C(0x336c)] = (uint8_t)r.ax; }
        }
    } else {
        int commit = 0;
        r.ax = lo(r.ax,1); g[UINT16_C(0x3366)] = 1; g[UINT16_C(0x2f5a)] = 1; g[UINT16_C(0x2f59)] = UINT8_C(0xa); r.cx = lo(r.cx,0);
        if (word(g,UINT16_C(0x8a9a)) != 1 && g[UINT16_C(0x33af)] != 0 && g[UINT16_C(0x5490)] == 0) {
            if ((uint8_t)r.bx != 0) {
                r.cx = lo(r.cx,1); r.cx = hi(r.cx,g[UINT16_C(0x2406) + r.bx]);
                r.ax = lo(r.ax,g[UINT16_C(0x240f) + r.bx]); r.bx = lo(r.bx,(uint8_t)((r.cx >> 8) + UINT16_C(7))); commit = 1;
            }
        } else {
            r.ax = hi(r.ax,g[UINT16_C(0x3394) + r.bx]);
            if ((uint8_t)(r.ax >> 8) != 0) {
                r.ax = lo(r.ax,(uint8_t)(g[UINT16_C(0x2f56)] + (uint8_t)(r.ax >> 8)));
                if ((uint8_t)r.ax <= g[UINT16_C(0x23a6)]) {
                    r.cx = lo(r.cx,1);
                    if (g[UINT16_C(0x3367)] != 1) { r.bx = lo(r.bx,(uint8_t)r.ax); commit = 1; }
                }
            }
        }
        if (commit) {
            g[UINT16_C(0x2f56)] = (uint8_t)r.ax; r.bx = (uint16_t)(r.bx * UINT16_C(4));
            r.ax = word(g,(uint16_t)(UINT16_C(0x23c6) + r.bx)); put_word(g,UINT16_C(0x3324),r.ax);
            r.ax = word(g,(uint16_t)(UINT16_C(0x23c8) + r.bx)); put_word(g,UINT16_C(0x3326),r.ax); g[UINT16_C(0x3365)] = (uint8_t)r.cx;
        }
        g[UINT16_C(0x3367)] = (uint8_t)r.cx;
    }
    out->registers = r; out->bp = bp; out->status = 0;
}
