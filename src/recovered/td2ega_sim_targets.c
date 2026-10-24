#include "td2ega_sim_targets.h"

static uint16_t word(const uint8_t *g, uint16_t at)
{
    return (uint16_t)((uint16_t)g[at] | ((uint16_t)g[(uint32_t)at + 1] << 8));
}
static void put_word(uint8_t *g, uint16_t at, uint16_t value)
{
    g[at] = (uint8_t)value; g[(uint32_t)at + 1] = (uint8_t)(value >> 8);
}
static int32_t signed_word(uint16_t value)
{
    return value < UINT16_C(0x8000) ? (int32_t)value : (int32_t)value - INT32_C(65536);
}

void td2ega_update_sample_targets(uint8_t *g, uint16_t incoming_dx,
    td2ega_sim_target_result *r)
{
    uint16_t ax, bx, cx;
    g[UINT16_C(0x336a)] = (uint8_t)(g[UINT16_C(0x336a)] + UINT8_C(1));
    bx = (uint16_t)((g[UINT16_C(0x336a)] & UINT8_C(0x1f)) * UINT16_C(2));
    ax = word(g, (uint16_t)(UINT16_C(0x32ae) + bx));
    put_word(g, UINT16_C(0x5fde), ax);
    bx = word(g, UINT16_C(0x332a)); cx = word(g, UINT16_C(0x332c));
    if (signed_word(bx) > signed_word(cx)) {
        bx = (uint16_t)(bx - UINT16_C(0x60));
        if (signed_word(bx) <= signed_word(cx)) bx = cx;
    } else {
        bx = (uint16_t)(bx + UINT16_C(0x60));
        if (signed_word(bx) >= signed_word(cx)) bx = cx;
    }
    put_word(g, UINT16_C(0x332a), bx);
    bx = word(g, (uint16_t)(UINT16_C(0x30e8) + ((bx >> 5) & UINT16_C(0xfffe))));
    put_word(g, UINT16_C(0x5fd8), bx);
    if (g[UINT16_C(0x3374)] == 0) {
        if (g[UINT16_C(0x33bc)] != 0) put_word(g, UINT16_C(0x5fda), UINT16_C(0x384));
        else {
            if (g[UINT16_C(0x3368)] == 1) {
                ax = (uint16_t)((ax & UINT16_C(0xff00)) | g[UINT16_C(0x33b2)]);
                if ((uint8_t)ax != 0) {
                    ax = (uint16_t)((ax & UINT16_C(0xff00)) | (uint8_t)((uint8_t)ax - UINT8_C(1)));
                    g[UINT16_C(0x33b2)] = (uint8_t)ax;
                    put_word(g, UINT16_C(0x5fda), UINT16_C(0x474));
                } else put_word(g, UINT16_C(0x5fda), UINT16_C(0xffff));
            }
            if (g[UINT16_C(0x336f)] != 0) put_word(g, UINT16_C(0x5fda), UINT16_C(0x8e8));
        }
    } else if ((word(g, UINT16_C(0x942e)) & UINT16_C(8)) != 0) {
        ax = word(g, UINT16_C(0x3350));
        if (g[UINT16_C(0x335c)] < UINT8_C(0x80)) {
            ax = (uint16_t)(ax + UINT16_C(2));
            if (signed_word(ax) >= INT32_C(0x708)) g[UINT16_C(0x335c)] = UINT8_C(0xff);
        } else {
            ax = (uint16_t)(ax - UINT16_C(2));
            if (signed_word(ax) <= INT32_C(0x5dc)) g[UINT16_C(0x335c)] = 1;
        }
        put_word(g, UINT16_C(0x3350), ax); put_word(g, UINT16_C(0x5fda), ax);
    } else put_word(g, UINT16_C(0x5fda),
        (word(g, UINT16_C(0x3346)) & UINT16_C(4)) != 0 ? UINT16_C(0x5dc) : UINT16_C(0x7d0));
    *r = (td2ega_sim_target_result){ax, bx, cx, incoming_dx};
}

void td2ega_compare_target_delta(uint8_t *g, uint16_t incoming_bx,
    uint16_t incoming_cx, uint16_t incoming_dx, td2ega_sim_target_result *r)
{
    uint16_t ax = (uint16_t)(incoming_dx - incoming_cx), bx = incoming_bx, dx = incoming_dx;
    if (signed_word(incoming_cx) <= signed_word(incoming_dx)) {
        if (ax >= UINT16_C(0xa8c) && g[UINT16_C(0x2f56)] != 0) {
            uint8_t high = (uint8_t)(g[UINT16_C(0x52cf)] - UINT8_C(5));
            g[UINT16_C(0x33b2)] = 3; g[UINT16_C(0x52cf)] = high;
            ax = (uint16_t)((ax & UINT16_C(0xff)) | ((uint16_t)high << 8));
        }
    } else {
        ax = (uint16_t)(UINT16_C(0) - ax);
        if (ax >= UINT16_C(0xbb8)) {
            uint8_t low = g[UINT16_C(0x2418)] >= g[UINT16_C(0x33c6)] ?
                (uint8_t)(g[UINT16_C(0x2418)] - g[UINT16_C(0x33c6)]) : 0;
            dx = ax; bx = (uint16_t)((bx & UINT16_C(0xff)) | ((uint16_t)g[UINT16_C(0x3329)] << 8));
            ax = (uint16_t)((uint16_t)low * g[UINT16_C(0x3329)]);
            if (ax >= UINT16_C(0x1b58)) g[UINT16_C(0x33b2)] = (uint8_t)(dx >> 8);
        }
    }
    *r = (td2ega_sim_target_result){ax, bx, incoming_cx, dx};
}

void td2ega_adjust_target(uint8_t *g, uint16_t incoming_bx,
    uint16_t incoming_cx, uint16_t incoming_dx, td2ega_sim_target_result *r)
{
    uint16_t ax = word(g, UINT16_C(0x332c)), dx = incoming_dx;
    if (g[UINT16_C(0x2f56)] != 0 || g[UINT16_C(0x336c)] == 0 || g[UINT16_C(0x336c)] >= UINT8_C(0x80)) {
        dx = ax; ax = (uint16_t)(ax - UINT16_C(0xc8));
        if (signed_word(ax) <= INT32_C(0x320)) ax = UINT16_C(0x320);
        if (ax != dx) {
            put_word(g, UINT16_C(0x332c), ax); g[UINT16_C(0x2f5b)] = 1;
        }
    } else {
        g[UINT16_C(0x2f5b)] = 1; ax = (uint16_t)(ax + UINT16_C(0x258));
        put_word(g, UINT16_C(0x332c), ax);
    }
    *r = (td2ega_sim_target_result){ax, incoming_bx, incoming_cx, dx};
}
