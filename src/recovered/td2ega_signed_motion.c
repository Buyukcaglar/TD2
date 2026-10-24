#include "td2ega_signed_motion.h"

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
static uint16_t arithmetic_shift(uint16_t v, uint16_t count)
{
    uint32_t shifted = (uint32_t)v >> count;
    if (v >= UINT16_C(0x8000)) shifted |= UINT32_C(0xffff) << (UINT16_C(16) - count);
    return (uint16_t)shifted;
}
static uint16_t wrapped_absolute(uint16_t v)
{
    return v >= UINT16_C(0x8000) ? (uint16_t)(UINT16_C(0) - v) : v;
}
void td2ega_long_multiply(uint32_t first, uint32_t second,
    uint16_t incoming_cx, td2ega_sim_target_result *r)
{
    uint16_t first_low = (uint16_t)first, first_high = (uint16_t)(first >> 16);
    uint16_t second_low = (uint16_t)second, second_high = (uint16_t)(second >> 16);
    uint32_t product = first * second;
    r->ax = (uint16_t)product; r->dx = (uint16_t)(product >> 16); r->bx = second_low;
    r->cx = (first_high | second_high) == 0 ? incoming_cx :
        (uint16_t)((uint32_t)first_high * second_low + (uint32_t)first_low * second_high);
}
void td2ega_update_signed_motion(uint8_t *g,
    const td2ega_sim_target_result *incoming, td2ega_signed_motion_result *out)
{
    td2ega_sim_target_result r = *incoming;
    uint16_t error, correction, rotation, lateral, factor;
    uint8_t steer = g[UINT16_C(0x336d)];
    int32_t signed_steer = steer < UINT8_C(0x80) ? (int32_t)steer : (int32_t)steer - INT32_C(256);
    *out = (td2ega_signed_motion_result){0};
    put_word(g,UINT16_C(0x335a),(uint16_t)(word(g,UINT16_C(0x335a)) >> 9));
    r.ax = arithmetic_shift((uint16_t)((uint16_t)g[UINT16_C(0x30e4)] << 8),5);
    r.ax = (uint16_t)(UINT16_C(0) - r.ax);
    r.cx = arithmetic_shift(word(g,UINT16_C(0x2f4a)),2);
    error = (uint16_t)(r.ax - r.cx); out->error = error;
    correction = (uint16_t)(signed_steer * INT32_C(120));
    r.ax = correction; r.dx = signed_steer < 0 ? UINT16_C(0xffff) : 0; r.cx = UINT16_C(0x78);
    rotation = word(g,UINT16_C(0x2f46)); lateral = word(g,UINT16_C(0x2f4a));
    if (steer == 0 && g[UINT16_C(0x336e)] != 0 && word(g,UINT16_C(0x3322)) == 0 &&
        signed_word(wrapped_absolute(rotation)) < INT32_C(0x600) &&
        signed_word(wrapped_absolute(lateral)) < INT32_C(0xc00)) {
        r.ax = arithmetic_shift(lateral,3); r.cx = 3;
        put_word(g,UINT16_C(0x2f4a),(uint16_t)(lateral - r.ax));
        r.ax = arithmetic_shift(rotation,2); rotation = (uint16_t)(rotation - r.ax);
        put_word(g,UINT16_C(0x2f46),rotation); r.ax = wrapped_absolute(rotation);
        if (signed_word(r.ax) < INT32_C(0x100)) put_word(g,UINT16_C(0x2f46),0);
        r.ax = 0; out->damped = 1; out->correction = correction;
        out->registers = r; return;
    }
    if (g[UINT16_C(0x336e)] != 0 && steer == 0 && rotation != 0) {
        uint32_t product;
        r.ax = arithmetic_shift(rotation,7); r.cx = 7;
        product = (uint32_t)r.ax * word(g,UINT16_C(0x335a));
        r.ax = (uint16_t)product; r.dx = (uint16_t)(product >> 16);
        correction = (uint16_t)(correction - r.ax);
    }
    if ((signed_steer > 0 && signed_word(error) > signed_word(rotation)) ||
        (signed_steer < 0 && signed_word(error) < signed_word(rotation))) {
        r.ax = arithmetic_shift((uint16_t)(rotation - error),3); r.cx = 3;
        correction = (uint16_t)(correction - r.ax);
    }
    factor = (uint16_t)(UINT16_C(0x100) - (word(g,UINT16_C(0x30e6)) >> 10));
    /* CWD afterMOVAX,correction supplies a signed16-bit first operand. */
    td2ega_long_multiply((uint32_t)signed_word(correction),factor,UINT16_C(0xa),&r);
    out->product = (uint32_t)r.ax | ((uint32_t)r.dx << 16);
    r.ax = (uint16_t)(out->product >> 8); r.dx = (uint16_t)(out->product >> 24);
    if (signed_word(r.ax) > INT32_C(0xa00)) r.ax = UINT16_C(0xa00);
    if (signed_word(r.ax) < -INT32_C(0xa00)) r.ax = UINT16_C(0xf600);
    out->correction = r.ax;
    rotation = (uint16_t)(word(g,UINT16_C(0x2f46)) + r.ax);
    put_word(g,UINT16_C(0x2f46),rotation);
    if (signed_word(rotation) > INT32_C(0xe80)) put_word(g,UINT16_C(0x2f46),UINT16_C(0xe80));
    if (signed_word(word(g,UINT16_C(0x2f46))) < -INT32_C(0xe80)) put_word(g,UINT16_C(0x2f46),UINT16_C(0xf180));
    out->registers = r;
}
