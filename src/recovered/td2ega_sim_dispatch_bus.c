#include "td2ega_sim_dispatch_bus.h"
#include <stddef.h>

static uint32_t address(uint16_t s, uint16_t o)
{ return (((uint32_t)s << 4) + o) & UINT32_C(0xfffff); }
static uint16_t word(const uint8_t *m, uint16_t s, uint16_t o)
{
    uint32_t a = address(s, o);
    return (uint16_t)(m[a] | ((uint16_t)m[(a + 1) & UINT32_C(0xfffff)] << 8));
}
static void put(uint8_t *m, uint16_t s, uint16_t o, uint16_t v, unsigned width)
{
    uint32_t a = address(s, o);
    m[a] = (uint8_t)v;
    if (width == 2) m[(a + 1) & UINT32_C(0xfffff)] = (uint8_t)(v >> 8);
}

void td2ega_sim_dispatch_bus(uint8_t *m, uint32_t bytes, uint16_t load,
    uint16_t ss, uint16_t sp, uint16_t entry,
    const td2ega_state_registers *in, uint16_t input_zf,
    td2ega_sim_dispatch_bus_result *out)
{
    td2ega_state_registers r;
    uint16_t ds, v, old, offset, zf;
    uint32_t sum;
    if (out == NULL) return;
    *out = (td2ega_sim_dispatch_bus_result){0}; out->status = 2;
    if (m == NULL || bytes < UINT32_C(0x100000) || in == NULL || entry > 10 ||
        sp == UINT16_C(0xffff) || input_zf > 1 || in->carry > 1 ||
        in->registers.interrupts_enabled > 1 || in->registers.direction > 1) return;
    r = *in; ds = r.registers.ds; zf = input_zf;
    if (entry == 0) {
        put(m, ds, 0x3371, 1, 1); ++out->bus_writes;
        v = word(m, ds, 0x9410); r.carry = 0; zf = (uint16_t)(v == 0);
        if (v != 0) {
            r.registers.ax = word(m, ds, 0x331e);
            put(m, ds, 0x3356, r.registers.ax, 2);
            r.registers.ax = word(m, ds, 0x942e);
            put(m, ds, 0x3358, r.registers.ax, 2);
            put(m, ds, 0x33d5, 1, 1); out->bus_writes += 3;
        }
    } else if (entry == 1) {
        put(m, ds, 0x3371, 2, 1); ++out->bus_writes;
    } else if (entry == 2 || entry == 3) {
        v = word(m, ds, 0x52da); r.carry = 0; zf = (uint16_t)(v == 0);
        if (v == 0) {
            if (entry == 3) {
                r.registers.bx = word(m, ds, 0x52ce);
                r.carry = (uint16_t)(r.registers.bx < 0x3200);
                zf = (uint16_t)(r.registers.bx == 0x3200);
                if (r.registers.bx <= 0x3200) goto returned;
                put(m, ds, 0x3354, r.registers.bx, 2); ++out->bus_writes;
            }
            sum = (uint32_t)r.bp + (entry == 2 ? 0x50u : 0x3cu);
            r.registers.ax = (uint16_t)sum;
            r.carry = (uint16_t)(sum > UINT16_MAX);
            zf = (uint16_t)(r.registers.ax == 0);
            put(m, ds, 0x52da, r.registers.ax, 2); ++out->bus_writes;
            if (entry == 3) {
                put(m, ds, 0x52de, 0, 2); put(m, ds, 0x33b7, 8, 1);
                out->bus_writes += 2; r.registers.bx = r.registers.ax;
                v = (uint16_t)(m[address(ds, r.registers.bx)] & 0x80);
                r.carry = 0; zf = (uint16_t)(v == 0);
                put(m, ds, 0x52dc, v ? 0x320 : 0x190, 2); ++out->bus_writes;
            }
        }
    } else if (entry == 4) {
        r.registers.cx = r.registers.bx;
        v = m[address(ds, 0x533e)];
        r.registers.bx = (uint16_t)((v + 0x45u) & 0x7fu); r.bp = r.registers.bx;
        r.registers.cx = (uint16_t)(r.registers.cx >> 1);
        r.registers.bx = r.registers.cx;
        r.registers.cx = (uint16_t)(r.registers.cx - 0x16u);
        old = (uint16_t)(r.registers.cx << 2);
        sum = (uint32_t)old + r.registers.cx;
        r.registers.ax = (uint16_t)sum;
        r.carry = (uint16_t)(sum > UINT16_MAX); zf = (uint16_t)(r.registers.ax == 0);
        put(m, ss, (uint16_t)(r.bp + 0x368a), r.registers.ax, 1); ++out->bus_writes;
        v = m[address(ds, (uint16_t)(r.registers.bx + 0x37dd))];
        r.registers.ax = (uint16_t)((r.registers.ax & 0xff00u) | v);
        put(m, ss, (uint16_t)(r.bp + 0x370a), r.registers.ax, 1); ++out->bus_writes;
    } else if (entry < 10) {
        offset = entry == 5 ? 0x37f7 : entry == 6 ? 0x37f6 : entry == 7 ? 0x37f8 : 0x337a;
        old = m[address(ds, offset)];
        if (entry < 8) { v = (uint16_t)(old ^ 1u); r.carry = 0; }
        else if (entry == 8) { v = (uint16_t)((old + 0x10u) & 0xffu); r.carry = (uint16_t)(old >= 0xf0); }
        else { v = (uint16_t)((old - 0x10u) & 0xffu); r.carry = (uint16_t)(old < 0x10); }
        zf = (uint16_t)(v == 0); put(m, ds, offset, v, 1); ++out->bus_writes;
    }
returned:
    out->next_segment = (uint16_t)(load + 0x6c9);
    out->next_ip = word(m, ss, sp); out->current_sp = (uint16_t)(sp + 2);
    out->returned = r; out->zero_flag = zf; out->flags_valid = 1; out->status = 0;
}
