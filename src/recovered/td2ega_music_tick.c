#include "td2ega_music_tick.h"
#include <stddef.h>

static uint32_t address(uint16_t segment, uint16_t offset)
{
    return (((uint32_t)segment << 4) + offset) & UINT32_C(0xfffff);
}
static uint8_t byte(const uint8_t *m, uint16_t s, uint16_t o)
{
    return m[address(s,o)];
}
static uint16_t word(const uint8_t *m, uint16_t s, uint16_t o)
{
    uint32_t at = address(s,o);
    return (uint16_t)((uint16_t)m[at] | ((uint16_t)m[(at+1)&UINT32_C(0xfffff)] << 8));
}
static void put_byte(uint8_t *m, uint16_t s, uint16_t o, uint8_t v)
{
    m[address(s,o)] = v;
}
static void put_word(uint8_t *m, uint16_t s, uint16_t o, uint16_t v)
{
    uint32_t at = address(s,o);
    m[at] = (uint8_t)v; m[(at+1)&UINT32_C(0xfffff)] = (uint8_t)(v >> 8);
}
static uint16_t low(uint16_t w, uint8_t b)
{
    return (uint16_t)((w & UINT16_C(0xff00)) | b);
}
static int32_t signed_word(uint16_t w)
{
    return w < UINT16_C(0x8000) ? (int32_t)w : (int32_t)w - INT32_C(65536);
}
static int io(td2ega_music_port_service service, void *context,
    td2ega_music_registers *r, uint16_t operation, uint16_t port)
{
    td2ega_music_port_request request = {operation,port,(uint8_t)r->ax,r->interrupts_enabled};
    uint8_t value = 0;
    if (!service(context,&request,&value)) return 0;
    if (operation == 0) r->ax = low(r->ax,value);
    return 1;
}
void td2ega_music_tick(uint8_t *m, uint32_t bytes, uint16_t load,
    const td2ega_music_registers *incoming, td2ega_music_port_service port,
    void *context, uint32_t max_steps, td2ega_music_tick_result *out)
{
    td2ega_music_registers r;
    uint16_t value;
    uint16_t principal = (uint16_t)(load + UINT16_C(0x178f));
    if (out == NULL) return;
    *out = (td2ega_music_tick_result){0}; out->status = 2;
    if (m == NULL || bytes < UINT32_C(0x100000) || incoming == NULL || port == NULL ||
        incoming->ds != principal || incoming->direction > 1 || incoming->interrupts_enabled > 1) return;
    r = *incoming;
#define B(o) byte(m,r.ds,UINT16_C(o))
#define W(o) word(m,r.ds,UINT16_C(o))
#define PB(o,v) put_byte(m,r.ds,UINT16_C(o),(uint8_t)(v))
#define PW(o,v) put_word(m,r.ds,UINT16_C(o),(uint16_t)(v))
#define IO(op,p) do { if (!io(port,context,&r,(op),(p))) { out->status=4; goto finish; } } while (0)
#define STEP() do { if (out->steps == max_steps) { out->status=3; goto finish; } ++out->steps; } while (0)
    STEP();
    if (B(0x5efb) != 3) goto silence;
    if (B(0x65d2) != 0) {
        PB(0x65d2,0); IO(0,0x61); r.ax = low(r.ax,(uint8_t)(r.ax | 2)); IO(1,0x61);
        goto song_record;
    }
    if (B(0x5efc) != 0) goto duration;
silence:
    PB(0x5efc,0); PB(0x65d2,0);
    IO(0,0x61); r.ax = low(r.ax,(uint8_t)(r.ax & UINT16_C(0xfc))); IO(1,0x61);
    goto normal;
song_record:
    STEP(); r.es = W(0x65f5); r.si = W(0x65ed);
    if (r.si == 0) goto silence;
    r.ax = word(m,r.es,r.si); PW(0x65e9,r.ax);
    r.bx = byte(m,r.es,(uint16_t)(r.si+2)); r.bx = (uint16_t)(r.bx+W(0x65d5));
    PW(0x65d9,r.bx); PW(0x65ed,W(0x65ed)+3);
event:
    STEP(); r.si = W(0x65e9);
    if (r.si == 0) goto silence;
    PW(0x65e9,W(0x65e9)+2); r.es = W(0x65f5); r.bx = byte(m,r.es,r.si);
    if (r.bx >= UINT16_C(0x80)) {
        if (r.bx < UINT16_C(0xfb)) goto silence;
        r.bx = (uint16_t)((uint8_t)(0-(uint8_t)r.bx)*UINT16_C(2));
        switch (r.bx) {
        case 2: r.ax = W(0x65f1); PW(0x65ed,r.ax); goto song_record;
        case 4: r.ax = byte(m,r.es,(uint16_t)(r.si+1)); PW(0x65d3,r.ax); goto event;
        case 6:
            r.bx = byte(m,r.es,(uint16_t)(r.si+1));
            r.si = (uint16_t)(r.bx*UINT16_C(32)+W(0x65f9));
            r.ds = W(0x65f7); r.dx = principal; r.es = r.dx;
            { uint16_t saved_di = r.di;
              r.di = UINT16_C(0x6609); r.cx = 14; r.direction = 0;
              while (r.cx != 0) {
                  value = word(m,r.ds,r.si); put_word(m,r.es,r.di,value);
                  r.si = (uint16_t)(r.si+2); r.di = (uint16_t)(r.di+2); --r.cx;
              }
              r.ds = r.dx; r.di = saved_di;
            }
            goto event;
        case 8: goto song_record;
        default:
            PB(0x5efc,0); PB(0x65d2,0); PW(0x65ed,0); PW(0x65ef,0); goto normal;
        }
    }
    if (r.bx == 0) {
        r.ax = (uint16_t)((uint8_t)W(0x65d3)*byte(m,r.es,(uint16_t)(r.si+1)));
        PW(0x65e1,r.bx); PW(0x65e5,r.ax); goto gate_off;
    }
    r.ax = W(0x65d3);
    r.cx = (uint16_t)((uint16_t)byte(m,r.es,(uint16_t)(r.si+1))*UINT16_C(0x101));
    r.cx = low(r.cx,(uint8_t)(r.cx & UINT16_C(0x7f)));
    r.ax = (uint16_t)((uint8_t)r.ax*(uint8_t)r.cx); r.dx = r.ax;
    if ((r.cx & UINT16_C(0x8000)) != 0) r.dx = 0;
    else {
        r.cx = low(r.cx,B(0x6609));
        if ((uint8_t)r.cx == 0) r.dx = 0;
        else { unsigned shift = (uint8_t)r.cx & 31u; r.dx = shift >= 16u ? 0 : (uint16_t)(r.dx >> shift); }
    }
    PW(0x65e5,r.dx); r.ax = (uint16_t)(r.ax-r.dx); PW(0x65e1,r.ax);
    if (r.ax == 0) goto gate_off;
    r.bx = (uint16_t)(r.bx+W(0x65d9)); PW(0x65fb,r.bx); r.bx = (uint16_t)(r.bx*2);
    r.ax = word(m,r.ds,(uint16_t)(UINT16_C(0x663b)+r.bx)); PW(0x65fd,r.ax);
    IO(1,0x42); r.ax = (uint16_t)((r.ax<<8)|(r.ax>>8)); IO(1,0x42);
    IO(0,0x61); r.ax = low(r.ax,(uint8_t)(r.ax|1)); IO(1,0x61);
    r.ax = W(0x660b); PW(0x65ff,r.ax); r.ax = 0; PW(0x6601,r.ax); PW(0x6607,r.ax);
    r.ax = W(0x6619); PW(0x6603,r.ax); r.ax = low(r.ax,B(0x661d));
    if ((uint8_t)r.ax == 0) r.ax = low(r.ax,1);
    PB(0x6605,r.ax);
duration:
    STEP();
    if (W(0x65e1) == 0) goto rest;
    value = (uint16_t)(W(0x65e1)-1); PW(0x65e1,value);
    if (value == 0) {
        IO(0,0x61); r.ax = low(r.ax,(uint8_t)(r.ax & UINT16_C(0xfe))); IO(1,0x61);
        PB(0x65d2,0); goto normal;
    }
    if (W(0x65ff) != 0) {
        value = (uint16_t)(W(0x65ff)-1); PW(0x65ff,value);
        if (value == 0) {
            r.ax = W(0x660d); PW(0x65ff,r.ax); PW(0x6601,W(0x6601)+1);
            r.bx = (uint16_t)(W(0x6601)&W(0x660f)); r.ax &= UINT16_C(0xff);
            r.ax = low(r.ax,byte(m,r.ds,(uint16_t)(UINT16_C(0x6611)+r.bx)));
            r.bx = (uint16_t)(r.ax+W(0x65fb)); r.bx = (uint16_t)(r.bx*2);
            r.ax = word(m,r.ds,(uint16_t)(UINT16_C(0x663b)+r.bx)); PW(0x65fd,r.ax);
        }
    }
    if (W(0x6603) != 0) { PW(0x6603,W(0x6603)-1); goto pitch_out; }
pitch_step:
    STEP(); r.ax = W(0x6607);
    if (B(0x6605) < UINT8_C(0x80)) {
        r.ax = (uint16_t)(W(0x661f)+r.ax);
        if (signed_word(r.ax) > signed_word(W(0x6623))) goto pitch_limit;
    } else {
        r.ax = (uint16_t)(r.ax-W(0x661f));
        if (signed_word(r.ax) < signed_word(W(0x6621))) goto pitch_limit;
    }
pitch_commit:
    PW(0x6607,r.ax); r.ax = W(0x661b); PW(0x6603,r.ax);
pitch_out:
    r.ax = (uint16_t)(W(0x6607)+W(0x65fd)); IO(1,0x42);
    r.ax = (uint16_t)((r.ax<<8)|(r.ax>>8)); IO(1,0x42); goto normal;
pitch_limit:
    if (B(0x661d) == 0) { PB(0x6605,0-B(0x6605)); goto pitch_step; }
    r.ax = 0; goto pitch_commit;
gate_off:
    IO(0,0x61); r.ax = low(r.ax,(uint8_t)(r.ax & UINT16_C(0xfe))); IO(1,0x61);
rest:
    STEP();
    if (W(0x65e5) == 0) goto event;
    PW(0x65e5,W(0x65e5)-1);
normal:
    out->status = 0;
finish:
    out->registers = r;
#undef B
#undef W
#undef PB
#undef PW
#undef IO
#undef STEP
}
