#include "td2ega_effect_tick.h"
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
    uint32_t at=address(s,o);
    return (uint16_t)((uint16_t)m[at] | ((uint16_t)m[(at+1)&UINT32_C(0xfffff)] << 8));
}
static void put_byte(uint8_t *m, uint16_t s, uint16_t o, uint8_t v)
{
    m[address(s,o)]=v;
}
static void put_word(uint8_t *m, uint16_t s, uint16_t o, uint16_t v)
{
    uint32_t at=address(s,o);m[at]=(uint8_t)v;m[(at+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);
}
static uint16_t low(uint16_t w, uint8_t b)
{
    return (uint16_t)((w&UINT16_C(0xff00))|b);
}
static int io(td2ega_music_port_service service, void *context,
    td2ega_music_registers *r, uint16_t operation, uint16_t port)
{
    td2ega_music_port_request request={operation,port,(uint8_t)r->ax,r->interrupts_enabled};
    uint8_t value=0;
    if (!service(context,&request,&value)) return 0;
    if (operation==0) r->ax=low(r->ax,value);
    return 1;
}
void td2ega_effect_tick(uint8_t *m, uint32_t bytes, uint16_t load,
    const td2ega_music_registers *incoming, td2ega_music_port_service port,
    void *context, uint32_t max_steps, td2ega_music_tick_result *out)
{
    td2ega_music_registers r;
    uint16_t count_at, start_at, return_at, value;
    if (out==NULL) return;
    *out=(td2ega_music_tick_result){0};out->status=2;
    if (m==NULL || bytes<UINT32_C(0x100000) || incoming==NULL || port==NULL ||
        incoming->ds!=(uint16_t)(load+UINT16_C(0x178f)) || incoming->direction>1 || incoming->interrupts_enabled>1) return;
    r=*incoming;
#define B(o) byte(m,r.ds,UINT16_C(o))
#define W(o) word(m,r.ds,UINT16_C(o))
#define PB(o,v) put_byte(m,r.ds,UINT16_C(o),(uint8_t)(v))
#define PW(o,v) put_word(m,r.ds,UINT16_C(o),(uint16_t)(v))
#define IO(op,p) do { if (!io(port,context,&r,(op),(p))) { out->status=4; goto finish; } } while (0)
#define STEP() do { if (out->steps==max_steps) { out->status=3; goto finish; } ++out->steps; } while (0)
    STEP();
    if ((B(0x5efb)&1)==0) { PB(0x5efc,0);PW(0x5eee,0);PW(0x5ef6,0);goto silence; }
    if (W(0x5ef6)!=0) {
        r.ax=W(0x5ef6);PW(0x5ef6,r.ax-1);
        if (r.ax==W(0x5ef8)) goto silence;
        goto normal;
    }
event:
    STEP();r.ax=W(0x5eee);
    if (r.ax==0) goto queue;
    r.es=r.ax;r.si=W(0x5ef0);r.bx=low(r.bx,byte(m,r.es,r.si));
    if ((uint8_t)r.bx>=UINT8_C(0x80)) {
        r.bx=(uint8_t)(0-(uint8_t)r.bx);
        if (r.bx>11) goto queue;
        r.bx=(uint16_t)(r.bx*2);
        switch (r.bx) {
        case 2: goto queue;
        case 4:
            r.ax=low(r.ax,byte(m,r.es,(uint16_t)(r.si+1)));PB(0x5efa,r.ax);PW(0x5ef0,W(0x5ef0)+2);goto event;
        case 6: count_at=UINT16_C(0x5f00);start_at=UINT16_C(0x5f06);goto begin_loop;
        case 8: count_at=UINT16_C(0x5f02);start_at=UINT16_C(0x5f08);goto begin_loop;
        case 10: count_at=UINT16_C(0x5f04);start_at=UINT16_C(0x5f0a);goto begin_loop;
        case 12: count_at=UINT16_C(0x5f00);start_at=UINT16_C(0x5f06);return_at=UINT16_C(0x5f0c);goto repeat_loop;
        case 14: count_at=UINT16_C(0x5f02);start_at=UINT16_C(0x5f08);return_at=UINT16_C(0x5f0e);goto repeat_loop;
        case 16: count_at=UINT16_C(0x5f04);start_at=UINT16_C(0x5f0a);return_at=UINT16_C(0x5f10);goto repeat_loop;
        case 18: count_at=UINT16_C(0x5f00);return_at=UINT16_C(0x5f0c);goto return_loop;
        case 20: count_at=UINT16_C(0x5f02);return_at=UINT16_C(0x5f0e);goto return_loop;
        default: count_at=UINT16_C(0x5f04);return_at=UINT16_C(0x5f10);goto return_loop;
        }
    }
    r.ax=word(m,r.es,(uint16_t)(r.si+1));PW(0x5ef6,r.ax);PW(0x5ef0,W(0x5ef0)+3);
    if ((uint8_t)r.bx==0) { PW(0x5ef8,0);goto silence; }
    r.cx=low(r.cx,B(0x5efa));
    if ((uint8_t)r.cx==0) r.ax=0;
    else { unsigned shift=(uint8_t)r.cx&31u;r.ax=shift>=16u?0:(uint16_t)(r.ax>>shift); }
    PW(0x5ef8,r.ax);r.bx=(uint16_t)((uint8_t)r.bx*UINT16_C(2));
    r.ax=word(m,r.ds,(uint16_t)(UINT16_C(0x5f2e)+r.bx));
    IO(1,0x42);r.ax=(uint16_t)((r.ax<<8)|(r.ax>>8));IO(1,0x42);
    IO(0,0x61);r.ax=low(r.ax,(uint8_t)(r.ax|3));IO(1,0x61);goto normal;
begin_loop:
    r.ax=word(m,r.es,(uint16_t)(r.si+1));put_word(m,r.ds,count_at,r.ax);PW(0x5ef0,W(0x5ef0)+3);
    r.ax=W(0x5ef0);put_word(m,r.ds,start_at,r.ax);goto event;
repeat_loop:
    value=(uint16_t)(word(m,r.ds,count_at)-1);put_word(m,r.ds,count_at,value);
    /* JS observes the result sign, including8000->7FFF; it does not test SF^OF. */
    if ((value&UINT16_C(0x8000))==0) {
        put_word(m,r.ds,return_at,r.si);r.ax=word(m,r.ds,start_at);PW(0x5ef0,r.ax);goto event;
    }
    PW(0x5ef0,W(0x5ef0)+1);goto event;
return_loop:
    if (word(m,r.ds,count_at)==0) { r.ax=word(m,r.ds,return_at);PW(0x5ef0,r.ax);goto event; }
    PW(0x5ef0,W(0x5ef0)+1);goto event;
queue:
    PB(0x5efc,0);
    if (B(0x5efd)!=0) { r.ax=W(0x5ef4);PW(0x5ef0,r.ax);r.ax=W(0x5ef2);PW(0x5eee,r.ax);goto event; }
    PW(0x5ef6,0);
silence:
    IO(0,0x61);r.ax=low(r.ax,(uint8_t)(r.ax&UINT16_C(0xfc)));IO(1,0x61);
normal:
    out->status=0;
finish:
    out->registers=r;
#undef B
#undef W
#undef PB
#undef PW
#undef IO
#undef STEP
}
