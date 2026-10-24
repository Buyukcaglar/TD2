#include "td2ega_timer_handler.h"
#include <stddef.h>

static uint32_t address(uint16_t s, uint16_t o)
{
    return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);
}
static uint8_t byte(const uint8_t *m, uint16_t s, uint16_t o)
{
    return m[address(s,o)];
}
static uint16_t word(const uint8_t *m, uint16_t s, uint16_t o)
{
    uint32_t at=address(s,o);
    return (uint16_t)((uint16_t)m[at]|((uint16_t)m[(at+1)&UINT32_C(0xfffff)]<<8));
}
static void put_byte(uint8_t *m, uint16_t s, uint16_t o, uint8_t v)
{
    m[address(s,o)]=v;
}
static void put_word(uint8_t *m, uint16_t s, uint16_t o, uint16_t v)
{
    uint32_t at=address(s,o);m[at]=(uint8_t)v;m[(at+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);
}
static uint16_t low(uint16_t w, uint8_t v)
{
    return (uint16_t)((w&UINT16_C(0xff00))|v);
}
static int step(td2ega_timer_handler_result *out, uint32_t limit)
{
    if (out->steps==limit) { out->status=3;return 0; }
    ++out->steps;return 1;
}
static int chain(uint8_t *m, uint16_t cs, td2ega_music_registers *r,
    td2ega_timer_call_service service, void *context, uint32_t limit,
    td2ega_timer_handler_result *out)
{
    td2ega_timer_call_request q;
    td2ega_music_registers returned;
    uint16_t old, enabled=r->interrupts_enabled, direction=r->direction;
    if (!step(out,limit)) return 0;
    if (byte(m,r->ds,UINT16_C(0x5e94))!=0) {
        old=word(m,r->ds,UINT16_C(0x5e96));put_word(m,r->ds,UINT16_C(0x5e96),(uint16_t)(old-1));
        if (!(old>1 && old<UINT16_C(0x8000))) {
            put_byte(m,r->ds,UINT16_C(0x5e94),0);put_byte(m,r->ds,UINT16_C(0x5e95),0);
        }
    }
    r->ax=0;r->es=0;r->ax=word(m,r->ds,UINT16_C(0x5e88));put_word(m,r->es,UINT16_C(0x20),r->ax);
    r->ax=word(m,r->ds,UINT16_C(0x5e8a));put_word(m,r->es,UINT16_C(0x22),r->ax);
    q=(td2ega_timer_call_request){1,word(m,0,UINT16_C(0x22)),word(m,0,UINT16_C(0x20)),*r};
    q.registers.interrupts_enabled=0;returned=q.registers;++out->old_interrupts;
    if (!service(context,m,&q,&returned)) { out->status=4;return 0; }
    *r=returned;r->interrupts_enabled=enabled;r->direction=direction;
    r->ax=UINT16_C(0x61bf);put_word(m,r->es,UINT16_C(0x20),r->ax);
    r->ax=cs;put_word(m,r->es,UINT16_C(0x22),r->ax);return 1;
}
void td2ega_timer_chain_old(uint8_t *m, uint32_t bytes, uint16_t cs,
    const td2ega_music_registers *incoming, td2ega_timer_call_service call,
    void *context, uint32_t limit, td2ega_timer_handler_result *out)
{
    td2ega_music_registers r;
    if (out==NULL) return;
    *out=(td2ega_timer_handler_result){0};out->status=2;
    if (m==NULL || bytes<UINT32_C(0x100000) || incoming==NULL || call==NULL ||
        incoming->interrupts_enabled>1 || incoming->direction>1) return;
    r=*incoming;
    if (chain(m,cs,&r,call,context,limit,out)) out->status=0;
    out->registers=r;
}
void td2ega_timer_handler(uint8_t *m, uint32_t bytes, uint16_t load,
    const td2ega_music_registers *incoming, uint16_t irq_flags,
    td2ega_music_port_service port, td2ega_timer_call_service call,
    void *context, uint32_t limit, td2ega_timer_handler_result *out)
{
    td2ega_music_registers r;
    td2ega_music_port_request p;
    td2ega_timer_call_request q;
    td2ega_music_registers returned;
    uint16_t old, at;
    uint8_t read_value=0;
    if (out==NULL) return;
    *out=(td2ega_timer_handler_result){0};out->status=2;
    if (m==NULL || bytes<UINT32_C(0x100000) || incoming==NULL || port==NULL || call==NULL ||
        incoming->interrupts_enabled>1 || incoming->direction>1) return;
    r=*incoming;
    if (!step(out,limit)) goto finish;
    r.interrupts_enabled=0;r.ax=low(r.ax,UINT8_C(0x20));
    p=(td2ega_music_port_request){1,0x20,(uint8_t)r.ax,r.interrupts_enabled};
    if (!port(context,&p,&read_value)) { out->status=4;goto finish; }
    r.ax=(uint16_t)(load+UINT16_C(0x178f));r.ds=r.ax;r.interrupts_enabled=1;
    old=word(m,r.ds,UINT16_C(0x5e9a));put_word(m,r.ds,UINT16_C(0x5e9a),(uint16_t)(old-1));
    if (!(old>1 && old<UINT16_C(0x8000))) {
        old=(uint16_t)(word(m,r.ds,UINT16_C(0x5e90))+1);put_word(m,r.ds,UINT16_C(0x5e90),old);
        if (old==0) put_word(m,r.ds,UINT16_C(0x5e92),(uint16_t)(word(m,r.ds,UINT16_C(0x5e92))+1));
        r.ax=word(m,r.ds,UINT16_C(0x5e98));put_word(m,r.ds,UINT16_C(0x5e9a),r.ax);
        if (byte(m,r.ds,UINT16_C(0x5e95))!=0 && !chain(m,(uint16_t)(load+UINT16_C(0x6c9)),&r,call,context,limit,out)) goto finish;
    }
    if (byte(m,r.ds,UINT16_C(0x5efe))!=0) {
        p=(td2ega_music_port_request){0,0x61,(uint8_t)r.ax,r.interrupts_enabled};
        if (!port(context,&p,&read_value)) { out->status=4;goto finish; }
        r.ax=low(r.ax,(uint8_t)(read_value&UINT8_C(0xfc)));
        p=(td2ega_music_port_request){1,0x61,(uint8_t)r.ax,r.interrupts_enabled};
        if (!port(context,&p,&read_value)) { out->status=4;goto finish; }
    } else {
        r.bx=word(m,r.ds,UINT16_C(0x5e9c));at=(uint16_t)(r.bx+UINT16_C(0x5e9e));
        put_word(m,r.ds,at,(uint16_t)(word(m,r.ds,at)+1));
        old=(uint16_t)(word(m,r.ds,UINT16_C(0x5e8c))+1);put_word(m,r.ds,UINT16_C(0x5e8c),old);
        if (old==0) put_word(m,r.ds,UINT16_C(0x5e8e),(uint16_t)(word(m,r.ds,UINT16_C(0x5e8e))+1));
        r.di=0;
        for (;;) {
            if (!step(out,limit)) goto finish;
            r.ax=word(m,r.ds,(uint16_t)(r.di+UINT16_C(0x5f14)));
            if (r.ax==0) break;
            r.interrupts_enabled=0;
            q=(td2ega_timer_call_request){0,r.ax,word(m,r.ds,(uint16_t)(r.di+UINT16_C(0x5f12))),r};
            returned=r;++out->callbacks;
            if (!call(context,m,&q,&returned)) { out->status=4;goto finish; }
            r=returned;r.di=(uint16_t)(r.di+4);
        }
    }
    out->status=0;out->registers=*incoming;out->return_flags=irq_flags;
    out->registers.interrupts_enabled=(uint16_t)((irq_flags>>9)&1);
    out->registers.direction=(uint16_t)((irq_flags>>10)&1);return;
finish:
    out->registers=r;
}
