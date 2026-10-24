#include "td2ega_wait_control.h"
#include <stddef.h>

static uint16_t word(const uint8_t *m, uint16_t s, uint16_t o)
{
    uint32_t at=(((uint32_t)s<<4)+o)&UINT32_C(0xfffff);
    return (uint16_t)((uint16_t)m[at]|((uint16_t)m[(at+1)&UINT32_C(0xfffff)]<<8));
}
static int valid(const uint8_t *m, uint32_t bytes, const td2ega_state_registers *in,
    td2ega_wait_result *out)
{
    if (out==NULL) return 0;
    *out=(td2ega_wait_result){0};out->status=2;
    return m!=NULL && bytes>=UINT32_C(0x100000) && in!=NULL && in->carry<=1 &&
        in->registers.direction<=1 && in->registers.interrupts_enabled<=1;
}
static void snapshot(const uint8_t *m, td2ega_state_registers *r)
{
    r->registers.interrupts_enabled=0;
    r->registers.ax=word(m,r->registers.ds,UINT16_C(0x5e8c));
    r->registers.dx=word(m,r->registers.ds,UINT16_C(0x5e8e));
    r->registers.interrupts_enabled=1;
}
void td2ega_counter_snapshot(const uint8_t *m, uint32_t bytes,
    const td2ega_state_registers *in, td2ega_wait_result *out)
{
    td2ega_state_registers r;
    if (!valid(m,bytes,in,out)) return;
    r=*in;snapshot(m,&r);out->status=0;out->returned=r;
}
static int event(uint8_t *m, uint16_t load, uint16_t kind, uint16_t site,
    td2ega_state_registers *r, td2ega_wait_service service, void *ctx,
    uint32_t limit, td2ega_wait_result *out)
{
    td2ega_wait_request q;
    td2ega_state_registers returned=*r;
    if (out->events==limit) { out->status=3;return 0; }
    q=(td2ega_wait_request){kind,site,(uint16_t)(load+UINT16_C(0x6c9)),kind==0?UINT16_C(0x79c8):UINT16_C(0x69fe),*r};
    ++out->events;
    if (!service(ctx,m,&q,&returned)) { out->status=4;return 0; }
    if (kind==0) snapshot(m,r);
    else {
        if (returned.bp!=r->bp || returned.carry>1 || returned.registers.interrupts_enabled>1 || returned.registers.direction>1) { out->status=2;return 0; }
        *r=returned;
    }
    return 1;
}
void td2ega_wait_control(uint8_t *m, uint32_t bytes, uint16_t load,
    uint16_t entry_sp, enum td2ega_wait_mode mode, uint32_t distance,
    const td2ega_state_registers *in, td2ega_wait_service service,
    void *ctx, uint32_t limit, td2ega_wait_result *out)
{
    td2ega_state_registers r;
    uint32_t deadline, current;
    uint64_t sum;
    if (!valid(m,bytes,in,out)) return;
    if (service==NULL || entry_sp<32 || entry_sp>UINT16_C(0xfff8) ||
        mode<TD2EGA_WAIT_COUNTER || mode>TD2EGA_WAIT_INPUT_OR_COUNTER) return;
    r=*in;r.bp=(uint16_t)(entry_sp-2);r.carry=0; /* Nonwrapping SUBSP4. */
    if (!event(m,load,0,mode==TD2EGA_WAIT_COUNTER?UINT16_C(0x7a5b):UINT16_C(0x6a70),&r,service,ctx,limit,out)) goto finish;
    current=((uint32_t)r.registers.dx<<16)|r.registers.ax;sum=(uint64_t)current+distance;
    deadline=(uint32_t)sum;r.registers.ax=(uint16_t)deadline;r.registers.dx=(uint16_t)(deadline>>16);r.carry=(uint16_t)(sum>>32);
    out->deadline_low=r.registers.ax;out->deadline_high=r.registers.dx;
    for (;;) {
        if (mode==TD2EGA_WAIT_INPUT_OR_COUNTER) {
            if (!event(m,load,1,UINT16_C(0x6a81),&r,service,ctx,limit,out)) goto finish;
            r.carry=0; /* CMPAX,0. */
            if (r.registers.ax!=0) break;
        }
        if (!event(m,load,0,mode==TD2EGA_WAIT_COUNTER?UINT16_C(0x7a6c):UINT16_C(0x6a8b),&r,service,ctx,limit,out)) goto finish;
        current=((uint32_t)r.registers.dx<<16)|r.registers.ax;r.carry=(uint16_t)(current<deadline);
        if (r.carry==0) {
            if (mode==TD2EGA_WAIT_INPUT_OR_COUNTER) r.registers.ax=0;
            break;
        }
    }
    r.bp=in->bp;out->status=0;
finish:
    out->returned=r;
}
