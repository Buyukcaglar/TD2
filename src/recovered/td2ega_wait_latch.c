#include "td2ega_wait_latch.h"
#include <stddef.h>
static uint32_t address(uint16_t s,uint16_t o)
{ return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff); }
static uint16_t word(const uint8_t *m,uint16_t s,uint16_t o)
{ uint32_t a=address(s,o);return (uint16_t)(m[a]|((uint16_t)m[(a+1)&UINT32_C(0xfffff)]<<8)); }
static void put(uint8_t *m,uint16_t s,uint16_t o,uint16_t v)
{ uint32_t a=address(s,o);m[a]=(uint8_t)v;m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8); }
void td2ega_wait_latch(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,
    uint16_t sp,enum td2ega_wait_latch_entry entry,
    const td2ega_state_registers *in,td2ega_wait_service service,void *context,
    uint32_t limit,td2ega_wait_result *out)
{
    td2ega_state_registers r,ignored;td2ega_wait_request q;td2ega_wait_result snapshot;
    uint32_t sum;uint16_t high,low;
    if (out==NULL) return;
    *out=(td2ega_wait_result){0};out->status=2;
    if (m==NULL || bytes<UINT32_C(0x100000) || in==NULL || service==NULL || entry<TD2EGA_LATCH_SET || entry>TD2EGA_LATCH_WAIT || sp<32 || sp>UINT16_C(0xfff0) || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1) return;
    r=*in;if (entry==TD2EGA_LATCH_SET) r.bp=(uint16_t)(sp-2);
    do {
        if (out->events==limit) { out->status=3;goto finish; }
        q=(td2ega_wait_request){0,entry==TD2EGA_LATCH_SET?UINT16_C(0x7a13):UINT16_C(0x7a27),(uint16_t)(load+0x6c9),UINT16_C(0x79c8),r};ignored=r;++out->events;
        if (!service(context,m,&q,&ignored)) { out->status=4;goto finish; }
        td2ega_counter_snapshot(m,bytes,&r,&snapshot);r=snapshot.returned;
        if (entry==TD2EGA_LATCH_SET) {
            sum=(uint32_t)r.registers.ax+word(m,ss,(uint16_t)(sp+4));r.registers.ax=(uint16_t)sum;
            sum=(uint32_t)r.registers.dx+word(m,ss,(uint16_t)(sp+6))+(sum>>16);r.registers.dx=(uint16_t)sum;r.carry=(uint16_t)(sum>>16);
            put(m,r.registers.ds,UINT16_C(0x6818),r.registers.ax);put(m,r.registers.ds,UINT16_C(0x681a),r.registers.dx);
            out->deadline_low=r.registers.ax;out->deadline_high=r.registers.dx;r.bp=in->bp;break;
        }
        high=word(m,r.registers.ds,UINT16_C(0x681a));r.carry=(uint16_t)(r.registers.dx<high);out->deadline_high=high;
        if (r.registers.dx<high) continue;
        if (r.registers.dx>high) break;
        low=word(m,r.registers.ds,UINT16_C(0x6818));r.carry=(uint16_t)(r.registers.ax<low);out->deadline_low=low;
        if (r.carry==0) break;
    } while (1);
    out->status=0;
finish:
    out->returned=r;
}
