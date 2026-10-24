#include "td2ega_edge_sequence.h"
#include <stddef.h>
static uint32_t address(uint16_t s,uint16_t o)
{ return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff); }
static uint16_t word(const uint8_t *m,uint16_t s,uint16_t o)
{ uint32_t a=address(s,o);return (uint16_t)(m[a]|((uint16_t)m[(a+1)&UINT32_C(0xfffff)]<<8)); }
void td2ega_edge_sequence(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,
    uint16_t sp,const td2ega_state_registers *in,td2ega_draw_sequence_service service,
    void *context,uint32_t limit,td2ega_draw_sequence_result *out)
{
    td2ega_state_registers r;uint16_t pool[15],live,site,v;uint32_t sum;unsigned i,j;
    if (out==NULL)return;
    *out=(td2ega_draw_sequence_result){0};out->status=2;
    if (m==NULL || bytes<UINT32_C(0x100000) || in==NULL || service==NULL || sp<256 || sp>UINT16_C(0xfff0) || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1)return;
    r=*in;out->return_bytes=2;r.registers.bx=word(m,r.registers.ds,(uint16_t)(r.registers.si+0x2b26));r.registers.cx=word(m,r.registers.ds,(uint16_t)(r.registers.si+0x275a));r.registers.cx=(uint16_t)(r.registers.cx>>1);r.registers.cx=(uint16_t)(0-r.registers.cx);sum=(uint32_t)r.registers.cx+r.registers.bx;r.registers.cx=(uint16_t)sum;r.registers.dx=UINT16_C(0xffff);r.carry=0;
    if (m[address(r.registers.ds,0x37f7)]!=0) { r.registers.cx=word(m,r.registers.ds,0x2c2a);r.carry=(uint16_t)(r.registers.cx<5);r.registers.cx=(uint16_t)(r.registers.cx-5); }
    r.registers.ax=word(m,r.registers.ds,(uint16_t)(r.registers.si+0x2a5e));r.registers.di=word(m,r.registers.ds,(uint16_t)(r.registers.si+0x2ac2));
    pool[0]=r.registers.di;pool[1]=r.registers.cx;pool[2]=r.registers.di;pool[3]=r.registers.bx;pool[4]=r.registers.dx;pool[5]=r.registers.ax;pool[6]=r.registers.cx;pool[7]=r.registers.ax;pool[8]=r.registers.bx;pool[9]=r.registers.dx;live=10;sp=(uint16_t)(sp-20);r.carry=0;site=0x3521;
    if (m[address(r.registers.ds,0x37f7)]==0) {
        for (i=10;i>0;--i)pool[i+4]=pool[i-1];
        pool[0]=r.registers.ax;pool[1]=r.registers.cx;pool[2]=r.registers.di;pool[3]=r.registers.cx;pool[4]=r.registers.dx;live=15;sp=(uint16_t)(sp-10);site=0x3519;
    }
    while (live!=0) {
        td2ega_draw_sequence_request q={0};td2ega_state_registers returned=r;
        if (out->calls==limit) { out->status=3;goto finish; }
        sp=(uint16_t)(sp-4);q.kind=1;q.site=site;q.segment=(uint16_t)(load+0x6c9);q.offset=0x8582;q.argument_count=5;q.live_argument_count=live;q.stack_segment=ss;q.stack_sp=sp;q.incoming=r;
        for (i=0;i<live;++i)q.arguments[i]=pool[i];++out->calls;
        if (!service(context,m,&q,&returned)) { out->status=4;goto finish; }
        r=returned;
        if (r.carry>1 || r.registers.interrupts_enabled>1 || r.registers.direction>1)goto finish;
        sp=(uint16_t)(sp+14);r.carry=0;v=(uint16_t)(live-5);
        for (j=0;j<v;++j)pool[j]=pool[j+5];live=v;site=site==0x3519?0x3521:0x3529;
    }
    sp=(uint16_t)(sp+2);out->status=0;
finish:
    out->current_sp=sp;out->returned=r;
}
