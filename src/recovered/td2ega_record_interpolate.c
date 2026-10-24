#include "td2ega_record_interpolate.h"
#include <stddef.h>
static uint32_t address(uint16_t s,uint16_t o)
{ return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff); }
static uint16_t word(const uint8_t *m,uint16_t s,uint16_t o)
{ uint32_t a=address(s,o);return (uint16_t)(m[a]|((uint16_t)m[(a+1)&UINT32_C(0xfffff)]<<8)); }
static void put(uint8_t *m,uint16_t s,uint16_t o,uint16_t v)
{ uint32_t a=address(s,o);m[a]=(uint8_t)v;m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8); }
static int32_t signed_word(uint16_t v)
{ return v<UINT16_C(0x8000)?(int32_t)v:(int32_t)v-INT32_C(65536); }
void td2ega_record_interpolate(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,
    uint16_t sp,const td2ega_state_registers *in,uint32_t limit,
    td2ega_record_interpolate_result *out)
{
    static const uint16_t sources[6]={0x2a2c,0x2a5e,0x2ac2,0x2af4,0x2bee,0x2bbc};
    static const uint16_t destinations[6]={0x9c4,0xa7c,0xb34,0xbec,0xca4,0xd5c};
    td2ega_state_registers r;td2ega_line_step_result child;uint16_t triples[5][3],previous,saved_si,saved_cx,current_sp,child_sp,v;uint32_t sum;int32_t difference;unsigned i;
    if (out==NULL) return;
    *out=(td2ega_record_interpolate_result){0};out->status=2;
    if (m==NULL || bytes<UINT32_C(0x100000) || in==NULL || sp<UINT16_C(0x140) || sp>UINT16_C(0xfff0) || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1) return;
    r=*in;r.registers.ax=r.registers.ds;r.registers.es=r.registers.ax;r.bp=0;r.carry=0;r.registers.si=2;r.registers.direction=0;current_sp=sp;out->stack_segment=ss;out->return_bytes=2;
    do {
        if (out->work==limit) { out->status=3;goto finish; }
        ++out->work;++out->iterations;r.registers.ax=word(m,r.registers.ds,(uint16_t)(r.registers.si+0x2b26));previous=word(m,ss,(uint16_t)(r.bp+0x2b26));r.carry=(uint16_t)(r.registers.ax<previous);
        if (r.registers.ax==previous) goto next_record;
        r.registers.dx=r.registers.ax;v=word(m,r.registers.ds,(uint16_t)(r.registers.si+0x2b56));difference=signed_word(r.registers.ax)-signed_word(v);r.carry=(uint16_t)(r.registers.ax<v);r.registers.ax=(uint16_t)(r.registers.ax-v);
        if (difference>=0) goto publish_previous;
        r.carry=(uint16_t)(r.registers.ax!=0);r.registers.ax=(uint16_t)(0-r.registers.ax);r.registers.cx=r.registers.ax;r.registers.di=r.registers.dx;r.carry=(uint16_t)(r.registers.di>>15);r.registers.di=(uint16_t)(r.registers.di<<1);r.carry=(uint16_t)((r.registers.cx&255)<1);
        if ((r.registers.cx&255)==1) {
            for (i=0;i<6;++i) { r.registers.ax=word(m,r.registers.ds,(uint16_t)(r.registers.si+sources[i]));put(m,r.registers.ds,(uint16_t)(r.registers.di+destinations[i]),r.registers.ax); }
            goto publish_previous;
        }
        v=word(m,ss,(uint16_t)(r.bp+0x2b26));r.carry=(uint16_t)(r.registers.dx<v);r.registers.dx=(uint16_t)(r.registers.dx-v);r.carry=(uint16_t)(r.registers.dx!=0);r.registers.dx=(uint16_t)(0-r.registers.dx);
        saved_si=r.registers.si;current_sp=(uint16_t)(current_sp-2);sum=(uint32_t)r.registers.di+UINT16_C(0x9c4);r.registers.di=(uint16_t)sum;r.carry=(uint16_t)(sum>>16);
        for (i=0;i<5;++i) {
            triples[i][0]=r.registers.di;triples[i][1]=word(m,ss,(uint16_t)(r.bp+sources[i]));triples[i][2]=word(m,r.registers.ds,(uint16_t)(r.registers.si+sources[i]));current_sp=(uint16_t)(current_sp-6);
            sum=(uint32_t)r.registers.di+UINT16_C(0xb8);r.registers.di=(uint16_t)sum;r.carry=(uint16_t)(sum>>16);
        }
        saved_cx=r.registers.cx;current_sp=(uint16_t)(current_sp-2);r.registers.ax=word(m,r.registers.ds,(uint16_t)(r.registers.si+0x2bbc));
        while (r.registers.cx!=0) {
            if (out->work==limit) { out->status=3;goto finish; }
            ++out->work;++out->attribute_words;put(m,r.registers.es,r.registers.di,r.registers.ax);r.registers.di=(uint16_t)(r.registers.di+2);r.registers.cx=(uint16_t)(r.registers.cx-1);
        }
        r.registers.cx=saved_cx;current_sp=(uint16_t)(current_sp+2);
        for (i=5;i>0;--i) {
            child_sp=(uint16_t)(current_sp-2);++out->helper_calls;
            td2ega_line_step(m,bytes,load,ss,child_sp,triples[i-1][0],triples[i-1][1],triples[i-1][2],&r,limit-out->work,&child);
            out->work+=child.work;out->line_words+=child.words;r=child.returned;current_sp=child.current_sp;
            if (child.status!=0) { out->status=child.status;goto finish; }
        }
        r.registers.si=saved_si;current_sp=(uint16_t)(current_sp+2);
publish_previous:
        r.bp=r.registers.si;
next_record:
        r.registers.si=(uint16_t)(r.registers.si+2);r.carry=(uint16_t)(r.registers.si<50);
    } while (r.registers.si!=50);
    current_sp=(uint16_t)(current_sp+2);out->status=0;
finish:
    out->current_sp=current_sp;out->returned=r;
}
