#include "td2ega_plane_span.h"
#include <stddef.h>
typedef struct span_context { uint8_t *m;td2ega_state_registers r;td2ega_plane_span_result *out; } span_context;
static uint32_t address(uint16_t s,uint16_t o)
{ return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff); }
static uint16_t word(const uint8_t *m,uint16_t s,uint16_t o)
{ uint32_t a=address(s,o);return (uint16_t)(m[a]|((uint16_t)m[(a+1)&UINT32_C(0xfffff)]<<8)); }
static uint16_t read(span_context *c,uint16_t o)
{ return word(c->m,c->r.registers.ds,o); }
static void put(span_context *c,uint16_t o,uint16_t v)
{ uint32_t a=address(c->r.registers.ds,o);c->m[a]=(uint8_t)v;c->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8); }
static int32_t sw(uint16_t v)
{ return v<UINT16_C(0x8000)?v:(int32_t)v-INT32_C(65536); }
static uint16_t sar3(uint16_t v)
{ return (uint16_t)((v>>3)|(v&UINT16_C(0x8000)?UINT16_C(0xe000):0)); }
static void bits(span_context *c,uint8_t mask,uint8_t value)
{ uint32_t a=address(c->r.registers.es,c->r.registers.di);c->m[a]=(uint8_t)((c->m[a]&mask)|value);c->r.carry=0;c->out->writes+=2; }
static void repeat(span_context *c)
{
    while (c->r.registers.cx!=0) {
        c->m[address(c->r.registers.es,c->r.registers.di)]=(uint8_t)c->r.registers.ax;
        c->r.registers.di=(uint16_t)(c->r.registers.di+(c->r.registers.direction?-1:1));
        --c->r.registers.cx;++c->out->writes;
    }
}
void td2ega_plane_span(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,
    uint16_t sp,uint16_t entry,const td2ega_state_registers *in,
    td2ega_plane_span_service service,void *context,td2ega_plane_span_result *out)
{
    span_context c;uint16_t saved_si,index,v,old;uint8_t b;unsigned i;
    if (out==NULL)return;
    *out=(td2ega_plane_span_result){0};out->status=2;
    if (m==NULL || bytes<UINT32_C(0x100000) || in==NULL || entry>1 || (entry==1 && service==NULL) || sp<256 || sp>UINT16_C(0xfff0) || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1)return;
    c=(span_context){m,*in,out};out->current_sp=sp;
#define R c.r.registers
#define W(o) read(&c,(uint16_t)(o))
    if (entry==1) {
        c.r.carry=(uint16_t)(R.dx<R.ax);
        if (sw(R.dx)<sw(R.ax)) {
            td2ega_plane_span_request q={0};td2ega_state_registers returned=c.r;
            q.site=0xd0a;q.segment=(uint16_t)(load+0x6c9);q.offset=0x8582;q.stack_segment=ss;q.stack_sp=(uint16_t)(sp-14);q.arguments[0]=R.dx;q.arguments[1]=R.di;q.arguments[2]=R.ax;q.arguments[3]=R.di;q.arguments[4]=R.bx;q.incoming=c.r;out->current_sp=q.stack_sp;out->calls=1;
            if (!service(context,m,&q,&returned)) { out->status=4;goto finish; }
            c.r=returned;
            if (c.r.carry>1 || R.interrupts_enabled>1 || R.direction>1)goto finish;
            c.r.carry=0;
        }
        goto normal;
    }
    R.dx=W(0x9c0);c.r.carry=(uint16_t)(R.ax<R.dx);
    if (sw(R.ax)<=sw(R.dx))goto normal;
    saved_si=R.si;R.dx=sar3(R.dx);put(&c,0x9c0,R.ax);R.bx&=15;c.r.carry=0;
    for (i=0;i<4;++i) { b=m[address(R.ds,(uint16_t)(R.bx+0x5428+i*16))];R.cx=(uint16_t)((R.cx&UINT16_C(0xff00))|b);m[address(R.ds,(uint16_t)(0x8ae+i))]=b; }
    R.ax=(uint16_t)(R.ax-1);R.bx=R.ax;R.ax=sar3(R.ax);R.bx&=7;c.r.carry=0;index=R.bx;R.cx=R.ax;c.r.carry=(uint16_t)(R.cx<R.dx);R.cx=(uint16_t)(R.cx-R.dx);c.r.bp=W(0x9be);b=m[address(ss,(uint16_t)(c.r.bp+0x5468))];R.ax=(uint16_t)((uint16_t)b|((uint16_t)b<<8));R.cx=(uint16_t)((R.cx&255)|((uint16_t)(uint8_t)(b^255)<<8));R.bx=R.ax;R.ax&=W(0x8ae);R.bx&=W(0x8b0);c.r.carry=0;
    R.es=W(0x5420);c.r.bp=R.es;bits(&c,(uint8_t)(R.cx>>8),(uint8_t)R.ax);
    R.es=W(0x5422);bits(&c,(uint8_t)(R.cx>>8),(uint8_t)(R.ax>>8));
    R.es=W(0x5424);bits(&c,(uint8_t)(R.cx>>8),(uint8_t)R.bx);
    R.es=W(0x5426);bits(&c,(uint8_t)(R.cx>>8),(uint8_t)(R.bx>>8));R.cx&=255;c.r.carry=0;
    if (R.cx!=0) {
        R.di=(uint16_t)(R.di+1);R.ax=W(0x8ae);R.bx=W(0x8b0);R.es=c.r.bp;R.dx=(uint16_t)((R.dx&UINT16_C(0xff00))|(uint8_t)R.cx);R.si=R.di;repeat(&c);
        R.es=W(0x5422);R.cx=(uint8_t)R.dx;R.di=R.si;R.ax=(uint16_t)((R.ax&UINT16_C(0xff00))|(R.ax>>8));repeat(&c);
        R.es=W(0x5424);R.cx=(uint8_t)R.dx;R.di=R.si;R.ax=(uint16_t)((R.ax&UINT16_C(0xff00))|(uint8_t)R.bx);repeat(&c);
        R.es=W(0x5426);R.cx=(uint8_t)R.dx;R.di=R.si;R.ax=(uint16_t)((R.ax&UINT16_C(0xff00))|(R.bx>>8));repeat(&c);R.di=(uint16_t)(R.di-1);
    }
    R.si=(uint16_t)(index+1);put(&c,0x9be,R.si);c.r.carry=(uint16_t)(R.si<8);
    if (R.si==8) {
        R.si=0;c.r.carry=0;put(&c,0x9be,R.si);R.di=(uint16_t)(R.di+1);R.ax=W(0x9c0);v=W(0x5348);c.r.carry=(uint16_t)(R.ax<v);
        if (R.ax==v) { R.si=saved_si;old=sp;c.r.carry=(uint16_t)((uint32_t)old+2>65535);out->current_sp=(uint16_t)(sp+2);out->next_ip=W(0x702);out->status=1;goto finish; }
    }
    R.si=saved_si;
normal:
    out->current_sp=(uint16_t)(sp+2);out->status=0;
finish:
    out->returned=c.r;
#undef R
#undef W
}
