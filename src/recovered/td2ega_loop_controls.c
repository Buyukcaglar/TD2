#include "td2ega_loop_controls.h"
#include <stddef.h>
typedef struct loop_context {
    uint8_t *m;uint16_t load,ss,sp;uint32_t limit;
    td2ega_state_registers r;td2ega_loop_control_service service;void *context;
    td2ega_loop_control_result *out;
} loop_context;
static uint32_t address(uint16_t s,uint16_t o)
{ return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff); }
static uint16_t word(const uint8_t *m,uint16_t s,uint16_t o)
{ uint32_t a=address(s,o);return (uint16_t)(m[a]|((uint16_t)m[(a+1)&UINT32_C(0xfffff)]<<8)); }
static void put(loop_context *c,uint16_t o,uint16_t v)
{ uint32_t a=address(c->r.registers.ds,o);c->m[a]=(uint8_t)v;c->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8); }
static int call(loop_context *c,uint16_t kind,uint16_t site,uint16_t offset,
    uint16_t argc,uint16_t live,const uint16_t *args)
{
    td2ega_loop_control_request q={0};td2ega_state_registers r;unsigned i;uint16_t frame=kind?4:2;
    if (c->out->calls==c->limit) { c->out->status=3;return 0; }
    c->sp=(uint16_t)(c->sp-frame);q.kind=kind;q.site=site;q.segment=(uint16_t)(c->load+0x6c9);q.offset=offset;q.argument_count=argc;q.live_argument_count=live;q.stack_segment=c->ss;q.stack_sp=c->sp;q.incoming=c->r;
    for (i=0;i<live;++i) q.arguments[i]=args[i];
    r=c->r;++c->out->calls;
    if (!c->service(c->context,c->m,&q,&r)) { c->out->status=4;return 0; }
    if (r.carry>1 || r.registers.interrupts_enabled>1 || r.registers.direction>1) { c->out->status=2;return 0; }
    c->r=r;c->sp=(uint16_t)(c->sp+frame);return 1;
}
static void cleanup(loop_context *c,uint16_t bytes)
{ c->sp=(uint16_t)(c->sp+bytes);c->r.carry=0; }
void td2ega_loop_control(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,
    uint16_t sp,enum td2ega_loop_control_entry entry,
    const td2ega_state_registers *in,td2ega_loop_control_service service,
    void *context,uint32_t limit,td2ega_loop_control_result *out)
{
    loop_context c;uint16_t args[10]={0},saved[5],value;uint32_t sum;unsigned i;
    if (out==NULL) return;
    *out=(td2ega_loop_control_result){0};out->status=2;
    if (m==NULL || bytes<UINT32_C(0x100000) || in==NULL || service==NULL || entry<TD2EGA_LOOP_1F60 || entry>TD2EGA_LOOP_1F99 || sp<256 || sp>UINT16_C(0xfff0) || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1) return;
    c=(loop_context){m,load,ss,sp,limit,*in,service,context,out};out->return_bytes=4;
    if (entry==TD2EGA_LOOP_1F60) {
        args[0]=word(m,c.r.registers.ds,0x2a20);args[1]=word(m,c.r.registers.ds,0x2a22);c.sp=(uint16_t)(c.sp-4);
        if (!call(&c,1,0x1f68,0x782c,2,2,args)) goto finish;
        cleanup(&c,4);goto normal;
    }
    c.sp=(uint16_t)(c.sp-6);
    if (entry==TD2EGA_LOOP_1F71) {
        put(&c,0x5348,80);
        if (!call(&c,0,0x1f7a,0x21c3,0,0,args) || !call(&c,0,0x1f7d,0x2477,0,0,args) || !call(&c,0,0x1f80,0x2542,0,0,args)) goto finish;
        c.r.registers.ax=word(m,c.r.registers.ds,0x2c2a);c.r.bp=17;
        if (!call(&c,0,0x1f89,0x88e,0,0,args)) goto finish;
    } else {
        put(&c,0x702,UINT16_C(0x28bd));args[0]=word(m,c.r.registers.ds,0x2a20);args[1]=word(m,c.r.registers.ds,0x2a22);c.sp=(uint16_t)(c.sp-4);
        if (!call(&c,1,0x1faa,0x7d5e,2,2,args)) goto finish;
        cleanup(&c,4);
        for (i=0;i<4;++i) { c.r.registers.ax=word(m,(uint16_t)(load+0x6c9),(uint16_t)(0xaf3c+2*i));put(&c,(uint16_t)(0x5420+2*i),c.r.registers.ax); }
        c.r.carry=0;
        if (m[address(c.r.registers.ds,0x33d4)]==0 || word(m,c.r.registers.ds,0x33ce)==0) {
            if (!call(&c,0,0x1fdc,0x26d8,0,0,args) || !call(&c,0,0x1fdf,0x284f,0,0,args)) goto finish;
            c.r.carry=0;
            if (m[address(c.r.registers.ds,0x2c98)]&128) if (!call(&c,0,0x1fe9,0x28f9,0,0,args)) goto finish;
            if (!call(&c,0,0x1fec,0x2958,0,0,args)) goto finish;
        }
        c.r.carry=0;
        if (m[address(c.r.registers.ds,0x33d4)]!=0) {
            c.r.registers.ax=word(m,c.r.registers.ds,0x33ce);c.r.carry=0;
            if (c.r.registers.ax!=0) {
                value=m[address(c.r.registers.ds,0x33d4)];c.r.carry=(uint16_t)(value<4);
                c.r.carry=(uint16_t)((c.r.registers.ax>>2)&1);c.r.registers.ax=(uint16_t)(c.r.registers.ax>>3);
                if (value==4) {
                    c.r.registers.di=c.r.registers.ax;c.r.registers.ax=(uint16_t)(0-c.r.registers.ax);c.r.registers.bx=0;c.r.carry=0;
                    args[0]=word(m,c.r.registers.ds,0x2a24);args[1]=word(m,c.r.registers.ds,0x2a26);args[2]=0;args[3]=c.r.registers.ax;c.sp=(uint16_t)(c.sp-8);
                    if (!call(&c,1,0x201a,0x91a4,4,4,args)) goto finish;
                    cleanup(&c,8);c.r.registers.ax=0;c.r.registers.bx=80;c.r.registers.cx=(uint16_t)(17-c.r.registers.di);c.r.carry=(uint16_t)(17<c.r.registers.di);c.r.registers.dx=180;c.r.registers.di=9;
                    args[0]=0;args[1]=c.r.registers.cx;args[2]=80;args[3]=180;args[4]=9;c.sp=(uint16_t)(c.sp-10);
                } else {
                    sum=(uint32_t)c.r.registers.ax+word(m,c.r.registers.ds,0x2c2a);c.r.registers.ax=(uint16_t)sum;c.r.registers.bx=0;c.r.carry=0;c.r.registers.cx=80;c.r.registers.di=word(m,c.r.registers.ds,0x5350);
                    saved[0]=0;saved[1]=0;saved[2]=80;saved[3]=c.r.registers.ax;saved[4]=c.r.registers.di;c.sp=(uint16_t)(c.sp-10);
                    c.r.registers.dx=0;c.r.registers.bx=(uint16_t)(17-c.r.registers.ax);c.r.carry=(uint16_t)(17<c.r.registers.ax);c.r.registers.di=6;
                    args[0]=0;args[1]=c.r.registers.ax;args[2]=80;args[3]=c.r.registers.bx;args[4]=6;
                    for (i=0;i<5;++i) args[5+i]=saved[i];
                    c.sp=(uint16_t)(c.sp-10);
                    if (!call(&c,1,0x2060,0x89a2,5,10,args)) goto finish;
                    cleanup(&c,10);
                    for (i=0;i<5;++i) args[i]=saved[i];
                }
                if (!call(&c,1,0x2068,0x89a2,5,5,args)) goto finish;
                cleanup(&c,10);
            }
        }
        if (!call(&c,1,0x2070,0x3efc,0,0,args)) goto finish;
        args[0]=word(m,c.r.registers.ds,0x2a24);args[1]=word(m,c.r.registers.ds,0x2a26);c.sp=(uint16_t)(c.sp-4);
        if (!call(&c,1,0x207d,0x9cc2,2,2,args)) goto finish;
        cleanup(&c,4);
    }
    c.r.registers.si=in->registers.si;c.r.registers.ds=in->registers.ds;c.r.bp=in->bp;c.sp=(uint16_t)(c.sp+6);
normal:
    c.sp=(uint16_t)(c.sp+4);out->status=0;
finish:
    out->current_sp=c.sp;out->returned=c.r;
}
