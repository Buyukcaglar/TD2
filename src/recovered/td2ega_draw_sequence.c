#include "td2ega_draw_sequence.h"
#include <stddef.h>
typedef struct draw_context {
    uint8_t *m;uint16_t load,ss,sp,pool[16],live;
    uint32_t limit;td2ega_state_registers r;
    td2ega_draw_sequence_service service;void *context;
    td2ega_draw_sequence_result *out;
} draw_context;
static uint32_t address(uint16_t s,uint16_t o)
{ return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff); }
static uint16_t word(const uint8_t *m,uint16_t s,uint16_t o)
{ uint32_t a=address(s,o);return (uint16_t)(m[a]|((uint16_t)m[(a+1)&UINT32_C(0xfffff)]<<8)); }
static uint16_t read(draw_context *c,uint16_t o)
{ return word(c->m,c->r.registers.ds,o); }
static uint8_t byte(draw_context *c,uint16_t o)
{ return c->m[address(c->r.registers.ds,o)]; }
static void put(draw_context *c,uint16_t o,uint16_t v)
{ uint32_t a=address(c->r.registers.ds,o);c->m[a]=(uint8_t)v;c->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8); }
static int32_t sw(uint16_t v)
{ return v<UINT16_C(0x8000)?v:(int32_t)v-INT32_C(65536); }
static void sub(draw_context *c,uint16_t *v,uint16_t rhs)
{ c->r.carry=(uint16_t)(*v<rhs);*v=(uint16_t)(*v-rhs); }
static void push(draw_context *c,uint16_t v)
{ unsigned i;for (i=c->live;i>0;--i)c->pool[i]=c->pool[i-1];c->pool[0]=v;++c->live;c->sp=(uint16_t)(c->sp-2); }
static void cleanup(draw_context *c,uint16_t words)
{ unsigned i;for (i=words;i<c->live;++i)c->pool[i-words]=c->pool[i];c->live=(uint16_t)(c->live-words);c->sp=(uint16_t)(c->sp+words*2);c->r.carry=0; }
static int call(draw_context *c,uint16_t kind,uint16_t site,uint16_t target,uint16_t argc)
{
    td2ega_draw_sequence_request q={0};td2ega_state_registers r;unsigned i;uint16_t frame=kind?4:2;
    if (c->out->calls==c->limit) { c->out->status=3;return 0; }
    c->sp=(uint16_t)(c->sp-frame);q.kind=kind;q.site=site;q.segment=(uint16_t)(c->load+0x6c9);q.offset=target;q.argument_count=argc;q.live_argument_count=c->live;q.stack_segment=c->ss;q.stack_sp=c->sp;q.incoming=c->r;
    for (i=0;i<c->live;++i)q.arguments[i]=c->pool[i];r=c->r;++c->out->calls;
    if (!c->service(c->context,c->m,&q,&r)) { c->out->status=4;return 0; }
    if (r.carry>1 || r.registers.interrupts_enabled>1 || r.registers.direction>1) { c->out->status=2;return 0; }
    c->r=r;c->sp=(uint16_t)(c->sp+frame);return 1;
}
static void five(draw_context *c,uint16_t a,uint16_t b,uint16_t d,uint16_t e,uint16_t f)
{ push(c,a);push(c,b);push(c,d);push(c,e);push(c,f); }
void td2ega_draw_sequence(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,
    uint16_t sp,uint16_t entry,const td2ega_state_registers *in,
    td2ega_draw_sequence_service service,void *context,uint32_t limit,
    td2ega_draw_sequence_result *out)
{
    draw_context c;uint16_t v,saved;unsigned i;
    if (out==NULL)return;
    *out=(td2ega_draw_sequence_result){0};out->status=2;
    if (m==NULL || bytes<UINT32_C(0x100000) || in==NULL || service==NULL || entry>2 || sp<256 || sp>UINT16_C(0xfff0) || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1)return;
    c=(draw_context){0};c.m=m;c.load=load;c.ss=ss;c.sp=sp;c.limit=limit;c.r=*in;c.service=service;c.context=context;c.out=out;out->return_bytes=2;
#define R c.r.registers
#define W(o) read(&c,(uint16_t)(o))
#define B(o) byte(&c,(uint16_t)(o))
#define CALL(k,s,t,a) do { if (!call(&c,k,s,t,a))goto finish; } while (0)
    if (entry==0) {
        R.si=0;c.r.carry=0;R.ax=W(0x2c2a);c.r.carry=0;
        if (B(0x37f7)!=0)goto whole;
        R.bx=(uint16_t)((R.bx&UINT16_C(0xff00))|B(0x2c98));c.r.carry=0;
        if (R.bx&128) {
            R.di=W(0x2c34);c.r.bp=W(0x2c84);c.r.carry=0;
            if (B(0x2c97)&128) {
                R.bx=W(0x2c7a);R.cx=W(0x2c7c);sub(&c,&R.cx,R.bx);sub(&c,&c.r.bp,R.di);R.dx=0;five(&c,R.dx,R.cx,c.r.bp,R.bx,R.di);goto final_five;
            }
            R.ax=W(0x2c7a);R.cx=W(0x2c7e);sub(&c,&R.cx,R.ax);sub(&c,&c.r.bp,R.di);R.dx=0;five(&c,R.dx,R.cx,c.r.bp,R.ax,R.di);v=c.r.bp;c.r.bp=(uint16_t)(c.r.bp+R.di);c.r.carry=(uint16_t)(c.r.bp<v);
            c.r.carry=0;
            if (R.bx&0x40) {
                R.ax=W(0x2c66);R.bx=W(0x2c7e);R.cx=W(0x2c2a);sub(&c,&R.cx,R.bx);R.dx=W(0x5350);sub(&c,&c.r.bp,R.ax);five(&c,R.dx,R.cx,c.r.bp,R.bx,R.ax);
            } else {
                R.ax=W(0x2c2c);R.bx=W(0x2c7e);R.cx=W(0x2c2a);sub(&c,&R.cx,R.bx);R.dx=W(0x5350);sub(&c,&R.ax,R.di);five(&c,R.dx,R.cx,R.ax,R.bx,R.di);
            }
            CALL(1,0x2767,0x89a2,5);cleanup(&c,5);goto final_five;
        }
        c.r.carry=0;
        if (R.bx&0x40) {
            c.r.carry=0;
            if (R.bx&8) { R.dx=W(0x5350);R.bx=W(0x2c66);R.cx=W(0x2c2c);sub(&c,&R.cx,R.bx);five(&c,R.dx,R.ax,R.cx,R.si,R.bx); }
            else { R.cx=80;R.dx=W(0x5350);R.bx=W(0x2c66);sub(&c,&R.cx,R.bx);five(&c,R.dx,R.ax,R.cx,R.si,R.bx); }
        } else {
            c.r.carry=0;if ((R.bx&8)==0)goto whole;
            R.cx=W(0x2c2c);R.dx=W(0x5350);five(&c,R.dx,R.ax,R.cx,R.si,R.si);
        }
final_five:
        CALL(1,0x27b4,0x89a2,5);cleanup(&c,5);goto normal;
whole:
        R.dx=W(0x5350);R.cx=80;five(&c,R.dx,R.ax,R.cx,R.si,R.si);CALL(1,0x27c9,0x89a2,5);cleanup(&c,5);c.r.carry=0;
        if (B(0x37f8)!=0)goto normal;
        v=W(0x27e0);c.r.carry=0;if (v==0)goto normal;
        R.di=W(0x5344);R.ax=W(0x2f48);
        for (i=0;i<3;++i) { c.r.carry=(uint16_t)(R.ax>>15);R.ax=(uint16_t)(R.ax<<1); }
        R.ax=(uint16_t)((R.ax&UINT16_C(0xff00))|(R.ax>>8));R.ax=(uint8_t)R.ax<128?(uint8_t)R.ax:(uint16_t)(UINT16_C(0xff00)|(uint8_t)R.ax);sub(&c,&R.di,R.ax);R.di&=0x3ff;c.r.carry=0;c.r.carry=(uint16_t)(R.di&1);R.di=(uint16_t)(R.di>>1);R.ax=W(0x2b56);
        push(&c,R.ax);push(&c,R.di);push(&c,W(0x27e0));push(&c,W(0x27de));sub(&c,&R.di,0x96);
        push(&c,R.ax);push(&c,R.di);push(&c,W(0x27e4));push(&c,W(0x27e2));sub(&c,&R.di,0x64);
        push(&c,R.ax);push(&c,R.di);push(&c,W(0x27e8));push(&c,W(0x27e6));sub(&c,&R.di,0x106);
        push(&c,R.ax);push(&c,R.di);push(&c,W(0x27e0));push(&c,W(0x27de));
        CALL(1,0x282e,0x916c,4);cleanup(&c,4);CALL(1,0x2836,0x916c,4);cleanup(&c,4);CALL(1,0x283e,0x916c,4);cleanup(&c,4);CALL(1,0x2846,0x916c,4);cleanup(&c,4);
    } else if (entry==1) {
        R.es=W(0x2a26);R.si=W(0x2c2a);c.r.carry=(uint16_t)(R.si>>15);R.si=(uint16_t)(R.si<<1);R.direction=0;R.bx=R.si;v=W(0x2a28);saved=R.bx;R.bx=(uint16_t)(R.bx+v);c.r.carry=(uint16_t)(R.bx<saved);R.di=word(m,(uint16_t)(load+0x6c9),R.bx);
        do {
            R.dx=0;c.r.carry=0;put(&c,0x9be,R.dx);put(&c,0x9c0,R.dx);c.r.carry=0;
            if (W(R.si+0xd5c)&0x20) {
                R.bx=W(0x5350);v=W(0x2c86);c.r.carry=(uint16_t)(R.si<v);
                if (sw(R.si)<sw(v))goto first_value;
                R.ax=W(0x2c2e);v=W(R.si+0x9c4);c.r.carry=(uint16_t)(R.ax<v);
                if (sw(R.ax)>=sw(v))goto first_value;
                CALL(0,0x28d8,0xc17,0);
            }
            R.bx=W(0x534a);
first_value:
            R.ax=W(R.si+0x9c4);CALL(0,0x287d,0xc17,0);R.bx=W(0x534e);R.ax=W(R.si+0xa7c);CALL(0,0x2888,0xc17,0);R.bx=7;R.ax=W(R.si+0xb34);CALL(0,0x2892,0xc17,0);R.bx=W(0x534e);R.ax=W(R.si+0xbec);CALL(0,0x289d,0xc17,0);c.r.carry=0;
            if (W(R.si+0xd5c)&4) {
                R.bx=W(0x534c);v=W(0x2c88);c.r.carry=(uint16_t)(R.si<v);
                if (sw(R.si)>=sw(v)) {
                    R.ax=W(0x2c68);v=W(R.si+0xbec);c.r.carry=(uint16_t)(R.ax<v);
                    if (sw(R.ax)>=sw(v)) { CALL(0,0x28f0,0xc17,0); }
                }
                R.bx=W(0x5350);
            } else { R.bx=W(0x534c);R.ax=W(R.si+0xca4);CALL(0,0x28b0,0xc17,0);R.bx=W(0x5352); }
            R.ax=80;CALL(0,0x28ba,0xc17,0);R.si=(uint16_t)(R.si+2);c.r.carry=(uint16_t)(R.si<34);
        } while (R.si!=34);
    } else {
        R.es=W(0x2a26);v=W(0x2c30);c.r.carry=(uint16_t)(v>>15);put(&c,0x2c30,(uint16_t)(v<<1));R.si=W(0x2c78);R.di=R.si;c.r.carry=(uint16_t)(R.si>>15);R.si=(uint16_t)(R.si<<1);v=W(0x2c30);c.r.carry=(uint16_t)(R.si<v);
        if (sw(R.si)<sw(v))do {
            R.dx=W(0x2c82);R.ax=W(R.si+0xa7c);c.r.carry=0;
            if (B(0x37f7)==0) { R.bx=0;CALL(0,0x2921,0xd01,0);R.dx=W(R.si+0xa7c);R.ax=W(R.si+0xb34);R.bx=8;CALL(0,0x292f,0xd01,0);R.bx=0; }
            else { R.bx=8;CALL(0,0x293a,0xd01,0);R.bx=8; }
            R.dx=W(R.si+0xb34);R.ax=W(0x2c32);CALL(0,0x2947,0xd01,0);R.di=(uint16_t)(R.di+1);R.si=(uint16_t)(R.si+2);v=W(0x2c30);c.r.carry=(uint16_t)(R.si<v);
        } while (sw(R.si)<sw(v));
        v=W(0x2c30);c.r.carry=(uint16_t)(v&1);put(&c,0x2c30,(uint16_t)(v>>1));
    }
normal:
    c.sp=(uint16_t)(c.sp+2);out->status=0;
finish:
    out->current_sp=c.sp;out->returned=c.r;
#undef R
#undef W
#undef B
#undef CALL
}
