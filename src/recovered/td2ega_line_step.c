#include "td2ega_line_step.h"
#include <stddef.h>
typedef struct line_context {
    uint8_t *m;uint16_t cs;uint32_t limit;
    td2ega_state_registers r;td2ega_line_step_result *out;
} line_context;
static uint32_t address(uint16_t s,uint16_t o)
{ return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff); }
static uint16_t word(const uint8_t *m,uint16_t s,uint16_t o)
{ uint32_t a=address(s,o);return (uint16_t)(m[a]|((uint16_t)m[(a+1)&UINT32_C(0xfffff)]<<8)); }
static int32_t signed_word(uint16_t v)
{ return v<UINT16_C(0x8000)?(int32_t)v:(int32_t)v-INT32_C(65536); }
static int tick(line_context *c)
{ if (c->out->work==c->limit) { c->out->status=3;return 0; }++c->out->work;return 1; }
static void store(line_context *c)
{
    uint32_t a=address(c->r.registers.es,c->r.registers.di);c->m[a]=(uint8_t)c->r.registers.ax;c->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(c->r.registers.ax>>8);
    c->r.registers.di=(uint16_t)(c->r.registers.di+(c->r.registers.direction?UINT16_C(0xfffe):2));++c->out->words;
}
static void sub(line_context *c,uint16_t *r,uint16_t v)
{ c->r.carry=(uint16_t)(*r<v);*r=(uint16_t)(*r-v); }
static void add(line_context *c,uint16_t *r,uint16_t v)
{ uint32_t sum=(uint32_t)*r+v;*r=(uint16_t)sum;c->r.carry=(uint16_t)(sum>>16); }
void td2ega_line_step(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,
    uint16_t sp,uint16_t destination,uint16_t second,uint16_t first,
    const td2ega_state_registers *in,uint32_t limit,td2ega_line_step_result *out)
{
    line_context c;uint16_t bound,delta;int32_t difference;int direction;
    if (out==NULL) return;
    *out=(td2ega_line_step_result){0};out->status=2;
    if (m==NULL || bytes<UINT32_C(0x100000) || in==NULL || sp<256 || sp>UINT16_C(0xfff0) || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1) return;
    c=(line_context){m,(uint16_t)(load+0x6c9),limit,*in,out};out->stack_segment=ss;out->current_sp=(uint16_t)(sp-8);out->return_bytes=8;
    c.r.bp=(uint16_t)(sp-2);c.r.registers.ax=first;c.r.registers.bx=second;c.r.registers.di=destination;c.r.carry=0;
    if (signed_word(first)<=0 && signed_word(second)<=0) { c.r.registers.ax=0;goto fill; }
    bound=word(m,c.r.registers.ds,UINT16_C(0x5348));c.r.carry=(uint16_t)(first<bound);
    if (signed_word(first)>=signed_word(bound)) {
        c.r.carry=(uint16_t)(second<bound);
        if (signed_word(second)>=signed_word(bound)) { c.r.registers.ax=bound;goto fill; }
    }
    if (!tick(&c)) goto finish;
    store(&c);c.r.registers.cx=(uint16_t)(c.r.registers.cx-1);difference=signed_word(c.r.registers.bx)-signed_word(c.r.registers.ax);sub(&c,&c.r.registers.bx,c.r.registers.ax);
    if (c.r.registers.bx==0) goto fill;
    if (difference>0) direction=1;
    else { c.r.carry=1;c.r.registers.bx=(uint16_t)(0-c.r.registers.bx);direction=-1; }
    if (!tick(&c)) goto finish;
    m[address(c.cs,UINT16_C(0x71f))]=(uint8_t)(direction>0?0x40:0x48);
    if (!tick(&c)) goto finish;
    m[address(c.cs,UINT16_C(0x735))]=(uint8_t)(direction>0?0x40:0x48);
    c.r.carry=(uint16_t)(c.r.registers.bx<c.r.registers.dx);
    if (c.r.registers.bx>c.r.registers.dx) {
        c.r.bp=c.r.registers.bx;c.r.registers.si=0;c.r.carry=0;
        for (;;) {
            if (!tick(&c)) goto finish;
            add(&c,&c.r.registers.si,c.r.registers.dx);c.r.registers.ax=(uint16_t)(c.r.registers.ax+direction);c.r.carry=(uint16_t)(c.r.registers.si<c.r.registers.bx);
            if (signed_word(c.r.registers.si)<signed_word(c.r.registers.bx)) continue;
            sub(&c,&c.r.registers.si,c.r.bp);store(&c);c.r.registers.cx=(uint16_t)(c.r.registers.cx-1);
            if (c.r.registers.cx==0) break;
        }
    } else {
        c.r.bp=c.r.registers.dx;c.r.registers.si=0;c.r.carry=0;
        do {
            if (!tick(&c)) goto finish;
            add(&c,&c.r.registers.si,c.r.registers.bx);c.r.carry=(uint16_t)(c.r.registers.si<c.r.registers.dx);
            if (signed_word(c.r.registers.si)>=signed_word(c.r.registers.dx)) { c.r.registers.ax=(uint16_t)(c.r.registers.ax+direction);sub(&c,&c.r.registers.si,c.r.bp); }
            store(&c);c.r.registers.cx=(uint16_t)(c.r.registers.cx-1);
        } while (c.r.registers.cx!=0);
    }
    goto normal;
fill:
    while (c.r.registers.cx!=0) {
        if (!tick(&c)) goto finish;
        store(&c);c.r.registers.cx=(uint16_t)(c.r.registers.cx-1);
    }
normal:
    c.r.bp=in->bp;c.r.registers.bx=in->registers.bx;c.r.registers.cx=in->registers.cx;c.r.registers.dx=in->registers.dx;out->current_sp=(uint16_t)(sp+8);out->status=0;
finish:
    delta=m[address(c.cs,UINT16_C(0x71f))];out->opcode_first=delta;out->opcode_second=m[address(c.cs,UINT16_C(0x735))];out->returned=c.r;
}
