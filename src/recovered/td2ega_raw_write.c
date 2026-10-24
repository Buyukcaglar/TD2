#include "td2ega_raw_write.h"
#include <stddef.h>
typedef struct context {
    uint8_t *m;uint16_t load,ss,sp,cs;uint32_t limit;
    td2ega_state_registers r;td2ega_small_platform_service service;
    void *user;td2ega_raw_write_result *out;
} context;
static uint32_t address(uint16_t s,uint16_t o)
{return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(context *c,uint16_t s,uint16_t o)
{uint32_t a=address(s,o);return (uint16_t)(c->m[a]|((uint16_t)c->m[(a+1)&UINT32_C(0xfffff)]<<8));}
static void put(context *c,uint16_t s,uint16_t o,uint16_t v)
{uint32_t a=address(s,o);c->m[a]=(uint8_t)v;c->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++c->out->bus_writes;}
static uint16_t frame_word(context *c,int offset)
{return word(c,c->ss,(uint16_t)(c->r.bp+offset));}
static void frame_put(context *c,int offset,uint16_t v)
{put(c,c->ss,(uint16_t)(c->r.bp+offset),v);}
static void push(context *c,uint16_t v)
{c->sp=(uint16_t)(c->sp-2);put(c,c->ss,c->sp,v);}
static uint16_t pop(context *c)
{uint16_t v=word(c,c->ss,c->sp);c->sp=(uint16_t)(c->sp+2);return v;}
static void ah(context *c,uint16_t v)
{c->r.registers.ax=(uint16_t)((c->r.registers.ax&255)|((v&255)<<8));}
static int service(context *c,uint16_t site)
{
    td2ega_small_platform_request q={0};td2ega_state_registers returned;
    if(c->out->services==c->limit){c->out->status=3;return 0;}
    q.vector=0x21;q.site=site;q.segment=c->cs;q.stack_segment=c->ss;q.stack_sp=c->sp;q.incoming=c->r;returned=c->r;++c->out->services;
    if(site==0x78c7)++c->out->write_requests;
    if(!c->service(c->user,c->m,&q,&returned)){c->out->status=4;return 0;}
    if(returned.carry>1 || returned.registers.interrupts_enabled>1 || returned.registers.direction>1){c->out->status=2;return 0;}
    c->r=returned;return 1;
}
void td2ega_raw_write(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,
    uint16_t sp,uint16_t entry,const td2ega_state_registers *in,
    td2ega_small_platform_service adapter,void *user,uint32_t limit,
    td2ega_raw_write_result *out)
{
    context c;uint16_t old,borrow,high;uint32_t sum;
    if(out==NULL)return;
    *out=(td2ega_raw_write_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || adapter==NULL || entry>1 || sp<32 || sp>UINT16_C(0xffd0) || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1)return;
    c=(context){m,load,ss,sp,(uint16_t)(load+0x6c9),limit,*in,adapter,user,out};push(&c,c.r.bp);c.r.bp=c.sp;
#define R c.r.registers
#define W(n) frame_word(&c,n)
#define P(n,value) frame_put(&c,n,value)
#define SERVICE(site) do{if(!service(&c,site))goto finish;}while(0)
    push(&c,R.ds);push(&c,R.si);push(&c,R.di);P(-10,entry);c.r.carry=(uint16_t)(c.sp<4);c.sp=(uint16_t)(c.sp-4);R.dx=W(6);R.cx=0;c.r.carry=0;ah(&c,0x3c);SERVICE(0x7889);
    if(c.r.carry)goto error;
    P(-8,R.ax);
loop:
    c.r.carry=0;if(W(12)!=0)goto write;
    c.r.carry=0;if(W(14)==0)goto close;
write:
    R.cx=0x4000;R.ax=W(12);old=W(12);borrow=(uint16_t)(old<R.cx);P(12,(uint16_t)(old-R.cx));high=W(14);c.r.carry=(uint16_t)(high<borrow);P(14,(uint16_t)(high-borrow));
    if(c.r.carry){R.cx=W(12);P(12,0);P(14,0);sum=(uint32_t)R.cx+0x4000;R.cx=(uint16_t)sum;c.r.carry=(uint16_t)(sum>>16);}
    R.ds=W(10);R.dx=W(8);R.bx=W(-8);ah(&c,0x40);SERVICE(0x78c7);
    if(c.r.carry)goto error;
    ++out->successful_writes;sum=(uint32_t)W(10)+0x400;P(10,(uint16_t)sum);c.r.carry=(uint16_t)(sum>>16);goto loop;
error:
    c.r.carry=0;if(W(-10)!=0)goto close;
    R.ax=0x6808;R.ds=W(-2);push(&c,W(6));push(&c,R.ax);push(&c,c.cs);push(&c,0x78e7);out->error_calls=1;out->status=1;out->next_segment=(uint16_t)(load+0x16a7);out->next_ip=2;goto finish;
close:
    R.bx=W(-8);ah(&c,0x3e);SERVICE(0x78ec);R.ax=0;c.r.carry=0;sum=(uint32_t)c.sp+4;c.sp=(uint16_t)sum;c.r.carry=(uint16_t)(sum>>16);R.di=pop(&c);R.si=pop(&c);R.ds=pop(&c);c.r.bp=pop(&c);out->next_ip=pop(&c);out->next_segment=pop(&c);out->status=0;
finish:
    out->current_sp=c.sp;out->returned=c.r;
#undef R
#undef W
#undef P
#undef SERVICE
}
