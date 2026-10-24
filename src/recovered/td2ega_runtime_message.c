#include "td2ega_runtime_message.h"
#include <stddef.h>
typedef struct work {
    uint8_t *m;uint16_t cs,ss,sp;uint32_t limit;
    td2ega_state_registers r;td2ega_runtime_message_result *out;
} work;
static uint32_t address(uint16_t s,uint16_t o)
{return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(work *w,uint16_t s,uint16_t o)
{uint32_t a=address(s,o);return (uint16_t)(w->m[a]|((uint16_t)w->m[(a+1)&UINT32_C(0xfffff)]<<8));}
static void push(work *w,uint16_t v)
{uint32_t a;w->sp=(uint16_t)(w->sp-2);a=address(w->ss,w->sp);w->m[a]=(uint8_t)v;w->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++w->out->bus_writes;}
static uint16_t pop(work *w)
{uint16_t v=word(w,w->ss,w->sp);w->sp=(uint16_t)(w->sp+2);return v;}
static int step(work *w,uint16_t ip)
{if(w->out->operations==w->limit){w->out->status=3;w->out->next_segment=w->cs;w->out->next_ip=ip;return 0;}++w->out->operations;return 1;}
static uint16_t advance(work *w,uint16_t v,unsigned size)
{return (uint16_t)(v+(w->r.registers.direction?-(int)size:(int)size));}
static int scan(work *w,uint16_t ip)
{
    while(w->r.registers.cx!=0){uint8_t value;if(!step(w,ip))return 0;value=w->m[address(w->r.registers.es,w->r.registers.di)];w->r.carry=(uint16_t)((uint8_t)w->r.registers.ax<value);w->r.registers.di=advance(w,w->r.registers.di,1);--w->r.registers.cx;if((uint8_t)w->r.registers.ax==value)break;}
    return 1;
}
static int lookup(work *w)
{
    uint16_t old;int equal;
    push(w,w->r.bp);w->r.bp=w->sp;push(w,w->r.registers.si);push(w,w->r.registers.di);push(w,w->r.registers.ds);w->r.registers.es=pop(w);w->r.registers.dx=word(w,w->ss,(uint16_t)(w->r.bp+6));w->r.registers.si=0x82c4;
    for(;;){
        if(!step(w,0x899))return 0;++w->out->rows;w->r.registers.ax=word(w,w->r.registers.ds,w->r.registers.si);w->r.registers.si=advance(w,w->r.registers.si,2);w->r.carry=(uint16_t)(w->r.registers.ax<w->r.registers.dx);if(w->r.registers.ax==w->r.registers.dx)break;
        ++w->r.registers.ax;equal=w->r.registers.ax==0;old=w->r.registers.si;w->r.registers.si=w->r.registers.ax;w->r.registers.ax=old;if(equal)break;old=w->r.registers.di;w->r.registers.di=w->r.registers.ax;w->r.registers.ax=old;w->r.registers.ax=0;w->r.carry=0;w->r.registers.cx=0xffff;if(!scan(w,0x8a8))return 0;w->r.registers.si=w->r.registers.di;
    }
    old=w->r.registers.si;w->r.registers.si=w->r.registers.ax;w->r.registers.ax=old;w->r.registers.di=pop(w);w->r.registers.si=pop(w);w->sp=w->r.bp;w->r.bp=pop(w);w->out->next_ip=pop(w);w->out->next_segment=pop(w);w->sp=(uint16_t)(w->sp+2);return 1;
}
static int valid(const td2ega_state_registers *r)
{return r->carry<=1 && r->registers.interrupts_enabled<=1 && r->registers.direction<=1;}
void td2ega_runtime_message(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,
    uint16_t sp,uint16_t entry,const td2ega_state_registers *in,
    td2ega_small_platform_service service,void *context,uint32_t limit,
    td2ega_runtime_message_result *out)
{
    work w;uint16_t old;td2ega_small_platform_request request;td2ega_state_registers returned;
    if(out==NULL)return;
    *out=(td2ega_runtime_message_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || entry>1 || sp<32 || sp>UINT16_C(0xffe0) || !valid(in))return;
    w=(work){m,(uint16_t)(load+0x13a8),ss,sp,limit,*in,out};
    if(entry==0){if(!lookup(&w))goto finish;out->status=0;goto finish;}
    push(&w,w.r.bp);w.r.bp=w.sp;push(&w,w.r.registers.di);push(&w,word(&w,ss,(uint16_t)(w.r.bp+6)));push(&w,w.cs);push(&w,0x8c3);
    if(!lookup(&w))goto finish;
    if(out->next_segment!=w.cs || out->next_ip!=0x8c3){out->status=1;goto finish;}
    w.r.carry=0;if(w.r.registers.ax!=0){
        old=w.r.registers.dx;w.r.registers.dx=w.r.registers.ax;w.r.registers.ax=old;w.r.registers.di=w.r.registers.dx;w.r.registers.ax=0;w.r.carry=0;w.r.registers.cx=0xffff;if(!scan(&w,0x8cf))goto finish;w.r.registers.cx=(uint16_t)~w.r.registers.cx;--w.r.registers.cx;w.r.registers.bx=2;w.r.registers.ax=0x4000;
        if(!step(&w,0x8d9))goto finish;
        request=(td2ega_small_platform_request){0x21,0x8d9,w.cs,ss,w.sp,w.r};returned=w.r;
        if(service==NULL || !service(context,m,&request,&returned) || !valid(&returned)){out->status=4;out->next_segment=w.cs;out->next_ip=0x8d9;goto finish;}++out->services;w.r=returned;
    }
    w.r.registers.di=pop(&w);w.sp=w.r.bp;w.r.bp=pop(&w);out->next_ip=pop(&w);out->next_segment=pop(&w);w.sp=(uint16_t)(w.sp+2);out->status=0;
finish:
    out->current_sp=w.sp;out->returned=w.r;
}
