#include "td2ega_runtime_vectors.h"
#include <stddef.h>
typedef struct work {
    uint8_t *m;uint16_t cs,ss,sp;uint32_t limit;
    td2ega_state_registers r;td2ega_runtime_vectors_result *out;
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
static int valid(const td2ega_state_registers *r)
{return r->carry<=1 && r->registers.interrupts_enabled<=1 && r->registers.direction<=1;}
static void lds(work *w,uint16_t o)
{uint16_t segment=word(w,w->r.registers.ds,(uint16_t)(o+2));w->r.registers.dx=word(w,w->r.registers.ds,o);w->r.registers.ds=segment;}
static int service(work *w,uint16_t ip,td2ega_small_platform_service dos,void *context)
{
    td2ega_small_platform_request request;td2ega_state_registers returned;
    if(!step(w,ip))return 0;
    request=(td2ega_small_platform_request){0x21,ip,w->cs,w->ss,w->sp,w->r};returned=w->r;if(dos==NULL || !dos(context,w->m,&request,&returned) || !valid(&returned)){w->out->status=4;w->out->next_segment=w->cs;w->out->next_ip=ip;return 0;}++w->out->services;w->r=returned;return 1;
}
void td2ega_runtime_vectors(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,
    uint16_t sp,const td2ega_state_registers *in,td2ega_small_platform_service dos,
    td2ega_finalizer_service callback,void *context,uint32_t limit,
    td2ega_runtime_vectors_result *out)
{
    work w;uint16_t segment,ip;td2ega_finalizer_request request;td2ega_state_registers returned;
    if(out==NULL)return;
    *out=(td2ega_runtime_vectors_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || sp<16 || sp>UINT16_C(0xffe0) || !valid(in))return;
    w=(work){m,(uint16_t)(load+0x13a8),ss,sp,limit,*in,out};w.r.registers.cx=word(&w,w.r.registers.ds,0x7078);
    if(w.r.registers.cx!=0){
        w.r.registers.bx=2;if(!step(&w,0x5e9))goto finish;ip=word(&w,w.r.registers.ds,0x7076);segment=word(&w,w.r.registers.ds,0x7078);push(&w,w.cs);push(&w,0x5ed);out->next_segment=segment;out->next_ip=ip;request=(td2ega_finalizer_request){0x5e9,segment,ip,ss,w.sp,w.r};returned=w.r;
        if(callback==NULL || !callback(context,m,&request,&returned) || !valid(&returned)){out->status=4;goto finish;}++out->callbacks;w.r=returned;ip=pop(&w);segment=pop(&w);if(segment!=w.cs || ip!=0x5ed){out->status=1;out->next_segment=segment;out->next_ip=ip;goto finish;}
    }
    push(&w,w.r.registers.ds);lds(&w,0x6d89);w.r.registers.ax=0x2500;if(!service(&w,0x5f5,dos,context))goto finish;w.r.registers.ds=pop(&w);w.r.carry=0;
    if(w.m[address(w.r.registers.ds,0x6dc6)]!=0){
        push(&w,w.r.registers.ds);w.r.registers.ax=(uint16_t)((w.r.registers.ax&0xff00)|w.m[address(w.r.registers.ds,0x6dc7)]);lds(&w,0x6dc8);w.r.registers.ax=(uint16_t)((w.r.registers.ax&0xff)|0x2500);if(!service(&w,0x609,dos,context))goto finish;w.r.registers.ds=pop(&w);
    }
    out->next_segment=w.cs;out->next_ip=pop(&w);out->status=0;
finish:
    out->current_sp=w.sp;out->returned=w.r;
}
