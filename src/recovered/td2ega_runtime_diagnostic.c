#include "td2ega_runtime_diagnostic.h"
#include <stddef.h>
typedef struct work {
    uint8_t *m;uint32_t bytes;uint16_t load,cs,ss,sp;uint32_t limit;
    td2ega_state_registers r;td2ega_small_platform_service dos;
    td2ega_finalizer_service callback;void *context;
    td2ega_runtime_diagnostic_result *out;
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
static int message(work *w,uint16_t key,uint16_t ret)
{
    td2ega_runtime_message_result result;
    w->r.registers.ax=key;push(w,w->r.registers.ax);push(w,w->cs);push(w,ret);td2ega_runtime_message(w->m,w->bytes,w->load,w->ss,w->sp,1,&w->r,w->dos,w->context,w->limit-w->out->operations,&result);w->r=result.returned;w->sp=result.current_sp;w->out->operations+=result.operations;w->out->rows+=result.rows;w->out->services+=result.services;w->out->bus_writes+=result.bus_writes;w->out->next_segment=result.next_segment;w->out->next_ip=result.next_ip;
    if(result.status!=0){w->out->status=result.status;return 0;}if(result.next_segment!=w->cs || result.next_ip!=ret){w->out->status=1;return 0;}return 1;
}
static void root_return(work *w)
{w->out->next_ip=pop(w);w->out->next_segment=pop(w);}
static int diagnostic(work *w)
{
    uint16_t segment,ip;td2ega_finalizer_request request;td2ega_state_registers returned;
    push(w,w->r.bp);w->r.bp=w->sp;if(!message(w,0xfc,0x62c))return 0;
    segment=word(w,w->r.registers.ds,0x6dce);w->r.carry=0;
    if(segment!=0){
        if(!step(w,0x633))return 0;
        ip=word(w,w->r.registers.ds,0x6dcc);push(w,w->cs);push(w,0x637);w->out->next_segment=segment;w->out->next_ip=ip;request=(td2ega_finalizer_request){0x633,segment,ip,w->ss,w->sp,w->r};returned=w->r;
        if(w->callback==NULL || !w->callback(w->context,w->m,&request,&returned) || !valid(&returned)){w->out->status=4;return 0;}++w->out->callbacks;w->r=returned;ip=pop(w);segment=pop(w);if(segment!=w->cs || ip!=0x637){w->out->status=1;w->out->next_segment=segment;w->out->next_ip=ip;return 0;}
    }
    if(!message(w,0xff,0x640))return 0;
    w->sp=w->r.bp;w->r.bp=pop(w);root_return(w);return 1;
}
void td2ega_runtime_diagnostic(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,
    uint16_t sp,uint16_t entry,const td2ega_state_registers *in,
    td2ega_small_platform_service dos,td2ega_finalizer_service callback,
    void *context,uint32_t limit,td2ega_runtime_diagnostic_result *out)
{
    work w;uint16_t ret_ip,ret_segment;uint8_t value;
    if(out==NULL)return;
    *out=(td2ega_runtime_diagnostic_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || entry>1 || sp<48 || sp>UINT16_C(0xffe0) || !valid(in))return;
    w=(work){m,bytes,load,(uint16_t)(load+0x13a8),ss,sp,limit,*in,dos,callback,context,out};
    if(entry==0){if(!diagnostic(&w))goto finish;out->status=0;goto finish;}
    push(&w,w.r.registers.si);w.r.registers.si=0;w.r.carry=0;w.r.registers.cx=0x42;w.r.registers.ax&=0xff;w.r.registers.direction=0;
    do{
        if(!step(&w,0x677))goto finish;
        value=w.m[address(w.r.registers.ds,w.r.registers.si)];++w.r.registers.si;w.r.registers.ax=(uint16_t)((w.r.registers.ax&0xff00)|value);w.r.registers.ax^=(uint16_t)((uint16_t)value<<8);w.r.carry=0;--w.r.registers.cx;
    }while(w.r.registers.cx!=0);
    w.r.registers.ax^=0x5500;w.r.carry=0;
    if(w.r.registers.ax&0xff00){
        push(&w,w.cs);push(&w,0x686);if(!diagnostic(&w))goto finish;ret_ip=out->next_ip;ret_segment=out->next_segment;if(ret_segment!=w.cs || ret_ip!=0x686){out->status=1;goto finish;}
        if(!message(&w,1,0x68f))goto finish;
        w.r.registers.ax=1;
    }
    w.r.registers.si=pop(&w);root_return(&w);out->status=0;
finish:
    out->current_sp=w.sp;out->returned=w.r;
}
