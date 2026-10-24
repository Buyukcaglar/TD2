#include "td2ega_runtime_early_exit.h"
#include <stddef.h>
typedef struct work {
    uint8_t *m;uint32_t bytes;uint16_t load,cs,ss,sp;uint32_t limit;
    td2ega_state_registers r;td2ega_small_platform_service dos;
    td2ega_finalizer_service callback;void *context;td2ega_runtime_exit_result *out;
} work;
static uint32_t address(uint16_t s,uint16_t o)
{return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(work *w,uint16_t s,uint16_t o)
{uint32_t a=address(s,o);return (uint16_t)(w->m[a]|((uint16_t)w->m[(a+1)&UINT32_C(0xfffff)]<<8));}
static void put(work *w,uint16_t s,uint16_t o,uint16_t v)
{uint32_t a=address(s,o);w->m[a]=(uint8_t)v;w->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++w->out->bus_writes;}
static void push(work *w,uint16_t v)
{w->sp=(uint16_t)(w->sp-2);put(w,w->ss,w->sp,v);}
static int valid(const td2ega_state_registers *r)
{return r->carry<=1 && r->registers.interrupts_enabled<=1 && r->registers.direction<=1;}
static int step(work *w,uint16_t ip)
{if(w->out->operations==w->limit){w->out->status=3;w->out->next_segment=w->cs;w->out->next_ip=ip;return 0;}++w->out->operations;return 1;}
static int returned(work *w,uint16_t status,uint16_t segment,uint16_t ip,
    uint16_t expected_ip,uint16_t expected_sp)
{
    w->out->next_segment=segment;w->out->next_ip=ip;
    if(status!=0){w->out->status=status;return 0;}
    if(segment!=w->cs || ip!=expected_ip || w->sp!=expected_sp){w->out->status=1;return 0;}return 1;
}
static int walk(work *w,uint16_t low,uint16_t high,uint16_t ret,uint32_t row_limit)
{
    td2ega_finalizer_result result;uint16_t expected_sp=w->sp;
    w->r.registers.si=low;w->r.registers.di=high;push(w,ret);td2ega_finalizer_list(w->m,w->bytes,w->load,w->ss,w->sp,&w->r,w->callback,w->context,row_limit,&result);w->r=result.returned;w->sp=result.current_sp;w->out->operations+=result.iterations;w->out->callbacks+=result.calls;w->out->bus_writes+=result.bus_writes;return returned(w,result.status,result.next_segment,result.next_ip,ret,expected_sp);
}
void td2ega_runtime_early_exit(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,
    uint16_t sp,const td2ega_state_registers *in,td2ega_small_platform_service dos,
    td2ega_finalizer_service callback,void *context,uint32_t limit,
    td2ega_runtime_exit_result *out)
{
    work w;uint16_t expected_sp;td2ega_runtime_diagnostic_result diagnostic;
    td2ega_runtime_vectors_result vectors;td2ega_small_platform_request request;
    td2ega_state_registers response;
    if(out==NULL)return;
    *out=(td2ega_runtime_exit_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || sp<80 || sp>UINT16_C(0xffe0) || !valid(in))return;
    w=(work){m,bytes,load,(uint16_t)(load+0x13a8),ss,sp,limit,*in,dos,callback,context,out};push(&w,w.r.bp);w.r.bp=w.sp;
    if(!walk(&w,0x841a,0x841a,0x58e,limit-out->operations) || !walk(&w,0x7082,0x7086,0x597,limit-out->operations) || !walk(&w,0x7086,0x7086,0x5a5,limit-out->operations) || !walk(&w,0x7086,0x7086,0x5ae,limit-out->operations))goto finish;
    expected_sp=w.sp;push(&w,w.cs);push(&w,0x5b3);td2ega_runtime_diagnostic(m,bytes,load,ss,w.sp,1,&w.r,dos,callback,context,limit-out->operations,&diagnostic);w.r=diagnostic.returned;w.sp=diagnostic.current_sp;out->operations+=diagnostic.operations;out->rows+=diagnostic.rows;out->services+=diagnostic.services;out->callbacks+=diagnostic.callbacks;out->bus_writes+=diagnostic.bus_writes;
    if(!returned(&w,diagnostic.status,diagnostic.next_segment,diagnostic.next_ip,0x5b3,expected_sp))goto finish;
    w.r.carry=0;if(w.r.registers.ax!=0 && word(&w,ss,(uint16_t)(w.r.bp+6))==0)put(&w,ss,(uint16_t)(w.r.bp+6),0xff);
    w.r.registers.cx=15;w.r.registers.bx=5;
    do{
        if(!step(&w,0x5c8))goto finish;++out->close_iterations;w.r.carry=0;
        if(w.m[address(w.r.registers.ds,(uint16_t)(w.r.registers.bx+0x6da4))]&1){
            w.r.registers.ax=(uint16_t)((w.r.registers.ax&0xff)|0x3e00);if(!step(&w,0x5d1))goto finish;request=(td2ega_small_platform_request){0x21,0x5d1,w.cs,ss,w.sp,w.r};response=w.r;
            if(dos==NULL || !dos(context,m,&request,&response) || !valid(&response)){out->status=4;out->next_segment=w.cs;out->next_ip=0x5d1;goto finish;}++out->services;++out->close_requests;w.r=response;
        }
        ++w.r.registers.bx;--w.r.registers.cx;
    }while(w.r.registers.cx!=0);
    expected_sp=w.sp;push(&w,0x5d9);td2ega_runtime_vectors(m,bytes,load,ss,w.sp,&w.r,dos,callback,context,limit-out->operations,&vectors);w.r=vectors.returned;w.sp=vectors.current_sp;out->operations+=vectors.operations;out->services+=vectors.services;out->callbacks+=vectors.callbacks;out->bus_writes+=vectors.bus_writes;
    if(!returned(&w,vectors.status,vectors.next_segment,vectors.next_ip,0x5d9,expected_sp))goto finish;
    w.r.registers.ax=word(&w,ss,(uint16_t)(w.r.bp+6));w.r.registers.ax=(uint16_t)((w.r.registers.ax&0xff)|0x4c00);if(!step(&w,0x5de))goto finish;out->exit_request=(td2ega_small_platform_request){0x21,0x5de,w.cs,ss,w.sp,w.r};out->next_segment=w.cs;out->next_ip=0x5de;out->status=5;
finish:
    out->current_sp=w.sp;out->returned=w.r;
}
