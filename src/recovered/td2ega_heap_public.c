#include "td2ega_heap_public.h"
#include <stddef.h>
typedef struct work {uint8_t *m;uint32_t bytes;uint16_t load,ss,sp,cs,last_zero;td2ega_state_registers r;const td2ega_heap_public_limits *limits;td2ega_small_platform_service service;void *context;td2ega_heap_public_result *o;} work;
static uint32_t address(uint16_t s,uint16_t o){return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(work *w,uint16_t s,uint16_t o){uint32_t a=address(s,o);return (uint16_t)(w->m[a]|((uint16_t)w->m[(a+1)&UINT32_C(0xfffff)]<<8));}
static uint16_t rd(work *w,uint16_t o){return word(w,w->r.registers.ds,o);}
static void put(work *w,uint16_t s,uint16_t o,uint16_t v){uint32_t a=address(s,o);w->m[a]=(uint8_t)v;w->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++w->o->bus_writes;}
static void wr(work *w,uint16_t o,uint16_t v){put(w,w->r.registers.ds,o,v);}
static void push(work *w,uint16_t v){w->sp=(uint16_t)(w->sp-2);put(w,w->ss,w->sp,v);}
static uint16_t pop(work *w){uint16_t v=word(w,w->ss,w->sp);w->sp=(uint16_t)(w->sp+2);return v;}
static int valid(const td2ega_state_registers *r){return r->carry<=1 && r->registers.interrupts_enabled<=1 && r->registers.direction<=1;}
static int helper(work *w,uint16_t site,int walk)
{
    td2ega_block_wrapper_result b;td2ega_heap_walk_result h;td2ega_heap_walk_limits limits=w->limits->walk;uint16_t expected=w->sp,status,next_segment,next_ip,flags_valid;
    if(w->o->calls==w->limits->calls){w->o->status=3;w->o->next_segment=w->cs;w->o->next_ip=site;return 0;}++w->o->calls;push(w,(uint16_t)(site+3));limits.services-=w->o->services;
    if(walk){td2ega_heap_walk(w->m,w->bytes,w->load,w->ss,w->sp,&w->r,&limits,w->service,w->context,&h);w->r=h.returned;w->sp=h.current_sp;w->o->heap_calls+=h.calls;w->o->align_calls+=h.align_calls;w->o->tail_calls+=h.tail_calls;w->o->wrapper_calls+=h.wrapper_calls;w->o->adjust_calls+=h.adjust_calls;w->o->services+=h.services;w->o->records+=h.records;w->o->iterations+=h.iterations;w->o->child_iterations+=h.child_iterations;w->o->bus_writes+=h.bus_writes;w->last_zero=h.zero_flag;flags_valid=h.flags_valid;status=h.status;next_segment=h.next_segment;next_ip=h.next_ip;}
    else{td2ega_block_wrapper(w->m,w->bytes,w->load,w->ss,w->sp,&w->r,w->service,w->context,limits.wrapper_calls,limits.adjust_calls,limits.records,limits.services,&b);w->r=b.returned;w->sp=b.current_sp;w->o->wrapper_calls+=b.calls;w->o->adjust_calls+=b.child_calls;w->o->services+=b.services;w->o->records+=b.records;w->o->bus_writes+=b.bus_writes;w->last_zero=b.zero_flag;flags_valid=b.flags_valid;status=b.status;next_segment=b.next_segment;next_ip=b.next_ip;}
    w->o->next_segment=next_segment;w->o->next_ip=next_ip;if(status!=0){w->o->status=status;return 0;}if(next_segment!=w->cs || next_ip!=(uint16_t)(site+3) || w->sp!=expected || !flags_valid){w->o->status=1;return 0;}return 1;
}
#define AX w.r.registers.ax
#define BX w.r.registers.bx
#define CX w.r.registers.cx
#define DX w.r.registers.dx
#define SI w.r.registers.si
#define DI w.r.registers.di
#define BP w.r.bp
#define CF w.r.carry
void td2ega_heap_public(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,uint16_t sp,const td2ega_state_registers *in,const td2ega_heap_public_limits *limits,td2ega_small_platform_service callback,void *context,td2ega_heap_public_result *out)
{
    work w;uint16_t v;uint32_t wide;
    if(out==NULL)return;
    *out=(td2ega_heap_public_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || limits==NULL || sp<50 || sp>UINT16_C(0xffe0) || !valid(in))return;
    w=(work){m,bytes,load,ss,sp,(uint16_t)(load+0x13a8),0,*in,limits,callback,context,out};push(&w,BP);BP=w.sp;push(&w,SI);push(&w,DI);BX=0x6f26;CF=0;
    if(rd(&w,BX)==0){push(&w,w.r.registers.ds);w.r.registers.es=pop(&w);AX=5;if(!helper(&w,0x26ba,0))goto done;if(w.last_zero){AX=0;CF=0;DX=0;w.last_zero=1;goto epilogue;}AX=(uint16_t)(AX+1);AX=(uint16_t)(AX&0xfffe);CF=0;wr(&w,0x6f26,AX);wr(&w,0x6f28,AX);v=SI;SI=AX;AX=v;wr(&w,SI,1);wide=(uint32_t)SI+4;CF=(uint16_t)(wide>65535);SI=(uint16_t)wide;wr(&w,(uint16_t)(SI-2),0xfffe);wr(&w,0x6f2c,SI);}
    CX=word(&w,ss,(uint16_t)(BP+6));AX=w.r.registers.ds;w.r.registers.es=AX;if(!helper(&w,0x26e5,1))goto done;
epilogue:
    DI=pop(&w);SI=pop(&w);w.sp=BP;BP=pop(&w);out->next_ip=pop(&w);out->next_segment=pop(&w);out->status=0;out->zero_flag=w.last_zero;out->flags_valid=1;
done:
    out->current_sp=w.sp;out->returned=w.r;
}
