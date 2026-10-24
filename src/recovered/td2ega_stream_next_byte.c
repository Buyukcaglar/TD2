#include "td2ega_stream_next_byte.h"
#include <stddef.h>
typedef struct work {uint8_t *m;uint32_t bytes;uint16_t load,ss,sp,cs,zf;td2ega_state_registers r;const td2ega_stream_next_byte_limits *limits;td2ega_small_platform_service service;void *context;td2ega_stream_next_byte_result *o;} work;
static uint32_t address(uint16_t s,uint16_t o){return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(work *w,uint16_t s,uint16_t o){uint32_t a=address(s,o);return (uint16_t)(w->m[a]|((uint16_t)w->m[(a+1)&UINT32_C(0xfffff)]<<8));}
static uint16_t rd(work *w,uint16_t o){return word(w,w->r.registers.ds,o);}
static void put(work *w,uint16_t s,uint16_t o,uint16_t v){uint32_t a=address(s,o);w->m[a]=(uint8_t)v;w->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++w->o->bus_writes;}
static void wr(work *w,uint16_t o,uint16_t v){put(w,w->r.registers.ds,o,v);}
static void push(work *w,uint16_t v){w->sp=(uint16_t)(w->sp-2);put(w,w->ss,w->sp,v);}
static uint16_t pop(work *w){uint16_t v=word(w,w->ss,w->sp);w->sp=(uint16_t)(w->sp+2);return v;}
static int valid(const td2ega_state_registers *r){return r->carry<=1 && r->registers.interrupts_enabled<=1 && r->registers.direction<=1;}
static int pull(work *w)
{
    td2ega_stream_pull_byte_result h;uint16_t expected=w->sp;
    w->o->next_segment=w->cs;w->o->next_ip=0x18cc;if(w->o->calls==w->limits->calls){w->o->status=3;return 0;}++w->o->calls;push(w,w->cs);push(w,0x18d1);
    td2ega_stream_pull_byte(w->m,w->bytes,w->load,w->ss,w->sp,&w->r,&w->limits->pull,w->service,w->context,&h);
    w->r=h.returned;w->sp=h.current_sp;w->o->pull_calls+=h.calls;w->o->buffer_calls+=h.buffer_calls;w->o->public_calls+=h.public_calls;w->o->heap_calls+=h.heap_calls;w->o->align_calls+=h.align_calls;w->o->tail_calls+=h.tail_calls;w->o->wrapper_calls+=h.wrapper_calls;w->o->adjust_calls+=h.adjust_calls;w->o->read_calls+=h.read_calls;w->o->read_steps+=h.read_steps;w->o->services+=h.services;w->o->records+=h.records;w->o->iterations+=h.iterations;w->o->child_iterations+=h.child_iterations;w->o->bus_writes+=h.bus_writes;w->o->next_segment=h.next_segment;w->o->next_ip=h.next_ip;
    if(h.status!=0){w->o->status=h.status;return 0;}
    if(h.next_segment!=w->cs || h.next_ip!=0x18d1 || w->sp!=expected || !h.flags_valid){w->o->status=1;return 0;}return 1;
}
void td2ega_stream_next_byte(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,uint16_t sp,const td2ega_state_registers *in,const td2ega_stream_next_byte_limits *limits,td2ega_small_platform_service callback,void *context,td2ega_stream_next_byte_result *out)
{
    work w;uint16_t count,v;
    if(out==NULL)return;
    *out=(td2ega_stream_next_byte_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || limits==NULL || sp<78 || sp>UINT16_C(0xffe0) || !valid(in))return;
    w=(work){m,bytes,load,ss,sp,(uint16_t)(load+0x13a8),0,*in,limits,callback,context,out};push(&w,w.r.registers.si);wr(&w,0x83ee,(uint16_t)(rd(&w,0x83ee)+1));w.r.registers.bx=rd(&w,0x83f2);count=(uint16_t)(rd(&w,(uint16_t)(w.r.registers.bx+2))-1);wr(&w,(uint16_t)(w.r.registers.bx+2),count);
    if(count&0x8000){v=rd(&w,0x83f2);push(&w,v);if(!pull(&w))goto done;v=(uint16_t)(w.sp+2);w.r.carry=(uint16_t)(v<w.sp);w.sp=v;w.zf=(uint16_t)(v==0);}
    else{w.r.registers.si=rd(&w,w.r.registers.bx);wr(&w,w.r.registers.bx,(uint16_t)(rd(&w,w.r.registers.bx)+1));w.r.registers.ax=w.m[address(w.r.registers.ds,w.r.registers.si)];w.r.carry=0;w.zf=1;}
    w.r.registers.si=pop(&w);out->next_ip=pop(&w);out->next_segment=pop(&w);out->status=0;out->zero_flag=w.zf;out->flags_valid=1;
done:
    out->current_sp=w.sp;out->returned=w.r;
}
