#include "td2ega_stream_buffer.h"
#include <stddef.h>
typedef struct work {uint8_t *m;uint32_t bytes;uint16_t load,ss,sp,cs,zf;td2ega_state_registers r;const td2ega_stream_buffer_limits *limits;td2ega_small_platform_service service;void *context;td2ega_stream_buffer_result *o;} work;
static uint32_t address(uint16_t s,uint16_t o){return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(work *w,uint16_t s,uint16_t o){uint32_t a=address(s,o);return (uint16_t)(w->m[a]|((uint16_t)w->m[(a+1)&UINT32_C(0xfffff)]<<8));}
static uint16_t rd(work *w,uint16_t o){return word(w,w->r.registers.ds,o);}
static uint8_t byte(work *w,uint16_t o){return w->m[address(w->r.registers.ds,o)];}
static void put(work *w,uint16_t s,uint16_t o,uint16_t v){uint32_t a=address(s,o);w->m[a]=(uint8_t)v;w->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++w->o->bus_writes;}
static void wr(work *w,uint16_t o,uint16_t v){put(w,w->r.registers.ds,o,v);}
static void wb(work *w,uint16_t o,uint8_t v){w->m[address(w->r.registers.ds,o)]=v;++w->o->bus_writes;}
static void push(work *w,uint16_t v){w->sp=(uint16_t)(w->sp-2);put(w,w->ss,w->sp,v);}
static uint16_t pop(work *w){uint16_t v=word(w,w->ss,w->sp);w->sp=(uint16_t)(w->sp+2);return v;}
static int valid(const td2ega_state_registers *r){return r->carry<=1 && r->registers.interrupts_enabled<=1 && r->registers.direction<=1;}
static int helper(work *w)
{
    td2ega_heap_public_result h;uint16_t expected=w->sp;
    if(w->o->calls==w->limits->calls){w->o->status=3;w->o->next_segment=w->cs;w->o->next_ip=0x0bf0;return 0;}++w->o->calls;push(w,w->cs);push(w,0x0bf5);
    td2ega_heap_public(w->m,w->bytes,w->load,w->ss,w->sp,&w->r,&w->limits->public_heap,w->service,w->context,&h);w->r=h.returned;w->sp=h.current_sp;w->o->public_calls+=h.calls;w->o->heap_calls+=h.heap_calls;w->o->align_calls+=h.align_calls;w->o->tail_calls+=h.tail_calls;w->o->wrapper_calls+=h.wrapper_calls;w->o->adjust_calls+=h.adjust_calls;w->o->services+=h.services;w->o->records+=h.records;w->o->iterations+=h.iterations;w->o->child_iterations+=h.child_iterations;w->o->bus_writes+=h.bus_writes;w->zf=h.zero_flag;w->o->next_segment=h.next_segment;w->o->next_ip=h.next_ip;
    if(h.status!=0){w->o->status=h.status;return 0;}if(h.next_segment!=w->cs || h.next_ip!=0x0bf5 || w->sp!=expected || !h.flags_valid){w->o->status=1;return 0;}return 1;
}
#define AX w.r.registers.ax
#define BX w.r.registers.bx
#define CX w.r.registers.cx
#define SI w.r.registers.si
#define BP w.r.bp
#define CF w.r.carry
static uint16_t sign_byte(uint8_t v){return (uint16_t)(v<128?v:UINT16_C(0xff00)|v);}
void td2ega_stream_buffer(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,uint16_t sp,const td2ega_state_registers *in,const td2ega_stream_buffer_limits *limits,td2ega_small_platform_service callback,void *context,td2ega_stream_buffer_result *out)
{
    work w;uint16_t v;uint32_t wide;
    if(out==NULL)return;
    *out=(td2ega_stream_buffer_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || limits==NULL || sp<60 || sp>UINT16_C(0xffe0) || !valid(in))return;
    w=(work){m,bytes,load,ss,sp,(uint16_t)(load+0x13a8),0,*in,limits,callback,context,out};push(&w,BP);BP=w.sp;push(&w,SI);AX=0x200;push(&w,AX);if(!helper(&w))goto done;w.sp=(uint16_t)(w.sp+2);
    BX=word(&w,ss,(uint16_t)(BP+4));wr(&w,(uint16_t)(BX+4),AX);CF=0;w.zf=(uint16_t)(AX==0);
    if(AX!=0){v=(uint16_t)(BX+6);wb(&w,v,(uint8_t)(byte(&w,v)|8));AX=sign_byte(byte(&w,(uint16_t)(BX+7)));BX=AX;BX=(uint16_t)(BX<<1);BX=(uint16_t)(BX+AX);CF=(uint16_t)(BX>>15);BX=(uint16_t)(BX<<1);w.zf=(uint16_t)(BX==0);wr(&w,(uint16_t)(BX+0x6e96),0x200);}
    else{BX=word(&w,ss,(uint16_t)(BP+4));v=(uint16_t)(BX+6);wb(&w,v,(uint8_t)(byte(&w,v)|4));AX=sign_byte(byte(&w,(uint16_t)(BX+7)));CX=AX;AX=(uint16_t)(AX<<1);AX=(uint16_t)(AX+CX);AX=(uint16_t)(AX<<1);SI=AX;wide=(uint32_t)AX+0x6e95;CF=(uint16_t)(wide>65535);AX=(uint16_t)wide;w.zf=(uint16_t)(AX==0);wr(&w,(uint16_t)(BX+4),AX);wr(&w,(uint16_t)(SI+0x6e96),1);}
    BX=word(&w,ss,(uint16_t)(BP+4));SI=BX;AX=rd(&w,(uint16_t)(SI+4));wr(&w,BX,AX);wr(&w,(uint16_t)(BX+2),0);SI=pop(&w);BP=pop(&w);out->next_ip=pop(&w);out->next_segment=w.cs;out->status=0;out->zero_flag=w.zf;out->flags_valid=1;
done:
    out->current_sp=w.sp;out->returned=w.r;
}
