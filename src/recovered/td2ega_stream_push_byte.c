#include "td2ega_stream_push_byte.h"
#include <stddef.h>
typedef struct work {uint8_t *m;uint32_t bytes;uint16_t load,ss,sp,cs,zf;td2ega_state_registers r;const td2ega_stream_push_byte_limits *limits;td2ega_small_platform_service service;void *context;td2ega_stream_push_byte_result *o;} work;
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
    td2ega_stream_buffer_result h;uint16_t expected=w->sp;
    if(w->o->calls==w->limits->calls){w->o->status=3;w->o->next_segment=w->cs;w->o->next_ip=0x21fb;return 0;}++w->o->calls;push(w,0x21fe);
    td2ega_stream_buffer(w->m,w->bytes,w->load,w->ss,w->sp,&w->r,&w->limits->buffer,w->service,w->context,&h);w->r=h.returned;w->sp=h.current_sp;w->o->buffer_calls+=h.calls;w->o->public_calls+=h.public_calls;w->o->heap_calls+=h.heap_calls;w->o->align_calls+=h.align_calls;w->o->tail_calls+=h.tail_calls;w->o->wrapper_calls+=h.wrapper_calls;w->o->adjust_calls+=h.adjust_calls;w->o->services+=h.services;w->o->records+=h.records;w->o->iterations+=h.iterations;w->o->child_iterations+=h.child_iterations;w->o->bus_writes+=h.bus_writes;w->zf=h.zero_flag;w->o->next_segment=h.next_segment;w->o->next_ip=h.next_ip;
    if(h.status!=0){w->o->status=h.status;return 0;}if(h.next_segment!=w->cs || h.next_ip!=0x21fe || w->sp!=expected || !h.flags_valid){w->o->status=1;return 0;}return 1;
}
#define AX w.r.registers.ax
#define BX w.r.registers.bx
#define SI w.r.registers.si
#define DI w.r.registers.di
#define BP w.r.bp
#define CF w.r.carry
static uint16_t sign_byte(uint8_t v){return (uint16_t)(v<128?v:UINT16_C(0xff00)|v);}
void td2ega_stream_push_byte(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,uint16_t sp,const td2ega_state_registers *in,const td2ega_stream_push_byte_limits *limits,td2ega_small_platform_service callback,void *context,td2ega_stream_push_byte_result *out)
{
    work w;uint16_t v;
    if(out==NULL)return;
    *out=(td2ega_stream_push_byte_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || limits==NULL || sp<70 || sp>UINT16_C(0xffe0) || !valid(in))return;
    w=(work){m,bytes,load,ss,sp,(uint16_t)(load+0x13a8),0,*in,limits,callback,context,out};push(&w,BP);BP=w.sp;push(&w,DI);push(&w,SI);SI=word(&w,ss,(uint16_t)(BP+6));DI=word(&w,ss,(uint16_t)(BP+8));CF=0;w.zf=(uint16_t)((byte(&w,(uint16_t)(DI+6))&1)==0);if(w.zf)goto failure;CF=(uint16_t)(SI<0xffff);w.zf=(uint16_t)(SI==0xffff);if(w.zf)goto failure;
    CF=0;w.zf=(uint16_t)(rd(&w,(uint16_t)(DI+4))==0);if(w.zf){push(&w,DI);if(!helper(&w))goto done;w.sp=(uint16_t)(w.sp+2);}
    AX=rd(&w,DI);v=rd(&w,(uint16_t)(DI+4));CF=(uint16_t)(v<AX);w.zf=(uint16_t)(v==AX);
    if(w.zf){CF=0;w.zf=(uint16_t)(rd(&w,(uint16_t)(DI+2))==0);if(!w.zf)goto failure;wr(&w,DI,(uint16_t)(rd(&w,DI)+1));}
    wr(&w,(uint16_t)(DI+2),(uint16_t)(rd(&w,(uint16_t)(DI+2))+1));wr(&w,DI,(uint16_t)(rd(&w,DI)-1));BX=rd(&w,DI);AX=SI;wb(&w,BX,(uint8_t)AX);v=(uint16_t)(DI+6);wb(&w,v,(uint8_t)(byte(&w,v)&0xef));
    if((byte(&w,v)&0x40)==0){AX=sign_byte(byte(&w,(uint16_t)(DI+7)));BX=AX;BX=(uint16_t)(BX<<1);BX=(uint16_t)(BX+AX);BX=(uint16_t)(BX<<1);v=(uint16_t)(BX+0x6e94);wb(&w,v,(uint8_t)(byte(&w,v)|4));}
    AX=(uint16_t)(SI&0xff);CF=0;w.zf=1;goto epilogue;
failure:
    AX=0xffff;
epilogue:
    SI=pop(&w);DI=pop(&w);BP=pop(&w);out->next_ip=pop(&w);out->next_segment=pop(&w);out->status=0;out->zero_flag=w.zf;out->flags_valid=1;
done:
    out->current_sp=w.sp;out->returned=w.r;
}
