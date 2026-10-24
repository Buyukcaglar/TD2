#include "td2ega_write_span.h"
#include <stddef.h>
typedef struct work {uint8_t *m;uint32_t bytes;uint16_t load,ss,sp,cs;td2ega_state_registers r;td2ega_small_platform_service service;void *context;td2ega_write_span_result *o;} work;
static uint32_t address(uint16_t s,uint16_t o){return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(work *w,uint16_t s,uint16_t o){uint32_t a=address(s,o);return (uint16_t)(w->m[a]|((uint16_t)w->m[(a+1)&UINT32_C(0xfffff)]<<8));}
static uint16_t rd(work *w,uint16_t o){return word(w,w->r.registers.ds,o);}
static uint8_t byte(work *w,uint16_t o){return w->m[address(w->r.registers.ds,o)];}
static void put(work *w,uint16_t s,uint16_t o,uint16_t v){uint32_t a=address(s,o);w->m[a]=(uint8_t)v;w->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++w->o->bus_writes;}
static void wb(work *w,uint16_t o,uint8_t v){w->m[address(w->r.registers.ds,o)]=v;++w->o->bus_writes;}
static void push(work *w,uint16_t v){w->sp=(uint16_t)(w->sp-2);put(w,w->ss,w->sp,v);}
static uint16_t pop(work *w){uint16_t v=word(w,w->ss,w->sp);w->sp=(uint16_t)(w->sp+2);return v;}
static int valid(const td2ega_state_registers *r){return r->carry<=1 && r->registers.interrupts_enabled<=1 && r->registers.direction<=1;}
/* Literal094A body/actualnearframe; avoidsborrowingthefrozenstandaloneAPI's
 * SP16..FFE0fixtureadmission for thisinherited/nonlocalstackcontext. */
static int mapper(work *w,uint32_t limit)
{
    uint8_t al=(uint8_t)w->r.registers.ax,ah=(uint8_t)(w->r.registers.ax>>8);uint16_t value,expected=w->sp,next;
    if(w->o->calls==limit){w->o->status=3;w->o->next_segment=w->cs;w->o->next_ip=0x0939;return 0;}++w->o->calls;push(w,0x093c);wb(w,0x6da0,al);w->r.carry=0;
    if(ah)al=ah;
    else{value=byte(w,0x6d9d);w->r.carry=(uint16_t)(value<3);if(value>=3){w->r.carry=(uint16_t)(al<0x22);if(al>=0x22)al=0x13;else{w->r.carry=(uint16_t)(al<0x20);if(al>=0x20)al=5;else{w->r.carry=(uint16_t)(al<0x13);if(al>0x13)al=0x13;}}}else{w->r.carry=(uint16_t)(al<0x13);if(al>0x13)al=0x13;}w->r.registers.bx=0x6dda;al=byte(w,(uint16_t)(w->r.registers.bx+al));}
    w->r.registers.ax=(uint16_t)(al<128?al:UINT16_C(0xff00)|al);put(w,w->r.registers.ds,0x6d95,w->r.registers.ax);next=pop(w);w->o->next_segment=w->cs;w->o->next_ip=next;
    if(next!=0x093c || w->sp!=expected){w->o->status=1;return 0;}return 1;
}
#define AX w.r.registers.ax
#define BX w.r.registers.bx
#define CX w.r.registers.cx
#define DX w.r.registers.dx
#define SI w.r.registers.si
#define DI w.r.registers.di
#define BP w.r.bp
#define CF w.r.carry
void td2ega_write_span(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,uint16_t sp,const td2ega_state_registers *in,uint32_t calls,uint32_t services,td2ega_small_platform_service callback,void *context,td2ega_write_span_result *out)
{
    work w;uint16_t v;uint32_t wide;td2ega_small_platform_request q;td2ega_state_registers returned;
    if(out==NULL)return;
    *out=(td2ega_write_span_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || !valid(in))return;
    w=(work){m,bytes,load,ss,sp,(uint16_t)(load+0x13a8),*in,callback,context,out};push(&w,AX);push(&w,BX);push(&w,CX);CX=DI;CF=(uint16_t)(CX<DX);CX=(uint16_t)(CX-DX);if(CX==0)goto near_return;
    BX=word(&w,ss,(uint16_t)(BP+6));AX=(uint16_t)((AX&0xff)|0x4000);out->next_segment=w.cs;out->next_ip=0x260e;
    if(out->services==services){out->status=3;goto done;}
    q=(td2ega_small_platform_request){0x21,0x260e,w.cs,ss,w.sp,w.r};returned=w.r;
    if(callback==NULL || !callback(context,m,&q,&returned) || !valid(&returned)){out->status=4;goto done;}++out->services;w.r=returned;
    if(CF)goto failure;
    v=(uint16_t)(BP-2);put(&w,ss,v,(uint16_t)(word(&w,ss,v)+AX));CF=0;if(AX!=0)goto near_return;
failure:
    wide=(uint32_t)w.sp+8;w.sp=(uint16_t)wide;CF=(uint16_t)(wide>65535);
    if(CF){AX=(uint16_t)((AX&0xff)|0x0900);goto shared;}
    CF=0;if(byte(&w,(uint16_t)(BX+0x6da4))&0x40){BX=word(&w,ss,(uint16_t)(BP+8));CF=(uint16_t)(byte(&w,BX)<0x1a);if(byte(&w,BX)==0x1a){CF=0;goto shared;}}
    CF=1;AX=0x1c00;
shared:
    w.sp=word(&w,ss,(uint16_t)(BP-8));SI=pop(&w);DI=pop(&w);
    if(CF){if(!mapper(&w,calls))goto done;AX=0xffff;DX=0xffff;}
    w.sp=BP;BP=pop(&w);out->next_ip=pop(&w);out->next_segment=pop(&w);out->return_kind=1;goto root_return;
near_return:
    CX=pop(&w);BX=pop(&w);AX=pop(&w);DI=DX;out->next_ip=pop(&w);out->next_segment=w.cs;out->return_kind=0;
root_return:
    out->status=0;out->return_valid=1;
done:
    out->current_sp=w.sp;out->returned=w.r;
}
