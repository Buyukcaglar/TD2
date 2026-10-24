#include "td2ega_read_span.h"
#include <stddef.h>
typedef struct work {uint8_t *m;uint16_t ss,sp,cs;td2ega_state_registers r;uint32_t calls,services,steps;td2ega_small_platform_service service;void *context;td2ega_read_span_result *o;} work;
static uint32_t address(uint16_t s,uint16_t o){return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(work *w,uint16_t s,uint16_t o){uint32_t a=address(s,o);return (uint16_t)(w->m[a]|((uint16_t)w->m[(a+1)&UINT32_C(0xfffff)]<<8));}
static uint8_t byte(work *w,uint16_t o){return w->m[address(w->r.registers.ds,o)];}
static void put(work *w,uint16_t s,uint16_t o,uint16_t v){uint32_t a=address(s,o);w->m[a]=(uint8_t)v;w->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++w->o->bus_writes;}
static void wb(work *w,uint16_t s,uint16_t o,uint8_t v){w->m[address(s,o)]=v;++w->o->bus_writes;}
static void push(work *w,uint16_t v){w->sp=(uint16_t)(w->sp-2);put(w,w->ss,w->sp,v);}
static uint16_t pop(work *w){uint16_t v=word(w,w->ss,w->sp);w->sp=(uint16_t)(w->sp+2);return v;}
static int valid(const td2ega_state_registers *r){return r->carry<=1 && r->registers.interrupts_enabled<=1 && r->registers.direction<=1;}
static void low(work *w,uint16_t v){w->r.registers.ax=(uint16_t)((w->r.registers.ax&0xff00)|(v&255));}
static void high(work *w,uint16_t v){w->r.registers.ax=(uint16_t)((w->r.registers.ax&255)|((v&255)<<8));}
static uint16_t sub(work *w,uint16_t a,uint16_t b){w->r.carry=(uint16_t)(a<b);return (uint16_t)(a-b);}
static int service(work *w,uint16_t site)
{
    td2ega_small_platform_request q;td2ega_state_registers returned=w->r;
    w->o->next_segment=w->cs;w->o->next_ip=site;
    if(w->o->services==w->services){w->o->status=3;return 0;}
    q=(td2ega_small_platform_request){0x21,site,w->cs,w->ss,w->sp,w->r};
    if(w->service==NULL || !w->service(w->context,w->m,&q,&returned) || !valid(&returned)){w->o->status=4;return 0;}
    ++w->o->services;w->r=returned;return 1;
}
/* Actual094A fullSS nearframe, same literalbody as acceptedwrite_span view. */
static int mapper(work *w)
{
    uint8_t al=(uint8_t)w->r.registers.ax,ah=(uint8_t)(w->r.registers.ax>>8);uint16_t value,expected=w->sp,next;
    w->o->next_segment=w->cs;w->o->next_ip=0x0939;
    if(w->o->calls==w->calls){w->o->status=3;return 0;}
    ++w->o->calls;push(w,0x093c);wb(w,w->r.registers.ds,0x6da0,al);w->r.carry=0;
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
#define DS w.r.registers.ds
#define BP w.r.bp
#define CF w.r.carry
void td2ega_read_span(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,uint16_t sp,const td2ega_state_registers *in,uint32_t calls,uint32_t services,uint32_t steps,td2ega_small_platform_service callback,void *context,td2ega_read_span_result *out)
{
    work w;uint16_t v;
    if(out==NULL)return;
    *out=(td2ega_read_span_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || !valid(in))return;
    w=(work){m,ss,sp,(uint16_t)(load+0x13a8),*in,calls,services,steps,callback,context,out};push(&w,BP);BP=w.sp;w.sp=sub(&w,w.sp,2);BX=word(&w,ss,(uint16_t)(BP+6));v=word(&w,DS,0x6da2);CF=(uint16_t)(BX<v);
    if(!CF){CF=1;AX=0x900;goto shared;}
    CF=0;if(byte(&w,(uint16_t)(BX+0x6da4))&2){AX=0;goto shared;}
    CX=word(&w,ss,(uint16_t)(BP+0xa));DX=word(&w,ss,(uint16_t)(BP+8));high(&w,0x3f);if(!service(&w,0x24a5))goto done;
    if(CF){high(&w,9);goto shared;}
    CF=0;if(!(byte(&w,(uint16_t)(BX+0x6da4))&0x80))goto shared;
    wb(&w,DS,(uint16_t)(BX+0x6da4),(uint8_t)(byte(&w,(uint16_t)(BX+0x6da4))&0xfb));CF=0;push(&w,SI);push(&w,DI);w.r.registers.direction=0;SI=DX;DI=DX;CX=AX;if(CX==0)goto restore;
    high(&w,0xd);v=byte(&w,SI);CF=(uint16_t)(v<0xa);if(v==0xa){wb(&w,DS,(uint16_t)(BX+0x6da4),(uint8_t)(byte(&w,(uint16_t)(BX+0x6da4))|4));CF=0;}
lods:
    out->next_segment=w.cs;out->next_ip=0x24d0;if(out->steps==w.steps){out->status=3;goto done;}++out->steps;low(&w,byte(&w,SI));SI=(uint16_t)(SI+(w.r.registers.direction?-1:1));v=(uint16_t)(AX>>8);CF=(uint16_t)((uint8_t)AX<v);if((uint8_t)AX==v)goto carriage;
    CF=(uint16_t)((uint8_t)AX<0x1a);if((uint8_t)AX==0x1a){wb(&w,DS,(uint16_t)(BX+0x6da4),(uint8_t)(byte(&w,(uint16_t)(BX+0x6da4))|2));CF=0;goto count;}
store:
    wb(&w,DS,DI,(uint8_t)AX);DI=(uint16_t)(DI+1);
loop:
    CX=(uint16_t)(CX-1);if(CX!=0)goto lods;
count:
    AX=DI;AX=sub(&w,AX,DX);
restore:
    DI=pop(&w);SI=pop(&w);goto shared;
carriage:
    CF=(uint16_t)(CX<1);if(CX==1)goto last;
    v=byte(&w,SI);CF=(uint16_t)(v<0xa);if(v==0xa)goto loop;goto store;
last:
    CF=0;if(byte(&w,(uint16_t)(BX+0x6da4))&0x40){AX=0x4400;if(!service(&w,0x2504))goto done;CF=0;if(DX&0x20)goto newline;DX=(uint16_t)(BP-1);high(&w,0x3f);if(!service(&w,0x2511))goto done;if(CF)goto restore;goto newline;}
    wb(&w,ss,(uint16_t)(BP-1),0);DX=(uint16_t)(BP-1);high(&w,0x3f);if(!service(&w,0x2522))goto done;if(CF)goto restore;CF=0;if(AX==0)goto original_cr;
    v=word(&w,ss,(uint16_t)(BP+0xa));CF=(uint16_t)(v<1);if(v==1){v=w.m[address(ss,(uint16_t)(BP-1))];CF=(uint16_t)(v<0xa);if(v==0xa)goto newline;}
    CX=0xffff;DX=CX;AX=0x4201;if(!service(&w,0x2538))goto done;CX=1;v=w.m[address(ss,(uint16_t)(BP-1))];CF=(uint16_t)(v<0xa);if(v==0xa){DX=word(&w,ss,(uint16_t)(BP+8));goto loop;}
original_cr:
    low(&w,0xd);goto buffer;
newline:
    low(&w,0xa);
buffer:
    DX=word(&w,ss,(uint16_t)(BP+8));goto store;
shared:
    if(CF){if(!mapper(&w))goto done;AX=0xffff;DX=0xffff;}
    w.sp=BP;BP=pop(&w);if(w.sp>0xfffc){out->status=5;out->next_segment=w.cs;out->next_ip=0x0943;goto done;}
    out->next_ip=pop(&w);out->next_segment=pop(&w);out->status=0;
done:
    out->current_sp=w.sp;out->returned=w.r;
}
