#include "td2ega_point_update.h"
#include <stddef.h>
typedef struct work {uint8_t *m;uint32_t bytes;uint16_t load,ss,sp,cs,zf;td2ega_state_registers r;const td2ega_point_update_limits *limits;td2ega_line_draw_service service;void *context;td2ega_point_update_result *o;} work;
static uint32_t address(uint16_t s,uint16_t o){return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(work *w,uint16_t s,uint16_t o){uint32_t a=address(s,o);return (uint16_t)(w->m[a]|((uint16_t)w->m[(a+1)&UINT32_C(0xfffff)]<<8));}
static uint16_t rd(work *w,uint16_t o){return word(w,w->r.registers.ds,o);}
static void put(work *w,uint16_t s,uint16_t o,uint16_t v){uint32_t a=address(s,o);w->m[a]=(uint8_t)v;w->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++w->o->bus_writes;}
static void push(work *w,uint16_t v){w->sp=(uint16_t)(w->sp-2);put(w,w->ss,w->sp,v);}
static uint16_t pop(work *w){uint16_t v=word(w,w->ss,w->sp);w->sp=(uint16_t)(w->sp+2);return v;}
static int32_t signed_word(uint16_t v){return v<0x8000?(int32_t)v:(int32_t)v-65536;}
static uint16_t add(work *w,uint16_t a,uint16_t b){uint32_t v=(uint32_t)a+b;w->r.carry=(uint16_t)(v>65535);w->zf=(uint16_t)((uint16_t)v==0);return (uint16_t)v;}
static int valid(const td2ega_state_registers *r){return r->carry<=1 && r->registers.interrupts_enabled<=1 && r->registers.direction<=1;}
static int point(work *w,uint16_t site,uint16_t next)
{
    td2ega_pixel_point_result h;uint16_t expected=w->sp;
    w->o->next_segment=w->cs;w->o->next_ip=site;if(w->o->calls==w->limits->calls){w->o->status=3;return 0;}++w->o->calls;push(w,w->cs);push(w,next);
    td2ega_pixel_point(w->m,w->bytes,w->load,w->ss,w->sp,&w->r,w->service,w->context,w->limits->events-w->o->events,&h);
    w->r=h.returned;w->sp=h.current_sp;w->o->events+=h.events;w->o->reads+=h.reads;w->o->writes+=h.writes;w->o->ports+=h.ports;w->o->bus_writes+=h.bus_writes;w->o->next_segment=h.next_segment;w->o->next_ip=h.next_ip;
    if(h.status!=0){w->o->status=h.status;return 0;}
    if(h.next_segment!=w->cs || h.next_ip!=next || w->sp!=expected){w->o->status=1;return 0;}return 1;
}
void td2ega_point_update(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,uint16_t sp,const td2ega_state_registers *in,const td2ega_point_update_limits *limits,td2ega_line_draw_service callback,void *context,td2ega_point_update_result *out)
{
    work w;uint16_t at;int32_t difference;unsigned i;
    if(out==NULL)return;
    *out=(td2ega_point_update_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || limits==NULL || !valid(in))return;
    w=(work){m,bytes,load,ss,sp,(uint16_t)(load+0x6c9),0,*in,limits,callback,context,out};difference=signed_word(w.r.registers.si)-0x3b51;w.r.registers.si=(uint16_t)(w.r.registers.si-0x3b51);if(difference<0)w.r.registers.si=0xffe0;at=(uint16_t)(w.r.registers.bx+0x2f50);w.r.registers.cx=rd(&w,at);
    for(i=0;i<5;++i){w.r.carry=(uint16_t)(w.r.registers.si&1);w.r.registers.si=(uint16_t)((w.r.registers.si>>1)|(w.r.registers.si&0x8000));}
    w.r.carry=(uint16_t)(w.r.registers.si<w.r.registers.cx);w.zf=(uint16_t)(w.r.registers.si==w.r.registers.cx);if(w.zf)goto root;
    put(&w,w.r.registers.ds,at,w.r.registers.si);w.r.registers.bx=0;w.r.carry=0;push(&w,w.r.registers.dx);push(&w,w.r.registers.bx);push(&w,w.r.registers.si);w.zf=(uint16_t)(w.r.registers.cx==0);
    if(!(w.r.registers.cx&0x8000)){push(&w,w.r.registers.bx);push(&w,w.r.registers.bx);push(&w,w.r.registers.cx);if(!point(&w,0x3ae4,0x3ae9))goto done;w.sp=add(&w,w.sp,6);}
    w.r.carry=0;w.zf=(uint16_t)(w.r.registers.si==0);if(!(w.r.registers.si&0x8000)){if(!point(&w,0x3af0,0x3af5))goto done;}w.sp=add(&w,w.sp,6);
root:
    out->next_ip=pop(&w);out->next_segment=w.cs;out->status=0;out->zero_flag=w.zf;out->flags_valid=1;
done:
    out->current_sp=w.sp;out->returned=w.r;
}
