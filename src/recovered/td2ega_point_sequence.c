#include "td2ega_point_sequence.h"
#include <stddef.h>
typedef struct work {uint8_t *m;uint32_t bytes;uint16_t load,ss,sp,cs,zf;td2ega_state_registers r;const td2ega_point_sequence_limits *limits;td2ega_line_draw_service service;void *context;td2ega_point_sequence_result *o;} work;
static uint32_t address(uint16_t s,uint16_t o){return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(work *w,uint16_t s,uint16_t o){uint32_t a=address(s,o);return (uint16_t)(w->m[a]|((uint16_t)w->m[(a+1)&UINT32_C(0xfffff)]<<8));}
static void push(work *w,uint16_t v){uint32_t a;w->sp=(uint16_t)(w->sp-2);a=address(w->ss,w->sp);w->m[a]=(uint8_t)v;w->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++w->o->bus_writes;}
static uint16_t pop(work *w){uint16_t v=word(w,w->ss,w->sp);w->sp=(uint16_t)(w->sp+2);return v;}
static int valid(const td2ega_state_registers *r){return r->carry<=1 && r->registers.interrupts_enabled<=1 && r->registers.direction<=1;}
static int update(work *w,uint16_t site)
{
    td2ega_point_update_result h;td2ega_point_update_limits bounds=w->limits->update;uint16_t expected=w->sp,next=(uint16_t)(site+3);
    w->o->next_segment=w->cs;w->o->next_ip=site;if(w->o->calls==w->limits->calls){w->o->status=3;return 0;}++w->o->calls;push(w,next);bounds.events=w->limits->update.events-w->o->events;bounds.calls=w->limits->update.calls-w->o->point_calls;
    td2ega_point_update(w->m,w->bytes,w->load,w->ss,w->sp,&w->r,&bounds,w->service,w->context,&h);
    w->r=h.returned;w->sp=h.current_sp;w->o->point_calls+=h.calls;w->o->events+=h.events;w->o->reads+=h.reads;w->o->writes+=h.writes;w->o->ports+=h.ports;w->o->bus_writes+=h.bus_writes;w->o->next_segment=h.next_segment;w->o->next_ip=h.next_ip;
    if(h.status!=0){w->o->status=h.status;return 0;}
    if(h.next_segment!=w->cs || h.next_ip!=next || w->sp!=expected || !h.flags_valid){w->o->status=1;return 0;}w->zf=h.zero_flag;return 1;
}
void td2ega_point_sequence(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,uint16_t sp,const td2ega_state_registers *in,const td2ega_point_sequence_limits *limits,td2ega_line_draw_service callback,void *context,td2ega_point_sequence_result *out)
{
    work w;
    if(out==NULL)return;
    *out=(td2ega_point_sequence_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || limits==NULL || !valid(in))return;
    w=(work){m,bytes,load,ss,sp,(uint16_t)(load+0x6c9),0,*in,limits,callback,context,out};w.r.registers.si=word(&w,w.r.registers.ds,0x52ca);w.r.registers.bx=0;w.r.carry=0;w.zf=1;w.r.registers.dx=0xc;if(!update(&w,0x3a9a))goto done;
    w.r.registers.si=word(&w,w.r.registers.ds,0x52d2);w.r.registers.bx=2;w.r.registers.dx=9;if(!update(&w,0x3aa7))goto done;
    w.r.registers.si=word(&w,w.r.registers.ds,0x52da);w.r.registers.bx=4;w.r.registers.dx=0xe;if(!update(&w,0x3ab4))goto done;
    out->next_ip=pop(&w);out->next_segment=w.cs;out->status=0;out->flags_valid=1;out->zero_flag=w.zf;
done:
    out->current_sp=w.sp;out->returned=w.r;
}
