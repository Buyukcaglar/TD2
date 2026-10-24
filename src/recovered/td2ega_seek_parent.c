#include "td2ega_seek_parent.h"
#include <stddef.h>
typedef struct work {uint8_t *m;uint32_t bytes;uint16_t load,cs,ss,sp;td2ega_state_registers r;td2ega_small_platform_service service;void *context;uint32_t limit,child_limit;td2ega_seek_parent_result *o;} work;
static uint32_t address(uint16_t s,uint16_t o){return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(work *w,uint16_t s,uint16_t o){uint32_t a=address(s,o);return (uint16_t)(w->m[a]|((uint16_t)w->m[(a+1)&UINT32_C(0xfffff)]<<8));}
static uint16_t atbp(work *w,uint16_t o){return word(w,w->ss,(uint16_t)(w->r.bp+o));}
static void put(work *w,uint16_t s,uint16_t o,uint16_t v){uint32_t a=address(s,o);w->m[a]=(uint8_t)v;w->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++w->o->bus_writes;}
static void local(work *w,uint16_t o,uint16_t v){put(w,w->ss,(uint16_t)(w->r.bp+o),v);}
static void push(work *w,uint16_t v){w->sp=(uint16_t)(w->sp-2);put(w,w->ss,w->sp,v);}
static uint16_t pop(work *w){uint16_t v=word(w,w->ss,w->sp);w->sp=(uint16_t)(w->sp+2);return v;}
static int valid(const td2ega_state_registers *r){return r->carry<=1 && r->registers.interrupts_enabled<=1 && r->registers.direction<=1;}
static int call(work *w,uint16_t site){td2ega_seek_handle_result r;uint16_t expected=w->sp,ret=(uint16_t)(site+5);uint32_t wide;if(w->o->calls==w->limit){w->o->status=3;w->o->next_segment=w->cs;w->o->next_ip=site;return 0;}++w->o->calls;push(w,w->cs);push(w,ret);td2ega_seek_handle(w->m,w->bytes,w->load,w->ss,w->sp,&w->r,w->service,w->context,w->child_limit,&r);w->r=r.returned;w->sp=r.current_sp;w->o->services+=r.services;w->o->error_calls+=r.error_calls;w->o->bus_writes+=r.bus_writes;w->o->next_segment=r.next_segment;w->o->next_ip=r.next_ip;if(r.status!=0){w->o->status=r.status;return 0;}if(r.next_segment!=w->cs || r.next_ip!=ret || w->sp!=expected){w->o->status=1;return 0;}wide=(uint32_t)w->sp+8;w->sp=(uint16_t)wide;w->r.carry=(uint16_t)(wide>65535);return 1;}
#define AX w.r.registers.ax
#define DX w.r.registers.dx
#define SI w.r.registers.si
#define BP w.r.bp
#define CF w.r.carry
void td2ega_seek_parent(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,uint16_t sp,const td2ega_state_registers *in,td2ega_small_platform_service callback,void *context,uint32_t limit,uint32_t child_limit,td2ega_seek_parent_result *out)
{
    work w;
    if(out==NULL)return;
    *out=(td2ega_seek_parent_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || sp<48 || sp>UINT16_C(0xffe0) || !valid(in))return;
    w=(work){m,bytes,load,(uint16_t)(load+0x13a8),ss,sp,*in,callback,context,limit,child_limit,out};push(&w,BP);BP=w.sp;w.sp=(uint16_t)(w.sp-8);CF=0;push(&w,SI);SI=atbp(&w,6);AX=1;push(&w,AX);AX=0;CF=0;push(&w,AX);push(&w,AX);push(&w,SI);if(!call(&w,0x2aeb))goto finish;local(&w,(uint16_t)-8,AX);local(&w,(uint16_t)-6,DX);CF=(uint16_t)(AX<0xffff);if(AX==0xffff){CF=(uint16_t)(DX<0xffff);if(DX==0xffff){AX=0xffff;DX=0xffff;goto returned;}}
    AX=2;push(&w,AX);AX=0;CF=0;push(&w,AX);push(&w,AX);push(&w,SI);if(!call(&w,0x2b15))goto finish;local(&w,(uint16_t)-4,AX);local(&w,(uint16_t)-2,DX);AX=0;CF=0;push(&w,AX);push(&w,atbp(&w,(uint16_t)-6));push(&w,atbp(&w,(uint16_t)-8));push(&w,SI);if(!call(&w,0x2b2d))goto finish;AX=atbp(&w,(uint16_t)-4);DX=atbp(&w,(uint16_t)-2);
returned:
    SI=pop(&w);w.sp=BP;BP=pop(&w);out->next_ip=pop(&w);out->next_segment=pop(&w);out->status=0;
finish:
    out->current_sp=w.sp;out->returned=w.r;
}
