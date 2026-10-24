#include "td2ega_heap_walk.h"
#include <stddef.h>
typedef struct work {uint8_t *m;uint32_t bytes;uint16_t load,ss,sp,cs,last_zero;td2ega_state_registers r;const td2ega_heap_walk_limits *limits;td2ega_small_platform_service service;void *context;td2ega_heap_walk_result *o;} work;
static uint32_t address(uint16_t s,uint16_t o){return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(work *w,uint16_t s,uint16_t o){uint32_t a=address(s,o);return (uint16_t)(w->m[a]|((uint16_t)w->m[(a+1)&UINT32_C(0xfffff)]<<8));}
static uint16_t rd(work *w,uint16_t o){return word(w,w->r.registers.ds,o);}
static uint8_t byte(work *w,uint16_t s,uint16_t o){return w->m[address(s,o)];}
static void put(work *w,uint16_t s,uint16_t o,uint16_t v,unsigned n){uint32_t a=address(s,o);w->m[a]=(uint8_t)v;if(n==2)w->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++w->o->bus_writes;}
static void wr(work *w,uint16_t o,uint16_t v){put(w,w->r.registers.ds,o,v,2);}
static void push(work *w,uint16_t v){w->sp=(uint16_t)(w->sp-2);put(w,w->ss,w->sp,v,2);}
static uint16_t pop(work *w){uint16_t v=word(w,w->ss,w->sp);w->sp=(uint16_t)(w->sp+2);return v;}
static uint16_t add(work *w,uint16_t a,uint16_t b){uint32_t v=(uint32_t)a+b;w->r.carry=(uint16_t)(v>65535);return (uint16_t)v;}
static uint16_t sub(work *w,uint16_t a,uint16_t b){w->r.carry=(uint16_t)(a<b);return (uint16_t)(a-b);}
static int valid(const td2ega_state_registers *r){return r->carry<=1 && r->registers.interrupts_enabled<=1 && r->registers.direction<=1;}
static int step(work *w,uint16_t ip){if(w->o->iterations==w->limits->iterations){w->o->status=3;w->o->next_segment=w->cs;w->o->next_ip=ip;return 0;}++w->o->iterations;return 1;}
static void lods(work *w){w->r.registers.ax=rd(w,w->r.registers.si);w->r.registers.si=(uint16_t)(w->r.registers.si+(w->r.registers.direction?-2:2));}
static int helper(work *w,uint16_t site,int align)
{
    td2ega_block_tail_result t;td2ega_block_align_result a;uint16_t expected=w->sp,status,next_segment,next_ip,flags_valid;
    if(w->o->calls==w->limits->calls){w->o->status=3;w->o->next_segment=w->cs;w->o->next_ip=site;return 0;}++w->o->calls;push(w,(uint16_t)(site+3));
    if(align){td2ega_block_align(w->m,w->bytes,w->load,w->ss,w->sp,&w->r,w->service,w->context,w->limits->align_calls,w->limits->tail_calls,w->limits->wrapper_calls,w->limits->adjust_calls,w->limits->records,w->limits->services-w->o->services,w->limits->align_iterations,&a);w->r=a.returned;w->sp=a.current_sp;w->o->align_calls+=a.calls;w->o->tail_calls+=a.child_near_calls;w->o->wrapper_calls+=a.child_far_calls;w->o->adjust_calls+=a.nested_calls;w->o->services+=a.services;w->o->records+=a.records;w->o->child_iterations+=a.iterations;w->o->bus_writes+=a.bus_writes;w->last_zero=a.zero_flag;flags_valid=a.flags_valid;status=a.status;next_segment=a.next_segment;next_ip=a.next_ip;}
    else{td2ega_block_tail(w->m,w->bytes,w->load,w->ss,w->sp,&w->r,w->service,w->context,w->limits->tail_calls,w->limits->wrapper_calls,w->limits->adjust_calls,w->limits->records,w->limits->services-w->o->services,&t);w->r=t.returned;w->sp=t.current_sp;w->o->tail_calls+=t.calls;w->o->wrapper_calls+=t.child_far_calls;w->o->adjust_calls+=t.child_near_calls;w->o->services+=t.services;w->o->records+=t.records;w->o->bus_writes+=t.bus_writes;w->last_zero=t.zero_flag;flags_valid=t.flags_valid;status=t.status;next_segment=t.next_segment;next_ip=t.next_ip;}
    w->o->next_segment=next_segment;w->o->next_ip=next_ip;if(status!=0){w->o->status=status;return 0;}if(next_segment!=w->cs || next_ip!=(uint16_t)(site+3) || w->sp!=expected || !flags_valid){w->o->status=1;return 0;}return 1;
}
#define AX w.r.registers.ax
#define BX w.r.registers.bx
#define CX w.r.registers.cx
#define DX w.r.registers.dx
#define SI w.r.registers.si
#define DI w.r.registers.di
#define CF w.r.carry
void td2ega_heap_walk(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,uint16_t sp,const td2ega_state_registers *in,const td2ega_heap_walk_limits *limits,td2ega_small_platform_service callback,void *context,td2ega_heap_walk_result *out)
{
    work w;unsigned first;uint16_t v;uint8_t b;
    if(out==NULL)return;
    *out=(td2ega_heap_walk_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || limits==NULL || sp<42 || sp>UINT16_C(0xffe0) || !valid(in))return;
    w=(work){m,bytes,load,ss,sp,(uint16_t)(load+0x13a8),0,*in,limits,callback,context,out};CX=(uint16_t)(CX+1);if(CX==0)goto failure;CX=(uint16_t)(CX&0xfffe);CF=0;CF=(uint16_t)(CX<0xffee);if(CX>=0xffee)goto failure;SI=rd(&w,(uint16_t)(BX+2));w.r.registers.direction=0;if(!step(&w,0x2700))goto done;lods(&w);DI=SI;CF=0;if((AX&1)==0)goto used_begin;first=1;
free_block:
    if(!step(&w,(uint16_t)(first?0x2707:0x275f)))goto done;AX=(uint16_t)(AX-1);CF=(uint16_t)(AX<CX);if(AX>=CX)goto allocate;DX=AX;SI=add(&w,SI,AX);lods(&w);CF=0;if((AX&1)==0){if(first)goto used_begin;goto used_header;}AX=add(&w,AX,DX);AX=add(&w,AX,2);SI=DI;wr(&w,(uint16_t)(SI-2),AX);goto free_block;
allocate:
    DI=SI;if(AX!=CX){DI=add(&w,DI,CX);wr(&w,(uint16_t)(SI-2),CX);AX=sub(&w,AX,CX);AX=(uint16_t)(AX-1);wr(&w,DI,AX);}else{DI=add(&w,DI,CX);b=byte(&w,w.r.registers.ds,(uint16_t)(SI-2));put(&w,w.r.registers.ds,(uint16_t)(SI-2),(uint8_t)(b-1),1);}AX=SI;DX=w.r.registers.ds;CX=ss;CF=(uint16_t)(DX<CX);out->zero_flag=(uint16_t)(DX==CX);if(DX!=CX)put(&w,w.r.registers.es,0x6f34,w.r.registers.ds,2);wr(&w,(uint16_t)(BX+2),DI);goto ret;
used_begin:
    put(&w,w.r.registers.es,0x6f3a,2,1);
used_header:
    CF=(uint16_t)(AX<0xfffe);if(AX==0xfffe)goto segment_end;DI=SI;SI=add(&w,SI,AX);
scan:
    if(!step(&w,0x2758))goto done;lods(&w);CF=0;if((AX&1)==0)goto used_header;DI=SI;first=0;goto free_block;
segment_end:
    AX=rd(&w,(uint16_t)(BX+8));CF=0;if(AX!=0){w.r.registers.ds=AX;goto restart;}b=byte(&w,w.r.registers.es,0x6f3a);b=(uint8_t)(b-1);put(&w,w.r.registers.es,0x6f3a,b,1);if(b==0)goto grow;AX=w.r.registers.ds;DI=ss;CF=(uint16_t)(AX<DI);if(AX!=DI)w.r.registers.ds=word(&w,w.r.registers.es,0x6f30);
restart:
    SI=rd(&w,BX);goto scan;
grow:
    SI=rd(&w,(uint16_t)(BX+6));AX=0;CF=0;if(!helper(&w,0x27a1,0))goto done;CF=(uint16_t)(AX<SI);if(AX==SI)goto align;AX=(uint16_t)((AX&0xff00)|(AX&1));CF=0;AX=(uint16_t)(AX+1);AX=(uint16_t)(AX+1);AX=(uint16_t)((uint8_t)AX|(((uint8_t)AX&0x80)?0xff00:0));if(!helper(&w,0x27ad,0))goto done;if(w.last_zero)goto failure;b=byte(&w,w.r.registers.ds,(uint16_t)(DI-2));put(&w,w.r.registers.ds,(uint16_t)(DI-2),(uint8_t)(b-1),1);
align:
    if(!helper(&w,0x27b5,1))goto done;if(w.last_zero)goto failure;v=SI;SI=AX;AX=v;SI=(uint16_t)(SI-1);SI=(uint16_t)(SI-1);goto scan;
failure:
    AX=w.r.registers.ds;CX=ss;CF=(uint16_t)(AX<CX);if(AX!=CX)put(&w,w.r.registers.es,0x6f34,AX,2);AX=rd(&w,BX);wr(&w,(uint16_t)(BX+2),AX);AX=0;CF=0;DX=0;out->zero_flag=1;
ret:
    out->next_ip=pop(&w);out->next_segment=w.cs;out->status=0;out->flags_valid=1;
done:
    out->current_sp=w.sp;out->returned=w.r;
}
