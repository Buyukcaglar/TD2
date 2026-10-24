#include "td2ega_block_align.h"
#include <stddef.h>
typedef struct work {uint8_t *m;uint16_t ss,sp,cs;td2ega_state_registers r;td2ega_block_align_result *o;} work;
static uint32_t address(uint16_t s,uint16_t o){return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(work *w,uint16_t s,uint16_t o){uint32_t a=address(s,o);return (uint16_t)(w->m[a]|((uint16_t)w->m[(a+1)&UINT32_C(0xfffff)]<<8));}
static void push(work *w,uint16_t v){uint32_t a;w->sp=(uint16_t)(w->sp-2);a=address(w->ss,w->sp);w->m[a]=(uint8_t)v;w->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++w->o->bus_writes;}
static uint16_t pop(work *w){uint16_t v=word(w,w->ss,w->sp);w->sp=(uint16_t)(w->sp+2);return v;}
static int valid(const td2ega_state_registers *r){return r->carry<=1 && r->registers.interrupts_enabled<=1 && r->registers.direction<=1;}
static int step(work *w,uint32_t limit,uint16_t ip){if(w->o->iterations==limit){w->o->status=3;w->o->next_segment=w->cs;w->o->next_ip=ip;return 0;}++w->o->iterations;return 1;}
#define AX w.r.registers.ax
#define CX w.r.registers.cx
#define DX w.r.registers.dx
#define SI w.r.registers.si
#define DI w.r.registers.di
#define CF w.r.carry
void td2ega_block_align(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,uint16_t sp,const td2ega_state_registers *in,td2ega_small_platform_service callback,void *context,uint32_t call_limit,uint32_t tail_limit,uint32_t far_limit,uint32_t near_limit,uint32_t record_limit,uint32_t service_limit,uint32_t iteration_limit,td2ega_block_align_result *out)
{
    work w;td2ega_block_tail_result child;uint16_t v,expected;uint32_t wide;
    if(out==NULL)return;
    *out=(td2ega_block_align_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || sp<40 || sp>UINT16_C(0xffe0) || !valid(in))return;
    w=(work){m,ss,sp,(uint16_t)(load+0x13a8),*in,out};push(&w,CX);AX=word(&w,w.r.registers.ds,(uint16_t)(DI-2));CF=0;if(AX&1){CF=(uint16_t)(CX<AX);CX=(uint16_t)(CX-AX);CX=(uint16_t)(CX-1);}CX=(uint16_t)(CX+1);CX=(uint16_t)(CX+1);DX=0x7fff;
    for(;;){if(!step(&w,iteration_limit,0x27e4))goto done;v=word(&w,w.r.registers.es,0x6f36);CF=(uint16_t)(DX<v);if(DX<=v)break;CF=(uint16_t)(DX&1);DX>>=1;if(DX==0)break;}
    for(;;){
        if(!step(&w,iteration_limit,0x27ef))goto done;AX=CX;wide=(uint32_t)AX+SI;CF=(uint16_t)(wide>65535);AX=(uint16_t)wide;if(CF)goto failure;wide=(uint32_t)AX+DX;CF=(uint16_t)(wide>65535);AX=(uint16_t)wide;if(CF)goto shrink;DX=(uint16_t)~DX;AX=(uint16_t)(AX&DX);CF=0;CF=(uint16_t)(AX<SI);AX=(uint16_t)(AX-SI);out->next_segment=w.cs;out->next_ip=0x27ff;
        if(out->calls==call_limit){out->status=3;goto done;}++out->calls;expected=w.sp;push(&w,0x2802);td2ega_block_tail(m,bytes,load,ss,w.sp,&w.r,callback,context,tail_limit,far_limit,near_limit,record_limit,service_limit-out->services,&child);w.r=child.returned;w.sp=child.current_sp;out->child_near_calls+=child.calls;out->child_far_calls+=child.child_far_calls;out->nested_calls+=child.child_near_calls;out->services+=child.services;out->records+=child.records;out->bus_writes+=child.bus_writes;out->next_segment=child.next_segment;out->next_ip=child.next_ip;
        if(child.status!=0){out->status=child.status;goto done;}if(child.next_segment!=w.cs || child.next_ip!=0x2802 || w.sp!=expected || !child.flags_valid){out->status=1;goto done;}if(!child.zero_flag){out->zero_flag=0;goto ret;}DX=(uint16_t)~DX;
shrink:
        CF=(uint16_t)(DX&1);DX>>=1;if(DX==0)goto failure;
    }
failure:
    AX=0;CF=0;out->zero_flag=1;
ret:
    CX=pop(&w);out->next_ip=pop(&w);out->next_segment=w.cs;out->status=0;out->flags_valid=1;
done:
    out->current_sp=w.sp;out->returned=w.r;
}
