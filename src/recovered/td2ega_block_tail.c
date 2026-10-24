#include "td2ega_block_tail.h"
#include <stddef.h>
typedef struct work {uint8_t *m;uint16_t ss,sp;td2ega_state_registers r;td2ega_block_tail_result *o;} work;
static uint32_t address(uint16_t s,uint16_t o){return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(work *w,uint16_t s,uint16_t o){uint32_t a=address(s,o);return (uint16_t)(w->m[a]|((uint16_t)w->m[(a+1)&UINT32_C(0xfffff)]<<8));}
static void put(work *w,uint16_t s,uint16_t o,uint16_t v){uint32_t a=address(s,o);w->m[a]=(uint8_t)v;w->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++w->o->bus_writes;}
static void push(work *w,uint16_t v){w->sp=(uint16_t)(w->sp-2);put(w,w->ss,w->sp,v);}
static uint16_t pop(work *w){uint16_t v=word(w,w->ss,w->sp);w->sp=(uint16_t)(w->sp+2);return v;}
static int valid(const td2ega_state_registers *r){return r->carry<=1 && r->registers.interrupts_enabled<=1 && r->registers.direction<=1;}
#define AX w.r.registers.ax
#define BX w.r.registers.bx
#define CX w.r.registers.cx
#define DX w.r.registers.dx
#define SI w.r.registers.si
#define DI w.r.registers.di
#define CF w.r.carry
void td2ega_block_tail(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,uint16_t sp,const td2ega_state_registers *in,td2ega_small_platform_service callback,void *context,uint32_t call_limit,uint32_t far_limit,uint32_t near_limit,uint32_t record_limit,uint32_t service_limit,td2ega_block_tail_result *out)
{
    work w;td2ega_block_wrapper_result child;uint16_t cs=(uint16_t)(load+0x13a8),expected;uint32_t wide;
    if(out==NULL)return;
    *out=(td2ega_block_tail_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || sp<36 || sp>UINT16_C(0xffe0) || !valid(in))return;
    w=(work){m,ss,sp,*in,out};push(&w,DX);push(&w,CX);out->next_segment=cs;out->next_ip=0x2810;
    if(call_limit==0){out->status=3;goto done;}++out->calls;expected=w.sp;push(&w,0x2813);td2ega_block_wrapper(m,bytes,load,ss,w.sp,&w.r,callback,context,far_limit,near_limit,record_limit,service_limit,&child);w.r=child.returned;w.sp=child.current_sp;out->child_far_calls+=child.calls;out->child_near_calls+=child.child_calls;out->services+=child.services;out->records+=child.records;out->bus_writes+=child.bus_writes;out->next_segment=child.next_segment;out->next_ip=child.next_ip;
    if(child.status!=0){out->status=child.status;goto done;}if(child.next_segment!=cs || child.next_ip!=0x2813 || w.sp!=expected || !child.flags_valid){out->status=1;goto done;}out->zero_flag=child.zero_flag;
    if(!child.zero_flag){push(&w,DI);DI=SI;SI=AX;wide=(uint32_t)SI+DX;CF=(uint16_t)(wide>65535);SI=(uint16_t)wide;put(&w,w.r.registers.ds,(uint16_t)(SI-2),0xfffe);put(&w,w.r.registers.ds,(uint16_t)(BX+6),SI);DX=SI;CF=(uint16_t)(DX<DI);DX=(uint16_t)(DX-DI);DX=(uint16_t)(DX-1);out->zero_flag=(uint16_t)(DX==0);put(&w,w.r.registers.ds,(uint16_t)(DI-2),DX);AX=pop(&w);}
    CX=pop(&w);DX=pop(&w);out->next_ip=pop(&w);out->next_segment=cs;out->status=0;out->flags_valid=1;
done:
    out->current_sp=w.sp;out->returned=w.r;
}
