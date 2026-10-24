#include "td2ega_block_wrapper.h"
#include <stddef.h>
typedef struct work {uint8_t *m;uint16_t ss,sp;td2ega_state_registers r;td2ega_block_wrapper_result *o;} work;
static uint32_t address(uint16_t s,uint16_t o){return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(work *w,uint16_t s,uint16_t o){uint32_t a=address(s,o);return (uint16_t)(w->m[a]|((uint16_t)w->m[(a+1)&UINT32_C(0xfffff)]<<8));}
static void push(work *w,uint16_t v){uint32_t a;w->sp=(uint16_t)(w->sp-2);a=address(w->ss,w->sp);w->m[a]=(uint8_t)v;w->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++w->o->bus_writes;}
static uint16_t pop(work *w){uint16_t v=word(w,w->ss,w->sp);w->sp=(uint16_t)(w->sp+2);return v;}
static int valid(const td2ega_state_registers *r){return r->carry<=1 && r->registers.interrupts_enabled<=1 && r->registers.direction<=1;}
#define AX w.r.registers.ax
#define BX w.r.registers.bx
#define DX w.r.registers.dx
#define CF w.r.carry
void td2ega_block_wrapper(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,uint16_t sp,const td2ega_state_registers *in,td2ega_small_platform_service callback,void *context,uint32_t call_limit,uint32_t child_call_limit,uint32_t record_limit,uint32_t service_limit,td2ega_block_wrapper_result *out)
{
    work w;td2ega_block_request_result child;uint16_t expected,cs=(uint16_t)(load+0x13a8),compared;uint32_t wide;
    if(out==NULL)return;
    *out=(td2ega_block_wrapper_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || sp<30 || sp>UINT16_C(0xffe0) || !valid(in))return;
    w=(work){m,ss,sp,*in,out};push(&w,BX);push(&w,AX);DX=0;CF=0;push(&w,w.r.registers.ds);push(&w,DX);push(&w,DX);push(&w,AX);AX=1;push(&w,AX);push(&w,w.r.registers.es);w.r.registers.ds=pop(&w);out->next_segment=cs;out->next_ip=0x283e;
    if(call_limit==0){out->status=3;goto done;}++out->calls;expected=w.sp;push(&w,cs);push(&w,0x2843);td2ega_block_request(m,bytes,load,ss,w.sp,&w.r,callback,context,child_call_limit,record_limit,service_limit,&child);w.r=child.returned;w.sp=child.current_sp;out->child_calls+=child.calls;out->services+=child.services;out->records+=child.records;out->bus_writes+=child.bus_writes;out->next_segment=child.next_segment;out->next_ip=child.next_ip;
    if(child.status!=0){out->status=child.status;goto done;}if(child.next_segment!=cs || child.next_ip!=0x2843 || w.sp!=expected){out->status=1;goto done;}wide=(uint32_t)w.sp+8;CF=(uint16_t)(wide>65535);w.sp=(uint16_t)wide;compared=DX;CF=(uint16_t)(compared<0xffff);w.r.registers.ds=pop(&w);DX=pop(&w);BX=pop(&w);if(compared==0xffff)out->zero_flag=1;else{CF=0;out->zero_flag=(uint16_t)(DX==0);}out->flags_valid=1;out->next_ip=pop(&w);out->next_segment=cs;out->status=0;
done:
    out->current_sp=w.sp;out->returned=w.r;
}
