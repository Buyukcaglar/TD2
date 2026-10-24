#include "td2ega_record_sequence.h"
#include <stddef.h>
typedef struct work {uint8_t *m;uint32_t bytes;uint16_t load,cs,ss,sp;uint32_t limit,child_limit;td2ega_state_registers r;td2ega_record_sequence_result *o;} work;
static uint32_t address(uint16_t s,uint16_t o){return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(work *w,uint16_t s,uint16_t o){uint32_t a=address(s,o);return (uint16_t)(w->m[a]|((uint16_t)w->m[(a+1)&UINT32_C(0xfffff)]<<8));}
static uint16_t rd(work *w,uint16_t o){return word(w,w->r.registers.ds,o);}
static void put(work *w,uint16_t s,uint16_t o,uint16_t v){uint32_t a=address(s,o);w->m[a]=(uint8_t)v;w->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++w->o->bus_writes;}
static void push(work *w,uint16_t v){w->sp=(uint16_t)(w->sp-2);put(w,w->ss,w->sp,v);}
static uint16_t pop(work *w){uint16_t v=word(w,w->ss,w->sp);w->sp=(uint16_t)(w->sp+2);return v;}
static int call(work *w,uint16_t site,int adjust)
{
    td2ega_record_math_result a;td2ega_small_arithmetic_result b;uint16_t expected=w->sp,ret=(uint16_t)(site+3),status;
    if(w->o->calls==w->limit){w->o->status=3;w->o->next_segment=w->cs;w->o->next_ip=site;return 0;}++w->o->calls;push(w,ret);
    if(adjust){td2ega_record_math(w->m,w->bytes,w->load,w->ss,w->sp,4,&w->r,w->child_limit,&a);w->r=a.returned;w->sp=a.current_sp;w->o->iterations+=a.iterations;w->o->bus_writes+=a.bus_writes;w->o->next_segment=a.next_segment;w->o->next_ip=a.next_ip;status=a.status;}
    else{td2ega_small_arithmetic(w->m,w->bytes,w->load,w->ss,w->sp,0,&w->r,w->child_limit,&b);w->r=b.returned;w->sp=b.current_sp;w->o->iterations+=b.iterations;w->o->bus_writes+=b.bus_writes;w->o->next_segment=b.next_segment;w->o->next_ip=b.next_ip;status=b.status;}
    if(status!=0){w->o->status=status;return 0;}if(w->o->next_segment!=w->cs || w->o->next_ip!=ret || w->sp!=expected){w->o->status=1;return 0;}return 1;
}
#define AX w.r.registers.ax
#define CX w.r.registers.cx
#define DX w.r.registers.dx
#define SI w.r.registers.si
#define DI w.r.registers.di
#define BP w.r.bp
#define CF w.r.carry
void td2ega_record_sequence(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,uint16_t sp,const td2ega_state_registers *in,uint32_t limit,uint32_t child_limit,td2ega_record_sequence_result *out)
{
    work w;
    if(out==NULL)return;
    *out=(td2ega_record_sequence_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || sp<24 || sp>UINT16_C(0xffe0) || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1)return;
    w=(work){m,bytes,load,(uint16_t)(load+0x6c9),ss,sp,limit,child_limit,*in,out};push(&w,SI);push(&w,DI);push(&w,BP);SI=rd(&w,0x330e);BP=0x39a3;CX=rd(&w,0x5356);if(!call(&w,0x5ae8,1))goto finish;
    SI=rd(&w,0x330c);BP=0x3813;CX=rd(&w,0x5354);if(!call(&w,0x5af6,1))goto finish;
    SI=0x39a3;CX=rd(&w,0x5356);AX=rd(&w,0x52c8);DX=rd(&w,0x52ca);if(!call(&w,0x5b07,0))goto finish;CF=(uint16_t)(SI<0x39a3);SI=(uint16_t)(SI-0x39a3);put(&w,w.r.registers.ds,0x330e,SI);
    SI=0x3813;CX=rd(&w,0x5354);if(!call(&w,0x5b19,0))goto finish;CF=(uint16_t)(SI<0x3813);SI=(uint16_t)(SI-0x3813);put(&w,w.r.registers.ds,0x330c,SI);CF=0;
    if(w.m[address(w.r.registers.ds,0x3379)]!=0){
        SI=0x39a3;CX=rd(&w,0x5356);AX=rd(&w,0x52d0);DX=rd(&w,0x52d2);if(!call(&w,0x5b39,0))goto finish;CF=(uint16_t)(SI<0x39a3);SI=(uint16_t)(SI-0x39a3);put(&w,w.r.registers.ds,0x3312,SI);
        SI=0x3813;CX=rd(&w,0x5354);if(!call(&w,0x5b4b,0))goto finish;CF=(uint16_t)(SI<0x3813);SI=(uint16_t)(SI-0x3813);put(&w,w.r.registers.ds,0x3310,SI);
    }
    BP=pop(&w);DI=pop(&w);SI=pop(&w);out->next_ip=pop(&w);out->next_segment=pop(&w);out->status=0;
finish:
    out->current_sp=w.sp;out->returned=w.r;
}
