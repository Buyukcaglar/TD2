#include "td2ega_field_controller.h"
#include <stddef.h>
typedef struct work {uint8_t *m;uint32_t bytes;uint16_t load,cs,ss,sp;uint32_t limit,child_limit;td2ega_state_registers r;td2ega_field_controller_result *o;} work;
static uint32_t address(uint16_t s,uint16_t o){return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(work *w,uint16_t s,uint16_t o){uint32_t a=address(s,o);return (uint16_t)(w->m[a]|((uint16_t)w->m[(a+1)&UINT32_C(0xfffff)]<<8));}
static uint16_t rd(work *w,uint16_t o){return word(w,w->r.registers.ds,o);}
static uint8_t byte(work *w,uint16_t o){return w->m[address(w->r.registers.ds,o)];}
static void put(work *w,uint16_t s,uint16_t o,uint16_t v,unsigned n){uint32_t a=address(s,o);w->m[a]=(uint8_t)v;if(n==2)w->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++w->o->bus_writes;}
static void wr(work *w,uint16_t o,uint16_t v){put(w,w->r.registers.ds,o,v,2);}
static void wb(work *w,uint16_t o,uint16_t v){put(w,w->r.registers.ds,o,v,1);}
static uint16_t pop(work *w){uint16_t v=word(w,w->ss,w->sp);w->sp=(uint16_t)(w->sp+2);return v;}
static int32_t sw(uint16_t v){return v&0x8000?(int32_t)v-65536:(int32_t)v;}
static uint16_t add(work *w,uint16_t a,uint16_t b){uint32_t v=(uint32_t)a+b;w->r.carry=(uint16_t)(v>65535);return (uint16_t)v;}
static uint16_t sub(work *w,uint16_t a,uint16_t b){w->r.carry=(uint16_t)(a<b);return (uint16_t)(a-b);}
static void cmp(work *w,uint16_t a,uint16_t b){w->r.carry=(uint16_t)(a<b);}
static int call(work *w,uint16_t site,unsigned kind,uint16_t selector)
{
    td2ega_record_math_result m;td2ega_small_arithmetic_result a;td2ega_small_algorithms_result b;td2ega_table_scalar_result t;uint16_t status,next_segment,next_ip,expected=w->sp,ret=(uint16_t)(site+3);
    if(w->o->calls==w->limit){w->o->status=3;w->o->next_segment=w->cs;w->o->next_ip=site;return 0;}++w->o->calls;w->sp=(uint16_t)(w->sp-2);put(w,w->ss,w->sp,ret,2);
    if(kind==0){td2ega_record_math(w->m,w->bytes,w->load,w->ss,w->sp,selector,&w->r,w->child_limit,&m);w->r=m.returned;w->sp=m.current_sp;w->o->bus_writes+=m.bus_writes;w->o->child_iterations+=m.iterations;status=m.status;next_segment=m.next_segment;next_ip=m.next_ip;}
    else if(kind==1){td2ega_small_arithmetic(w->m,w->bytes,w->load,w->ss,w->sp,selector,&w->r,w->child_limit,&a);w->r=a.returned;w->sp=a.current_sp;w->o->bus_writes+=a.bus_writes;w->o->child_iterations+=a.iterations;status=a.status;next_segment=a.next_segment;next_ip=a.next_ip;}
    else if(kind==2){td2ega_small_algorithms(w->m,w->bytes,w->load,w->ss,w->sp,selector,&w->r,w->child_limit,&b);w->r=b.returned;w->sp=b.current_sp;w->o->bus_writes+=b.bus_writes;w->o->child_iterations+=b.iterations;status=b.status;next_segment=b.next_segment;next_ip=b.next_ip;}
    else{td2ega_table_scalar(w->m,w->bytes,w->load,w->ss,w->sp,selector,&w->r,&t);w->r=t.returned;w->sp=t.current_sp;w->o->bus_writes+=t.bus_writes;status=t.status;next_segment=t.next_segment;next_ip=t.next_ip;}
    w->o->next_segment=next_segment;w->o->next_ip=next_ip;if(status!=0){w->o->status=status;return 0;}if(next_segment!=w->cs || next_ip!=ret || w->sp!=expected){w->o->status=1;return 0;}return 1;
}
#define AX w.r.registers.ax
#define BX w.r.registers.bx
#define CX w.r.registers.cx
#define DX w.r.registers.dx
#define SI w.r.registers.si
#define DI w.r.registers.di
#define CF w.r.carry
void td2ega_field_controller(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,uint16_t sp,const td2ega_state_registers *in,uint32_t limit,uint32_t child_limit,td2ega_field_controller_result *out)
{
    work w;uint8_t b;
    if(out==NULL)return;
    *out=(td2ega_field_controller_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || sp<34 || sp>UINT16_C(0xffe0) || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1)return;
    w=(work){m,bytes,load,(uint16_t)(load+0x6c9),ss,sp,limit,child_limit,*in,out};wr(&w,0x3340,100);BX=rd(&w,0x52ca);DI=255;if(!call(&w,0x588d,0,0))goto finish;wb(&w,0x33be,(uint8_t)BX);BX=rd(&w,0x52ca);DI=1600;SI=rd(&w,0x52ce);if(!call(&w,0x589f,1,3))goto finish;wb(&w,0x3376,(uint8_t)AX);DX=rd(&w,0x52ca);DI=rd(&w,0x330c);CX=rd(&w,(uint16_t)(DI+0x3815));AX=byte(&w,0x52cf);CF=0;BX=0xffce;if(!call(&w,0x58b9,2,1))goto finish;wr(&w,0x333e,AX);DX=rd(&w,0x52ca);DI=rd(&w,0x330e);CX=rd(&w,(uint16_t)(DI+0x39a5));AX=byte(&w,0x52cf);CF=0;BX=50;if(!call(&w,0x58d3,2,1))goto finish;BX=rd(&w,(uint16_t)(DI+0x39a9));CF=0;if(byte(&w,0x3376)==0){if(!call(&w,0x58e1,3,3))goto finish;}AX=rd(&w,0x52cc);AX=add(&w,AX,40);if(!call(&w,0x58ea,3,4))goto finish;b=byte(&w,0x33b7);BX=(uint16_t)((BX&0xff00)|b);cmp(&w,b,2);if(b>=2)CX=200;CF=0;if(byte(&w,0x3376)!=0)CX=200;AX=rd(&w,0x52ce);cmp(&w,b,2);
    if(b<2){AX=sub(&w,AX,rd(&w,0x3344));if(CF){cmp(&w,DX,20);if(DX<20)goto mark_ff;}else{cmp(&w,DX,20);if(DX<20)goto mark_ff;cmp(&w,AX,1600);if(AX>=1600)goto mark_ff;cmp(&w,rd(&w,0x3344),0);if(rd(&w,0x3344)==0)goto mark_ff;wb(&w,0x336c,0);goto adjust;}}else goto mark_ff;
    goto adjust;
mark_ff:
    wb(&w,0x336c,255);
adjust:
    AX=rd(&w,0x52cc);AX=add(&w,AX,40);cmp(&w,AX,CX);if(AX!=CX){if(sw(AX)>=sw(CX)){AX=sub(&w,AX,44);cmp(&w,AX,CX);if(sw(AX)<=sw(CX))AX=CX;}else{AX=add(&w,AX,44);cmp(&w,AX,CX);if(sw(AX)>=sw(CX))AX=CX;}}AX=sub(&w,AX,40);wr(&w,0x52cc,AX);out->next_ip=pop(&w);out->next_segment=w.cs;out->status=0;
finish:
    out->current_sp=w.sp;out->returned=w.r;
}
