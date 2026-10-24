#include "td2ega_block_request.h"
#include <stddef.h>
typedef struct work {uint8_t *m;uint32_t bytes;uint16_t load,ss,sp,cs;td2ega_state_registers r;td2ega_small_platform_service service;void *context;uint32_t calls,services,records;td2ega_block_request_result *o;} work;
static uint32_t address(uint16_t s,uint16_t o){return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(work *w,uint16_t s,uint16_t o){uint32_t a=address(s,o);return (uint16_t)(w->m[a]|((uint16_t)w->m[(a+1)&UINT32_C(0xfffff)]<<8));}
static uint16_t rd(work *w,uint16_t o){return word(w,w->r.registers.ds,o);}
static uint16_t arg(work *w,uint16_t o){return word(w,w->ss,(uint16_t)(w->r.bp+o));}
static void put(work *w,uint16_t s,uint16_t o,uint16_t v){uint32_t a=address(s,o);w->m[a]=(uint8_t)v;w->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++w->o->bus_writes;}
static void wr(work *w,uint16_t o,uint16_t v){put(w,w->r.registers.ds,o,v);}
static void push(work *w,uint16_t v){w->sp=(uint16_t)(w->sp-2);put(w,w->ss,w->sp,v);}
static uint16_t pop(work *w){uint16_t v=word(w,w->ss,w->sp);w->sp=(uint16_t)(w->sp+2);return v;}
static uint16_t add(work *w,uint16_t a,uint16_t b){uint32_t v=(uint32_t)a+b;w->r.carry=(uint16_t)(v>65535);return (uint16_t)v;}
static int valid(const td2ega_state_registers *r){return r->carry<=1 && r->registers.interrupts_enabled<=1 && r->registers.direction<=1;}
static int child(work *w,uint16_t site)
{
    td2ega_block_adjust_result r;uint16_t expected=w->sp;
    if(w->o->calls==w->calls){w->o->status=3;w->o->next_segment=w->cs;w->o->next_ip=site;return 0;}++w->o->calls;push(w,(uint16_t)(site+3));td2ega_block_adjust(w->m,w->bytes,w->load,w->ss,w->sp,&w->r,w->service,w->context,w->records,w->services-w->o->services,&r);w->r=r.returned;w->sp=r.current_sp;w->o->services+=r.services;w->o->records+=r.records;w->o->bus_writes+=r.bus_writes;w->o->next_segment=r.next_segment;w->o->next_ip=r.next_ip;if(r.status!=0){w->o->status=r.status;return 0;}if(r.next_segment!=w->cs || r.next_ip!=(uint16_t)(site+3) || w->sp!=expected){w->o->status=1;return 0;}return 1;
}
#define AX w.r.registers.ax
#define BX w.r.registers.bx
#define CX w.r.registers.cx
#define DX w.r.registers.dx
#define SI w.r.registers.si
#define DI w.r.registers.di
#define BP w.r.bp
#define CF w.r.carry
void td2ega_block_request(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,uint16_t sp,const td2ega_state_registers *in,td2ega_small_platform_service callback,void *context,uint32_t call_limit,uint32_t record_limit,uint32_t service_limit,td2ega_block_request_result *out)
{
    work w;uint16_t v,old;unsigned shift;td2ega_small_platform_request request;td2ega_state_registers returned;
    if(out==NULL)return;
    *out=(td2ega_block_request_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || sp<12 || sp>UINT16_C(0xffe0) || !valid(in))return;
    w=(work){m,bytes,load,ss,sp,(uint16_t)(load+0x13a8),*in,callback,context,call_limit,service_limit,record_limit,out};push(&w,BP);BP=w.sp;push(&w,SI);push(&w,DI);push(&w,w.r.registers.es);CF=0;if(arg(&w,10)!=0)goto failure;DI=0x6d2a;DX=arg(&w,8);AX=arg(&w,6);AX=(uint16_t)(AX-1);if(AX==0){if(!child(&w,0x286a))goto done;if(CF)goto failure;goto epilogue;}
    SI=rd(&w,0x6d7a);AX=(uint16_t)(AX-1);if(AX==0)goto advance;CF=(uint16_t)(SI<DI);if(SI==DI)goto advance;AX=rd(&w,(uint16_t)(SI+2));put(&w,ss,(uint16_t)(BP+14),AX);push(&w,SI);if(!child(&w,0x2883))goto done;SI=pop(&w);if(!CF)goto epilogue;
advance:
    SI=add(&w,SI,4);CF=(uint16_t)(SI<0x6d7a);if(SI>=0x6d7a)goto failure;CF=0;if(DX==0)goto failure;BX=DX;BX=add(&w,BX,15);old=BX;BX=(uint16_t)((BX>>1)|(CF<<15));CF=(uint16_t)(old&1);CX=(uint16_t)((CX&0xff00)|3);for(shift=0;shift<3;++shift){CF=(uint16_t)(BX&1);BX>>=1;}AX=(uint16_t)((AX&255)|0x4800);out->next_segment=w.cs;out->next_ip=0x28a9;
    if(out->services==service_limit){out->status=3;goto done;}request=(td2ega_small_platform_request){0x21,0x28a9,w.cs,ss,w.sp,w.r};returned=w.r;if(callback==NULL || !callback(context,m,&request,&returned) || !valid(&returned)){out->status=4;goto done;}++out->services;w.r=returned;if(CF)goto failure;v=DX;DX=AX;AX=v;wr(&w,SI,AX);wr(&w,(uint16_t)(SI+2),DX);wr(&w,0x6d7a,SI);AX=0;CF=0;goto epilogue;
failure:
    AX=0xffff;DX=0xffff;
epilogue:
    w.r.registers.es=pop(&w);DI=pop(&w);SI=pop(&w);w.sp=BP;BP=pop(&w);out->next_ip=pop(&w);out->next_segment=pop(&w);out->status=0;
done:
    out->current_sp=w.sp;out->returned=w.r;
}
