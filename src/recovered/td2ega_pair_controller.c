#include "td2ega_pair_controller.h"
#include <stddef.h>
typedef struct work {uint8_t *m;uint32_t bytes;uint16_t load,cs,ss,sp;uint32_t limit;td2ega_state_registers r;td2ega_pair_controller_result *o;} work;
static uint32_t address(uint16_t s,uint16_t o){return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(work *w,uint16_t s,uint16_t o){uint32_t a=address(s,o);return (uint16_t)(w->m[a]|((uint16_t)w->m[(a+1)&UINT32_C(0xfffff)]<<8));}
static uint16_t rd(work *w,uint16_t o){return word(w,w->r.registers.ds,o);}
static uint8_t byte(work *w,uint16_t o){return w->m[address(w->r.registers.ds,o)];}
static void put(work *w,uint16_t s,uint16_t o,uint16_t v,unsigned n){uint32_t a=address(s,o);w->m[a]=(uint8_t)v;if(n==2)w->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++w->o->bus_writes;}
static void wr(work *w,uint16_t o,uint16_t v){put(w,w->r.registers.ds,o,v,2);}
static void wb(work *w,uint16_t o,uint16_t v){put(w,w->r.registers.ds,o,v,1);}
static uint16_t pop(work *w){uint16_t v=word(w,w->ss,w->sp);w->sp=(uint16_t)(w->sp+2);return v;}
static uint16_t add(work *w,uint16_t a,uint16_t b){uint32_t v=(uint32_t)a+b;w->r.carry=(uint16_t)(v>65535);return (uint16_t)v;}
static uint16_t sub(work *w,uint16_t a,uint16_t b){w->r.carry=(uint16_t)(a<b);return (uint16_t)(a-b);}
static int call(work *w,uint16_t site){td2ega_small_arithmetic_result result;uint16_t expected=w->sp,ret=(uint16_t)(site+3);if(w->o->calls==w->limit){w->o->status=3;w->o->next_segment=w->cs;w->o->next_ip=site;return 0;}++w->o->calls;w->sp=(uint16_t)(w->sp-2);put(w,w->ss,w->sp,ret,2);td2ega_small_arithmetic(w->m,w->bytes,w->load,w->ss,w->sp,2,&w->r,0,&result);w->r=result.returned;w->sp=result.current_sp;w->o->bus_writes+=result.bus_writes;w->o->next_segment=result.next_segment;w->o->next_ip=result.next_ip;if(result.status!=0){w->o->status=result.status;return 0;}if(result.next_segment!=w->cs || result.next_ip!=ret || w->sp!=expected){w->o->status=1;return 0;}return 1;}
#define AX w.r.registers.ax
#define BX w.r.registers.bx
#define CX w.r.registers.cx
#define DX w.r.registers.dx
#define SI w.r.registers.si
#define DI w.r.registers.di
#define BP w.r.bp
#define CF w.r.carry
void td2ega_pair_controller(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,uint16_t sp,const td2ega_state_registers *in,uint32_t limit,td2ega_pair_controller_result *out)
{
    work w;uint16_t v;
    if(out==NULL)return;
    *out=(td2ega_pair_controller_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || sp<18 || sp>UINT16_C(0xffe0) || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1)return;
    w=(work){m,bytes,load,(uint16_t)(load+0x6c9),ss,sp,limit,*in,out};BP=0;CF=0;SI=0x52c8;DI=0x52d0;BX=rd(&w,0x334a);DX=rd(&w,0x3332);CF=0;
    if(byte(&w,0x3379)!=0){if(!call(&w,0x5976))goto finish;wr(&w,0x334a,CX);if(CF){CF=0;if((BX&0x8000)==0){wb(&w,0x5490,2);wb(&w,0x3375,10);v=(uint16_t)(rd(&w,0x331c)+1);wr(&w,0x331c,v);}else{AX=rd(&w,0x52ce);wr(&w,0x52d6,AX);}goto returned;}}
    CF=0;if(byte(&w,0x33b8)!=0){
        BP=(uint16_t)(BP+1);DI=0x52d8;BX=rd(&w,0x334c);if(!call(&w,0x598e))goto finish;wr(&w,0x334c,CX);
        if(CF){CF=0;if((CX&0x8000)==0){wr(&w,0x8424,1);wb(&w,0x5490,2);}else{v=rd(&w,0x52da);v=sub(&w,v,2);wr(&w,0x52da,v);AX=rd(&w,0x52ce);wr(&w,0x52de,AX);wb(&w,0x33b7,1);wb(&w,0x33b8,1);wb(&w,0x33ba,0);}goto returned;}
        BP=(uint16_t)(BP+1);SI=0x52d0;DX=rd(&w,0x52d4);BX=rd(&w,0x334e);CF=0;
        if(byte(&w,0x3379)!=0){if(!call(&w,0x59aa))goto finish;wr(&w,0x334e,CX);if(CF){CF=0;if((CX&0x8000)==0){wb(&w,0x3375,30);v=(uint16_t)(rd(&w,0x331c)+1);wr(&w,0x331c,v);}else{v=rd(&w,0x52da);v=sub(&w,v,2);wr(&w,0x52da,v);AX=rd(&w,0x52d6);AX=add(&w,AX,0x500);wr(&w,0x52de,AX);wb(&w,0x33b6,1);wb(&w,0x33b8,1);wb(&w,0x33ba,0);}goto returned;}}
    }
returned:
    out->next_ip=pop(&w);out->next_segment=w.cs;out->status=0;
finish:
    out->current_sp=w.sp;out->returned=w.r;
}
