#include "td2ega_control_controllers.h"
#include <stddef.h>
typedef struct work {uint8_t *m;uint32_t bytes;uint16_t load,cs,ss,sp;td2ega_state_registers r;uint32_t limit,child_limit;td2ega_control_controllers_result *o;} work;
static uint32_t address(uint16_t s,uint16_t o){return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(work *w,uint16_t s,uint16_t o){uint32_t a=address(s,o);return (uint16_t)(w->m[a]|((uint16_t)w->m[(a+1)&UINT32_C(0xfffff)]<<8));}
static uint16_t rd(work *w,uint16_t o){return word(w,w->r.registers.ds,o);}
static uint8_t byte(work *w,uint16_t o){return w->m[address(w->r.registers.ds,o)];}
static void put(work *w,uint16_t s,uint16_t o,uint16_t v,unsigned n){uint32_t a=address(s,o);w->m[a]=(uint8_t)v;if(n==2)w->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++w->o->bus_writes;}
static void wr(work *w,uint16_t o,uint16_t v){put(w,w->r.registers.ds,o,v,2);}
static void wb(work *w,uint16_t o,uint16_t v){put(w,w->r.registers.ds,o,v,1);}
static void push(work *w,uint16_t v){w->sp=(uint16_t)(w->sp-2);put(w,w->ss,w->sp,v,2);}
static uint16_t pop(work *w){uint16_t v=word(w,w->ss,w->sp);w->sp=(uint16_t)(w->sp+2);return v;}
static int32_t sw(uint16_t v){return v&0x8000?(int32_t)v-65536:(int32_t)v;}
static uint16_t add(work *w,uint16_t a,uint16_t b){uint32_t v=(uint32_t)a+b;w->r.carry=(uint16_t)(v>65535);return (uint16_t)v;}
static uint16_t sub(work *w,uint16_t a,uint16_t b){w->r.carry=(uint16_t)(a<b);return (uint16_t)(a-b);}
static void cmp(work *w,uint16_t a,uint16_t b){w->r.carry=(uint16_t)(a<b);}
static int invoke(work *w,uint16_t selector,int tail,uint16_t site)
{
    td2ega_control_bus_result r;uint16_t expected=w->sp,ret=(uint16_t)(site+3);
    if(!tail){if(w->o->calls==w->limit){w->o->status=3;w->o->next_segment=w->cs;w->o->next_ip=site;return 0;}++w->o->calls;push(w,ret);}
    td2ega_control_bus(w->m,w->bytes,w->load,w->ss,w->sp,selector,&w->r,w->child_limit,&r);w->r=r.returned;w->sp=r.current_sp;w->o->nested_calls+=r.calls;w->o->bus_writes+=r.bus_writes;w->o->next_segment=r.next_segment;w->o->next_ip=r.next_ip;if(r.status!=0){w->o->status=r.status;return 0;}if(tail){w->o->status=0;return 0;}if(r.next_segment!=w->cs || r.next_ip!=ret || w->sp!=expected){w->o->status=1;return 0;}return 1;
}
#define AX w.r.registers.ax
#define BX w.r.registers.bx
#define CX w.r.registers.cx
#define DX w.r.registers.dx
#define CF w.r.carry
void td2ega_control_controllers(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,uint16_t sp,uint16_t entry,const td2ega_state_registers *in,uint32_t limit,uint32_t child_limit,td2ega_control_controllers_result *out)
{
    work w;uint16_t v;uint8_t b;uint32_t wide;unsigned shift;
    if(out==NULL)return;
    *out=(td2ega_control_controllers_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || sp<20 || sp>UINT16_C(0xffe0) || entry>1 || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1)return;
    w=(work){m,bytes,load,(uint16_t)(load+0x6c9),ss,sp,*in,limit,child_limit,out};
    if(entry==0){
        wb(&w,0x2f56,0);wb(&w,0x33b2,0);if(!invoke(&w,0,0,0x5a79))goto finish;if(!invoke(&w,1,0,0x5a7c))goto finish;b=byte(&w,0x33d4);cmp(&w,b,1);
        if(b==1){AX=rd(&w,0x52cc);AX=sub(&w,AX,25);wr(&w,0x52cc,AX);v=rd(&w,0x33d0);cmp(&w,AX,v);if(sw(AX)<sw(v))goto increase_counter;goto returned;}
        cmp(&w,b,4);if(b==4){AX=rd(&w,0x33ce);AX=add(&w,AX,3);wr(&w,0x33ce,AX);cmp(&w,AX,100);if(AX>=100)wb(&w,0x5490,2);goto returned;}
        AX=rd(&w,0x52cc);AX=add(&w,AX,25);wr(&w,0x52cc,AX);v=rd(&w,0x33d0);cmp(&w,AX,v);if(sw(AX)<=sw(v))goto returned;
increase_counter:
        AX=rd(&w,0x33ce);BX=rd(&w,0x33d2);AX=add(&w,AX,BX);BX=(uint16_t)(BX+2);wr(&w,0x33ce,AX);wr(&w,0x33d2,BX);cmp(&w,AX,280);if(AX>=280)wb(&w,0x5490,2);goto returned;
    }
    CF=0;if(byte(&w,0x33d5)!=0)goto fixed1600;b=byte(&w,0x336c);AX=(uint16_t)((AX&0xff00)|b);CF=0;if(b&0x80)goto fixed1600;CF=0;if(byte(&w,0x336f)!=0){DX=800;goto fixed_current;}CF=0;if(byte(&w,0x3365)!=0)goto ordinary;CF=0;if(byte(&w,0x3366)!=0)goto ordinary;b=byte(&w,0x2f56);BX=(uint16_t)((BX&0xff00)|b);CF=0;if(b==0)goto ordinary;BX=(uint8_t)BX;CF=0;b=(uint8_t)AX;CF=0;if(b==0 || (b&0x80)){wb(&w,0x33b2,0);goto returned;}
    b=byte(&w,(uint16_t)(BX+0x33bf));CF=0;if(b!=0){DX=400;goto fixed_current;}b=byte(&w,0x33b7);cmp(&w,b,8);if(b!=8){cmp(&w,b,2);if(b>=2)goto returned;}wb(&w,0x2f5b,1);BX=rd(&w,0x332c);wide=(uint32_t)BX*2;BX=(uint16_t)wide;CF=(uint16_t)(wide>65535);BX=(uint8_t)(BX>>8);CF=0;b=(uint8_t)BX;cmp(&w,b,80);if(b>=80)BX=(uint16_t)((BX&0xff00)|80);AX=(uint16_t)((AX&0xff00)|byte(&w,(uint16_t)(BX+0x2419)));b=byte(&w,0x33b2);cmp(&w,b,8);DX=rd(&w,0x3328);wide=(uint32_t)(uint8_t)AX*(uint8_t)(DX>>8);AX=(uint16_t)wide;CF=(uint16_t)(wide>255);for(shift=0;shift<5;++shift){CF=(uint16_t)(AX&1);AX>>=1;}DX=AX;CF=0;if(byte(&w,0x336f)!=0){CF=(uint16_t)(DX&1);DX>>=1;}if(!invoke(&w,2,0,0x4582))goto finish;(void)invoke(&w,3,1,0);goto finish;
ordinary:
    if(!invoke(&w,0,0,0x4521))goto finish;b=byte(&w,0x336c);CF=0;if(b&0x80)goto fixed1600;DX=0;CF=0;if(!invoke(&w,2,0,0x452d))goto finish;goto returned;
fixed1600:
    (void)invoke(&w,1,1,0);goto finish;
fixed_current:
    (void)invoke(&w,4,1,0);goto finish;
returned:
    out->next_ip=pop(&w);out->next_segment=w.cs;out->status=0;
finish:
    out->current_sp=w.sp;out->returned=w.r;
}
