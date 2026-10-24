#include "td2ega_indexed_sample.h"
#include <stddef.h>
typedef struct work {uint8_t *m;uint32_t bytes;uint16_t load,ss,sp,cs,zf;td2ega_state_registers r;const td2ega_indexed_sample_limits *limits;td2ega_indexed_sample_result *o;} work;
static uint32_t address(uint16_t s,uint16_t o){return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(work *w,uint16_t s,uint16_t o){uint32_t a=address(s,o);return (uint16_t)(w->m[a]|((uint16_t)w->m[(a+1)&UINT32_C(0xfffff)]<<8));}
static uint16_t rd(work *w,uint16_t o){return word(w,w->r.registers.ds,o);}
static uint8_t byte(work *w,uint16_t o){return w->m[address(w->r.registers.ds,o)];}
static void push(work *w,uint16_t v){uint32_t a;w->sp=(uint16_t)(w->sp-2);a=address(w->ss,w->sp);w->m[a]=(uint8_t)v;w->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++w->o->bus_writes;}
static uint16_t pop(work *w){uint16_t v=word(w,w->ss,w->sp);w->sp=(uint16_t)(w->sp+2);return v;}
static void wb(work *w,uint16_t o,uint8_t v){w->m[address(w->r.registers.ds,o)]=v;++w->o->bus_writes;}
static int32_t sw(uint16_t v){return v<0x8000?v:(int32_t)v-65536;}
static int32_t sb(uint8_t v){return v<0x80?v:(int32_t)v-256;}
static void low(work *w,uint8_t v){w->r.registers.ax=(uint16_t)((w->r.registers.ax&0xff00)|v);}
static void cmp(work *w,uint16_t a,uint16_t b){w->r.carry=(uint16_t)(a<b);w->zf=(uint16_t)(a==b);}
static uint16_t add(work *w,uint16_t a,uint16_t b){uint32_t v=(uint32_t)a+b;w->r.carry=(uint16_t)(v>65535);w->zf=(uint16_t)((uint16_t)v==0);return (uint16_t)v;}
static uint16_t sub(work *w,uint16_t a,uint16_t b){uint16_t v=(uint16_t)(a-b);w->r.carry=(uint16_t)(a<b);w->zf=(uint16_t)(v==0);return v;}
static int guard(work *w)
{
    uint16_t expected=w->sp,center=w->r.registers.ax,radius=w->r.registers.bx,lower,upper,minimum,maximum,match,ret;
    w->o->next_segment=w->cs;w->o->next_ip=0x4d0e;if(w->o->guard_calls==w->limits->guard_calls){w->o->status=3;return 0;}++w->o->guard_calls;
    push(w,0x4d11);push(w,w->r.registers.cx);upper=(uint16_t)(center+radius);maximum=rd(w,0x3336);minimum=rd(w,0x3334);match=td2ega_signed_interval_overlap(center,radius,minimum,maximum,&lower);w->r.registers.ax=lower;w->r.registers.cx=upper;w->r.carry=match?0:(uint16_t)(sw(lower)>sw(maximum)?lower<maximum:upper<minimum);w->zf=match;if(match)w->r.registers.cx=0;w->r.registers.cx=pop(w);ret=pop(w);w->o->next_segment=w->cs;w->o->next_ip=ret;
    if(ret!=0x4d11 || w->sp!=expected){w->o->status=1;return 0;}return 1;
}
#define AX w.r.registers.ax
#define BX w.r.registers.bx
#define CX w.r.registers.cx
#define DI w.r.registers.di
#define BP w.r.bp
#define CF w.r.carry
void td2ega_indexed_sample(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,uint16_t sp,const td2ega_state_registers *in,const td2ega_indexed_sample_limits *limits,td2ega_indexed_sample_result *out)
{
    work w;uint8_t token,v;uint16_t old,site,ip,expected,force_state;int32_t product;td2ega_sample_adjust_result h;
    if(out==NULL)return;
    *out=(td2ega_indexed_sample_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || limits==NULL || sp<22 || sp>UINT16_C(0xffe0) || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1)return;
    w=(work){m,bytes,load,ss,sp,(uint16_t)(load+0x6c9),0,*in,limits,out};low(&w,byte(&w,0x533e));low(&w,(uint8_t)(AX&0x7f));CF=0;w.zf=(uint16_t)((uint8_t)AX==0);AX=(uint8_t)AX;BX=AX;low(&w,byte(&w,(uint16_t)(BX+0x368a)));token=(uint8_t)AX;CF=0;w.zf=(uint16_t)(token==0);if(token>=0x80)goto root;cmp(&w,token,80);
    if(token<80){DI=AX;BP=AX;DI=(uint16_t)(DI<<2);v=(uint8_t)(rd(&w,(uint16_t)(DI+0x1db4))!=0);cmp(&w,v,0);if(v!=0){DI=AX;DI=(uint16_t)(DI>>2);CX=byte(&w,(uint16_t)(DI+0x337c));CF=0;w.zf=1;goto coefficient;}}
    cmp(&w,token,30);if(token<30)goto root;old=rd(&w,0x940e);cmp(&w,old,0);if(old==0)goto root;w.r.registers.es=rd(&w,0x940e);low(&w,(uint8_t)(token-30));CX=(uint16_t)((CX&0xff00)|5);v=(uint8_t)AX;AX=(uint16_t)(((v%5)<<8)|(v/5));old=AX;AX=(uint16_t)(AX<<1);CF=(uint16_t)(old>>15);w.zf=(uint16_t)(AX==0);DI=AX;AX=word(&w,w.r.registers.es,DI);CF=0;w.zf=(uint16_t)(AX==0);if(AX==0)goto root;DI=AX;CX=word(&w,w.r.registers.es,DI);CF=(uint16_t)(CX&1);CX=(uint16_t)(CX>>1);w.zf=(uint16_t)(CX==0);
coefficient:
    low(&w,byte(&w,(uint16_t)(BX+0x370a)));BX=(uint16_t)((BX&0xff00)|50);product=sb((uint8_t)AX)*50;AX=(uint16_t)product;CF=0;w.zf=(uint16_t)(AX==0);if(sw(AX)<0)AX=sub(&w,AX,500);else AX=add(&w,AX,500);v=(uint8_t)(byte(&w,0x5491)&1);CF=0;w.zf=(uint16_t)(v==0);if(v!=0){CF=0;w.zf=(uint16_t)(AX==0);if(sw(AX)>=0)AX=add(&w,AX,400);else{v=byte(&w,0x37f6);cmp(&w,v,0);if(v!=0)AX=sub(&w,AX,400);}}BX=CX;if(!guard(&w))goto done;if(!w.zf)goto root;cmp(&w,BP,20);force_state=(uint16_t)(BP>=20);site=force_state?0x4d1d:0x4d14;ip=force_state?0x4d20:0x4d17;out->next_segment=w.cs;out->next_ip=site;if(out->sample_calls==limits->sample_calls){out->status=3;goto done;}++out->sample_calls;expected=w.sp;push(&w,ip);td2ega_sample_adjust(w.m,w.bytes,w.load,w.ss,w.sp,&w.r,&w.limits->child,&h);w.r=h.returned;w.sp=h.current_sp;out->child_calls=h.calls;out->control_calls=h.control_calls;out->bus_writes+=h.bus_writes;out->next_segment=h.next_segment;out->next_ip=h.next_ip;
    if(h.status!=0){out->status=h.status;goto done;}if(h.next_segment!=w.cs || h.next_ip!=ip || w.sp!=expected){out->status=1;goto done;}w.zf=h.zero_flag;if(force_state)wb(&w,0x5490,2);
root:
    out->status=0;out->next_ip=pop(&w);out->next_segment=w.cs;out->zero_flag=w.zf;out->flags_valid=1;
done:
    out->current_sp=w.sp;out->returned=w.r;
}
