#include "td2ega_window_controllers.h"
#include <stddef.h>
typedef struct work {uint8_t *m;uint32_t bytes;uint16_t load,ss,sp,cs,zf;td2ega_state_registers r;const td2ega_window_controllers_limits *limits;td2ega_window_controllers_result *o;} work;
static uint32_t address(uint16_t s,uint16_t o){return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(work *w,uint16_t s,uint16_t o){uint32_t a=address(s,o);return (uint16_t)(w->m[a]|((uint16_t)w->m[(a+1)&UINT32_C(0xfffff)]<<8));}
static uint16_t rd(work *w,uint16_t o){return word(w,w->r.registers.ds,o);}
static uint8_t byte(work *w,uint16_t o){return w->m[address(w->r.registers.ds,o)];}
static void put(work *w,uint16_t s,uint16_t o,uint16_t v){uint32_t a=address(s,o);w->m[a]=(uint8_t)v;w->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++w->o->bus_writes;}
static void wr(work *w,uint16_t o,uint16_t v){put(w,w->r.registers.ds,o,v);}
static void wb(work *w,uint16_t o,uint8_t v){w->m[address(w->r.registers.ds,o)]=v;++w->o->bus_writes;}
static void push(work *w,uint16_t v){w->sp=(uint16_t)(w->sp-2);put(w,w->ss,w->sp,v);}
static uint16_t pop(work *w){uint16_t v=word(w,w->ss,w->sp);w->sp=(uint16_t)(w->sp+2);return v;}
static int32_t sw(uint16_t v){return v<0x8000?v:(int32_t)v-65536;}
static int32_t sb(uint8_t v){return v<0x80?v:(int32_t)v-256;}
static uint16_t add(work *w,uint16_t a,uint16_t b){uint32_t v=(uint32_t)a+b;w->r.carry=(uint16_t)(v>65535);w->zf=(uint16_t)((uint16_t)v==0);return (uint16_t)v;}
static uint16_t sub(work *w,uint16_t a,uint16_t b){uint16_t v=(uint16_t)(a-b);w->r.carry=(uint16_t)(a<b);w->zf=(uint16_t)(v==0);return v;}
static void cmp(work *w,uint16_t a,uint16_t b){w->r.carry=(uint16_t)(a<b);w->zf=(uint16_t)(a==b);}
static int guard(work *w,uint16_t site,uint16_t expected_ip)
{
    uint16_t expected=w->sp,center=w->r.registers.ax,radius=w->r.registers.bx,lower,upper,minimum,maximum,match,ret;
    w->o->next_segment=w->cs;w->o->next_ip=site;
    if(w->o->guard_calls==w->limits->guard_calls){w->o->status=3;return 0;}++w->o->guard_calls;
    push(w,expected_ip);push(w,w->r.registers.cx);upper=(uint16_t)(center+radius);maximum=rd(w,0x3336);minimum=rd(w,0x3334);match=td2ega_signed_interval_overlap(center,radius,minimum,maximum,&lower);w->r.registers.ax=lower;w->r.registers.cx=upper;w->r.carry=match?0:(uint16_t)(sw(lower)>sw(maximum)?lower<maximum:upper<minimum);w->zf=match;if(match)w->r.registers.cx=0;w->r.registers.cx=pop(w);ret=pop(w);w->o->next_segment=w->cs;w->o->next_ip=ret;
    if(ret!=expected_ip || w->sp!=expected){w->o->status=1;return 0;}return 1;
}
#define AX w.r.registers.ax
#define BX w.r.registers.bx
#define CX w.r.registers.cx
#define CF w.r.carry
void td2ega_window_controllers(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,uint16_t sp,uint16_t entry,const td2ega_state_registers *in,const td2ega_window_controllers_limits *limits,td2ega_window_controllers_result *out)
{
    work w;uint8_t cl,v;uint16_t expected;td2ega_sample_adjust_result h;
    if(out==NULL)return;
    *out=(td2ega_window_controllers_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || limits==NULL || entry>1 || (entry==0?sp==UINT16_C(0xffff):sp<22 || sp>UINT16_C(0xffe0)) || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1)return;
    w=(work){m,bytes,load,ss,sp,(uint16_t)(load+0x6c9),0,*in,limits,out};
    if(entry==0){AX=rd(&w,0x52cc);AX=add(&w,AX,40);wr(&w,0x3332,AX);BX=AX;BX=sub(&w,BX,90);wr(&w,0x3334,BX);BX=add(&w,BX,180);wr(&w,0x3336,BX);cl=byte(&w,0x3371);CX=(uint16_t)((CX&0xff00)|cl);cmp(&w,cl,1);
        if(sb(cl)<1)goto root;
        if(sb(cl)==1){v=byte(&w,0x33d5);cmp(&w,v,0);if(v!=0){v=byte(&w,0x52cf);cmp(&w,v,5);if(v<=5)wb(&w,0x5490,1);goto root;}cmp(&w,AX,600);if(sw(AX)>=600)wr(&w,0x52cc,560);}
        v=byte(&w,0x52cf);cmp(&w,v,5);if(v>5)goto root;cmp(&w,cl,2);if(cl==2){wb(&w,0x5490,4);goto root;}cmp(&w,AX,100);wb(&w,0x5490,(uint8_t)(sw(AX)<100?9:1));goto root;
    }
    v=(uint8_t)(byte(&w,0x533e)-1);AX=(uint16_t)((AX&0xff00)|v);w.zf=(uint16_t)(v==0);CF=0;w.zf=(uint16_t)((v&15)==0);if(!w.zf)goto root;AX=0xfe0c;BX=5;CF=0;w.zf=(uint16_t)((byte(&w,0x5491)&1)==0);if(!w.zf){v=byte(&w,0x37f6);cmp(&w,v,0);if(v!=0)AX=0xfc7c;}
    if(!guard(&w,0x4b7e,0x4b81))goto done;
    if(!w.zf){AX=500;CF=0;w.zf=(uint16_t)((byte(&w,0x5491)&1)==0);if(!w.zf)AX=900;if(!guard(&w,0x4b90,0x4b93))goto done;if(!w.zf)goto root;}
    out->next_segment=w.cs;out->next_ip=0x4b96;if(out->sample_calls==limits->sample_calls){out->status=3;goto done;}++out->sample_calls;expected=w.sp;push(&w,0x4b99);td2ega_sample_adjust(w.m,w.bytes,w.load,w.ss,w.sp,&w.r,&w.limits->child,&h);w.r=h.returned;w.sp=h.current_sp;out->child_calls=h.calls;out->control_calls=h.control_calls;out->bus_writes+=h.bus_writes;out->next_segment=h.next_segment;out->next_ip=h.next_ip;
    if(h.status!=0){out->status=h.status;goto done;}if(h.next_segment!=w.cs || h.next_ip!=0x4b99 || w.sp!=expected){out->status=1;goto done;}w.zf=h.zero_flag;
root:
    out->status=0;out->next_ip=pop(&w);out->next_segment=w.cs;out->zero_flag=w.zf;out->flags_valid=1;
done:
    out->current_sp=w.sp;out->returned=w.r;
}
