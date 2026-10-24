#include "td2ega_sample_guards.h"
#include <stddef.h>
typedef struct work {uint8_t *m;uint32_t bytes;uint16_t load,ss,sp,cs,zf;td2ega_state_registers r;const td2ega_sample_guards_limits *limits;td2ega_sample_guards_result *o;} work;
static uint32_t address(uint16_t s,uint16_t o){return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(work *w,uint16_t s,uint16_t o){uint32_t a=address(s,o);return (uint16_t)(w->m[a]|((uint16_t)w->m[(a+1)&UINT32_C(0xfffff)]<<8));}
static uint16_t rd(work *w,uint16_t o){return word(w,w->r.registers.ds,o);}
static uint8_t byte(work *w,uint16_t o){return w->m[address(w->r.registers.ds,o)];}
static void push(work *w,uint16_t v){uint32_t a;w->sp=(uint16_t)(w->sp-2);a=address(w->ss,w->sp);w->m[a]=(uint8_t)v;w->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++w->o->bus_writes;}
static uint16_t pop(work *w){uint16_t v=word(w,w->ss,w->sp);w->sp=(uint16_t)(w->sp+2);return v;}
static int32_t sw(uint16_t v){return v<0x8000?v:(int32_t)v-65536;}
static int guard(work *w,uint16_t site,uint16_t expected_ip)
{
    uint16_t expected=w->sp,center=w->r.registers.ax,radius=w->r.registers.bx,lower,upper,minimum,maximum,match,ret;
    w->o->next_segment=w->cs;w->o->next_ip=site;
    if(w->o->guard_calls==w->limits->guard_calls){w->o->status=3;return 0;}++w->o->guard_calls;
    push(w,expected_ip);push(w,w->r.registers.cx);
    upper=(uint16_t)(center+radius);maximum=rd(w,0x3336);minimum=rd(w,0x3334);
    match=td2ega_signed_interval_overlap(center,radius,minimum,maximum,&lower);w->r.registers.ax=lower;w->r.registers.cx=upper;
    w->r.carry=match?0:(uint16_t)(sw(lower)>sw(maximum)?lower<maximum:upper<minimum);w->zf=match;
    if(match)w->r.registers.cx=0;
    w->r.registers.cx=pop(w);ret=pop(w);w->o->next_segment=w->cs;w->o->next_ip=ret;
    if(ret!=expected_ip || w->sp!=expected){w->o->status=1;return 0;}return 1;
}
void td2ega_sample_guards(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,uint16_t sp,uint16_t entry,const td2ega_state_registers *in,const td2ega_sample_guards_limits *limits,td2ega_sample_guards_result *out)
{
    work w;td2ega_sample_adjust_result h;
    if(out==NULL)return;
    *out=(td2ega_sample_guards_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || limits==NULL || entry>1 || sp<20 || sp>UINT16_C(0xffe0) || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1)return;
    w=(work){m,bytes,load,ss,sp,(uint16_t)(load+0x6c9),0,*in,limits,out};
    if(entry==1){w.r.registers.ax=200;w.r.carry=0;w.zf=(uint16_t)((w.r.registers.bx&2)==0);if(!w.zf){w.r.registers.ax=(uint16_t)(0-w.r.registers.ax);w.r.carry=1;w.zf=0;}w.r.registers.bx=7;
        if(!guard(&w,0x4a26,0x4a29))goto done;
        w.r.registers.ax=(uint16_t)((w.r.registers.ax&255)|0x6f00);if(!w.zf)goto root;
    }else{w.r.registers.ax=0xfe70;w.r.registers.bx=5;w.r.carry=0;w.zf=(uint16_t)((byte(&w,0x5491)&1)==0);if(!w.zf){w.r.carry=0;w.zf=(uint16_t)(byte(&w,0x37f6)==0);if(!w.zf)w.r.registers.ax=0xfce0;}
        if(!guard(&w,0x49fe,0x4a01))goto done;
        if(w.zf)goto tail;
        w.r.registers.ax=400;w.r.carry=0;w.zf=(uint16_t)((byte(&w,0x5491)&1)==0);if(!w.zf)w.r.registers.ax=800;
        if(!guard(&w,0x4a10,0x4a13))goto done;
        if(!w.zf)goto root;
    }
tail:
    td2ega_sample_adjust(w.m,w.bytes,w.load,w.ss,w.sp,&w.r,&w.limits->sample,&h);out->status=h.status;out->next_segment=h.next_segment;out->next_ip=h.next_ip;out->sample_calls=h.calls;out->control_calls=h.control_calls;out->bus_writes+=h.bus_writes;out->zero_flag=h.zero_flag;out->flags_valid=h.flags_valid;w.sp=h.current_sp;w.r=h.returned;goto done;
root:
    out->status=0;out->next_ip=pop(&w);out->next_segment=w.cs;out->zero_flag=w.zf;out->flags_valid=1;
done:
    out->current_sp=w.sp;out->returned=w.r;
}
