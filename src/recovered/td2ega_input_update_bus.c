#include "td2ega_input_update_bus.h"
#include <stddef.h>

typedef struct work {
    uint8_t *m;uint32_t bytes;uint16_t load,ss,sp,cs,zf,af;
    td2ega_state_registers r;td2ega_input_flags f;
    const td2ega_input_poll_bus_limits *limits;
    const td2ega_input_poll_bus_services *services;
    td2ega_input_update_bus_result *out;
} work;
static uint32_t address(uint16_t s,uint16_t o){return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(work *w,uint16_t s,uint16_t o){uint32_t a=address(s,o);return (uint16_t)(w->m[a]|((uint16_t)w->m[(a+1)&UINT32_C(0xfffff)]<<8));}
static uint16_t rd(work *w,uint16_t o){return word(w,w->r.registers.ds,o);}
static uint8_t byte(work *w,uint16_t o){return w->m[address(w->r.registers.ds,o)];}
static void put(work *w,uint16_t s,uint16_t o,uint16_t v){uint32_t a=address(s,o);w->m[a]=(uint8_t)v;w->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++w->out->bus_writes;}
static void wr(work *w,uint16_t o,uint16_t v){put(w,w->r.registers.ds,o,v);}
static void wb(work *w,uint16_t o,uint8_t v){w->m[address(w->r.registers.ds,o)]=v;++w->out->bus_writes;}
static void push(work *w,uint16_t v){w->sp=(uint16_t)(w->sp-2);put(w,w->ss,w->sp,v);}
static uint16_t pop(work *w){uint16_t v=word(w,w->ss,w->sp);w->sp=(uint16_t)(w->sp+2);return v;}
static void flags(work *w,td2ega_input_flags f){w->f=f;w->r.carry=(uint16_t)(f.word&1);w->zf=(uint16_t)((f.word>>6)&1);}
static void cmp(work *w,uint16_t a,uint16_t b,unsigned width){flags(w,td2ega_input_flag_sub(w->f,a,b,width));}
static void logic(work *w,uint16_t v){flags(w,td2ega_input_flag_logic(w->f,v,16,w->af));}
static void partial(work *w,uint16_t zero,int zero_valid)
{
    w->zf=zero;w->f.word=(uint16_t)((w->f.word&~0x641)|w->r.carry|(zero<<6)|(w->r.registers.interrupts_enabled<<9)|(w->r.registers.direction<<10));
    w->f.mask=(uint16_t)((w->f.mask&~TD2EGA_INPUT_ARITH_FLAGS)|1|(zero_valid?0x40:0));
}
static int begin(work *w,uint16_t site,uint16_t size,int far)
{
    if(w->out->calls==w->limits->calls){w->out->status=3;w->out->next_segment=w->cs;w->out->next_ip=site;return 0;}
    ++w->out->calls;if(far)push(w,w->cs);push(w,(uint16_t)(site+size));return 1;
}
static int finish(work *w,uint16_t status,uint16_t sp,uint16_t cs,uint16_t ip,uint16_t expected_sp,uint16_t expected_ip)
{
    w->sp=sp;w->out->next_segment=cs;w->out->next_ip=ip;
    if(status!=0){w->out->status=status;return 0;}
    if(sp!=expected_sp || cs!=w->cs || ip!=expected_ip){w->out->status=1;return 0;}
    return 1;
}
static int input(work *w,uint16_t site,uint16_t entry)
{
    td2ega_input_poll_bus_result r;td2ega_input_poll_bus_limits limits;uint16_t expected=w->sp;
    if(!begin(w,site,5,1))return 0;
    limits=(td2ega_input_poll_bus_limits){w->limits->calls-w->out->calls,w->limits->bios_calls-w->out->bios_calls,w->limits->callback_calls-w->out->callback_calls,w->limits->port_reads-w->out->port_reads};
    td2ega_input_poll_bus(w->m,w->bytes,w->load,w->ss,w->sp,entry,w->f.word,w->f.mask,&w->r,&limits,w->services,&r);
    w->out->calls+=r.calls;w->out->bios_calls+=r.bios_calls;w->out->callback_calls+=r.callback_calls;w->out->port_reads+=r.port_reads;w->out->port_transfers+=r.port_transfers;w->out->bus_writes+=r.bus_writes;w->r=r.returned;w->zf=r.zero_flag;w->f=(td2ega_input_flags){r.flags_word,r.flags_mask};
    return finish(w,r.status,r.current_sp,r.next_segment,r.next_ip,expected,(uint16_t)(site+5));
}
static int fields(work *w,uint16_t site,uint16_t entry,uint16_t prepared)
{
    td2ega_input_fields_bus_result r;uint16_t expected=w->sp;
    if(!begin(w,site,3,0))return 0;
    td2ega_input_fields_bus(w->m,w->bytes,w->load,w->ss,w->sp,entry,prepared,&w->r,w->limits->calls-w->out->calls,&r);
    w->out->calls+=r.calls;w->out->bus_writes+=r.bus_writes;w->r=r.returned;partial(w,r.zero_flag,r.flags_valid);
    return finish(w,r.status,r.current_sp,r.next_segment,r.next_ip,expected,(uint16_t)(site+3));
}
static int translate(work *w)
{
    td2ega_gameport_bus_result r;uint16_t expected=w->sp;
    if(!begin(w,0x421a,5,1))return 0;
    td2ega_gameport_bus(w->m,w->bytes,w->load,w->ss,w->sp,2,w->zf,&w->r,0,NULL,NULL,&r);
    w->out->bus_writes+=r.bus_writes;w->r=r.returned;partial(w,r.zero_flag,r.flags_valid);
    return finish(w,r.status,r.current_sp,r.next_segment,r.next_ip,expected,0x421f);
}
static int motion(work *w)
{
    td2ega_motion_flags_bus_result r;uint16_t expected=w->sp,f;
    if(!begin(w,0x4261,5,1))return 0;
    /* InitialmotionSUBSP4 definesallarithbits beforeanyread/FLAGSstorage.
     * Unexposedincomingarithbits thereforehave no observableconsumer here. */
    f=(uint16_t)(2|w->r.carry|(w->r.registers.interrupts_enabled<<9)|(w->r.registers.direction<<10));
    td2ega_motion_flags_bus(w->m,w->bytes,w->load,w->ss,w->sp,f,0xffff,&w->r,w->limits->calls-w->out->calls,&r);
    w->out->calls+=r.calls;w->out->bus_writes+=r.bus_writes;w->r=r.returned;w->zf=r.zero_flag;w->f=(td2ega_input_flags){r.flags_word,r.flags_mask};
    return finish(w,r.status,r.current_sp,r.next_segment,r.next_ip,expected,0x4266);
}
static int scan(work *w)
{
    td2ega_motion_scan_bus_result r;uint16_t expected=w->sp,status;
    if(!begin(w,0x427d,3,0))return 0;
    td2ega_motion_scan_bus(w->m,w->bytes,w->load,w->ss,w->sp,2,&w->r,0,&r);
    w->out->bus_writes+=r.bus_writes;w->r=r.returned;partial(w,r.zero_flag,r.flags_valid);w->out->unresolved_target=r.unresolved_target;status=(uint16_t)(r.status==4?6:r.status);
    return finish(w,status,r.current_sp,r.next_segment,r.next_ip,expected,0x4280);
}
void td2ega_input_update_bus(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,uint16_t sp,uint16_t raw_flags,uint16_t mask,const td2ega_state_registers *in,const td2ega_mutable_control *state,const td2ega_input_poll_bus_limits *limits,const td2ega_input_poll_bus_services *services,td2ega_input_update_bus_result *out)
{
    work w;uint16_t v,old;uint8_t b;
    if(out==NULL)return;*out=(td2ega_input_update_bus_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || state==NULL || limits==NULL || services==NULL || sp<24 || sp>UINT16_C(0xffe0) || services->undefined_af>1 || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1 || (raw_flags&~UINT16_C(0x0ed7))!=0 || (raw_flags&2)==0 || (mask!=UINT16_C(0xffff) && mask!=UINT16_C(0xffef)) || in->carry!=(raw_flags&1) || in->registers.interrupts_enabled!=((raw_flags>>9)&1) || in->registers.direction!=((raw_flags>>10)&1) || (state->branch_424a!=0 && state->branch_424a!=2) || (state->branch_4275!=0 && state->branch_4275!=2) || (state->branch_42ad!=1 && state->branch_42ad!=2))return;
    w=(work){m,bytes,load,ss,sp,(uint16_t)(load+0x6c9),(uint16_t)((raw_flags>>6)&1),services->undefined_af,*in,{raw_flags,mask},limits,services,out};
    b=byte(&w,0x33d4);cmp(&w,b,0,8);if(b!=0)goto consume;
    out->stage=1;if(!input(&w,0x4211,2))goto done;wb(&w,0x33b1,(uint8_t)w.r.registers.ax);push(&w,w.r.registers.ax);
    if(!translate(&w))goto done;w.r.registers.bx=pop(&w);w.r.registers.bx&=0x30;logic(&w,w.r.registers.bx);b=byte(&w,0x90a8);cmp(&w,b,0,8);if(b==0){w.r.registers.ax|=w.r.registers.bx;logic(&w,w.r.registers.ax);}
    wb(&w,0x33b0,(uint8_t)w.r.registers.ax);old=rd(&w,0x3352);v=(uint16_t)(old+1);wr(&w,0x3352,v);cmp(&w,rd(&w,0x3352),0x960,16);if(v>0x960)goto idle;
    logic(&w,w.r.registers.ax);if(w.r.registers.ax==0)goto control;wr(&w,0x3352,0);v=rd(&w,0x8a9a);cmp(&w,v,1,16);if(state->branch_424a==2?v!=1:v<=1)goto control;
idle:
    wb(&w,0x5490,0xff);
control:
    if(!fields(&w,0x4251,0,(uint16_t)(state->branch_42ad==2)))goto done;b=byte(&w,0x3365);cmp(&w,b,0,8);if(b!=0 && !fields(&w,0x425b,1,0))goto done;
    if(!fields(&w,0x425e,3,0) || !motion(&w))goto done;
consume:
    out->stage=2;if(!input(&w,0x4266,1))goto done;logic(&w,w.r.registers.ax);push(&w,w.r.registers.ax);if(w.r.registers.ax==0)goto dispatch;v=rd(&w,0x8a9a);cmp(&w,v,1,16);if(state->branch_4275==2?v!=1:v<=1)goto dispatch;wb(&w,0x5490,0xff);
dispatch:
    w.r.registers.ax=pop(&w);out->stage=3;if(!scan(&w))goto done;out->next_ip=pop(&w);out->next_segment=w.cs;out->status=0;out->zero_flag=w.zf;out->flags_valid=1;
done:
    out->current_sp=w.sp;out->returned=w.r;out->flags_word=w.f.word;out->flags_mask=w.f.mask;
}
