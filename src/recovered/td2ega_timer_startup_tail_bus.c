#include "td2ega_timer_startup_tail_bus.h"
#include <stddef.h>
typedef struct work {
    uint8_t *m;uint32_t bytes;uint16_t load,cs,ss,sp;
    td2ega_state_registers r;td2ega_input_flags f;
    const td2ega_timer_startup_tail_limits *caps;
    td2ega_music_port_service port;void *context;
    td2ega_timer_startup_tail_result *out;
} work;
static uint32_t address(uint16_t s,uint16_t o){return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(work *w,uint16_t o)
{uint32_t a=address(w->ss,o);return (uint16_t)(w->m[a]|((uint16_t)w->m[(a+1)&UINT32_C(0xfffff)]<<8));}
static void push(work *w,uint16_t v)
{uint32_t a;w->sp=(uint16_t)(w->sp-2);a=address(w->ss,w->sp);w->m[a]=(uint8_t)v;w->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++w->out->bus_writes;}
static uint16_t pop(work *w){uint16_t v=word(w,w->sp);w->sp=(uint16_t)(w->sp+2);return v;}
static int call(work *w,uint16_t site,uint16_t ret,uint16_t stage)
{
    if(w->out->calls==w->caps->calls){w->out->status=3;w->out->next_segment=w->cs;w->out->next_ip=site;w->out->halt_site=site;return 0;}
    ++w->out->calls;w->out->stage=stage;push(w,w->cs);push(w,ret);return 1;
}
static int retired(work *w,uint16_t status,uint16_t sp,uint16_t segment,uint16_t ip,uint16_t expected_ip,uint16_t expected_sp,uint16_t halt)
{
    w->sp=sp;w->out->halt_site=halt;
    if(status || segment!=w->cs || ip!=expected_ip || sp!=expected_sp){w->out->status=status?status:1;w->out->next_segment=segment;w->out->next_ip=ip;return 0;}
    w->out->stage=0;return 1;
}
static void cleanup(work *w)
{w->f=td2ega_input_flag_add16(w->f,w->sp,4);w->sp=(uint16_t)(w->sp+4);w->r.carry=(uint16_t)(w->f.word&1);w->r.registers.interrupts_enabled=(uint16_t)((w->f.word>>9)&1);w->r.registers.direction=(uint16_t)((w->f.word>>10)&1);}
void td2ega_timer_startup_tail_bus(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,uint16_t sp,uint16_t flags,uint16_t mask,const td2ega_state_registers *in,const td2ega_timer_startup_tail_limits *caps,td2ega_music_port_service port,void *context,td2ega_timer_startup_tail_result *out)
{
    work w;td2ega_timer_control_bus_result t;td2ega_timer_callback_bus_result c;uint16_t before,site,ret,stage;
    if(out==NULL)return;*out=(td2ega_timer_startup_tail_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || caps==NULL || port==NULL || sp<10 || sp>0xffe0 || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1 || (flags&~UINT16_C(0x0ed7)) || !(flags&2) || (mask!=0xffff && mask!=0xffef && mask!=0xf72b && mask!=0xf72a) || (flags&1)!=in->carry || ((flags>>9)&1)!=in->registers.interrupts_enabled || ((flags>>10)&1)!=in->registers.direction)return;
    w=(work){m,bytes,load,(uint16_t)(load+0x6c9),ss,sp,*in,{flags,mask},caps,port,context,out};
    before=w.sp;if(!call(&w,0x3fd9,0x3fde,1))goto done;
    td2ega_timer_control_bus(m,bytes,load,ss,w.sp,0,w.f.word,w.f.mask,&w.r,port,context,caps->timer_steps,caps->timer_ports,&t);
    w.r=t.returned;w.f=(td2ega_input_flags){t.flags_word,t.flags_mask};out->ports+=t.ports;out->bus_writes+=t.bus_writes;
    if(!retired(&w,t.status,t.current_sp,t.next_segment,t.next_ip,0x3fde,before,t.halt_site))goto done;
    for(stage=2;stage<=3;++stage){
        w.r.registers.ax=(uint16_t)(stage==2?0x6269:0x403b);push(&w,w.cs);push(&w,w.r.registers.ax);before=w.sp;site=(uint16_t)(stage==2?0x3fe3:0x3ff0);ret=(uint16_t)(stage==2?0x3fe8:0x3ff5);
        if(!call(&w,site,ret,stage))goto done;
        td2ega_timer_callback_bus(m,bytes,load,ss,w.sp,0,w.f.word,w.f.mask,&w.r,caps->callback_steps,&c);
        w.r=c.returned;w.f=(td2ega_input_flags){c.flags_word,c.flags_mask};out->bus_writes+=c.bus_writes;out->call_segment=c.call_segment;out->call_offset=c.call_offset;
        if(!retired(&w,c.status,c.current_sp,c.next_segment,c.next_ip,ret,before,c.halt_site))goto done;
        cleanup(&w);
    }
    out->halt_site=0x3ff8;out->next_ip=pop(&w);out->next_segment=pop(&w);out->status=0;
done:
    out->current_sp=w.sp;out->returned=w.r;out->flags_word=w.f.word;out->flags_mask=w.f.mask;
}
