#include "td2ega_runtime_report_bus.h"
#include <stddef.h>
typedef struct work {
    uint8_t *m;uint32_t bytes;uint16_t load,cs,parent,ss,sp;
    td2ega_state_registers r;td2ega_input_flags f;
    const td2ega_runtime_report_limits *caps;
    const td2ega_runtime_report_services *services;
    td2ega_runtime_report_result *out;
} work;
static uint32_t address(uint16_t s,uint16_t o){return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(work *w,uint16_t s,uint16_t o)
{uint32_t a=address(s,o);return (uint16_t)(w->m[a]|((uint16_t)w->m[(a+1)&UINT32_C(0xfffff)]<<8));}
static void put(work *w,uint16_t s,uint16_t o,uint16_t v,unsigned width)
{uint32_t a=address(s,o);w->m[a]=(uint8_t)v;if(width==2)w->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++w->out->bus_writes;}
static void push(work *w,uint16_t v){w->sp=(uint16_t)(w->sp-2);put(w,w->ss,w->sp,v,2);}
static uint16_t pop(work *w){uint16_t v=word(w,w->ss,w->sp);w->sp=(uint16_t)(w->sp+2);return v;}
static int valid(const td2ega_state_registers *r,uint16_t flags,uint16_t mask)
{return r->carry<=1 && r->registers.interrupts_enabled<=1 && r->registers.direction<=1 && !(flags&~UINT16_C(0x0ed7)) && (flags&2) && (mask==0xffff || mask==0xffef || mask==0xf72b || mask==0xf72a) && (flags&1)==r->carry && ((flags>>9)&1)==r->registers.interrupts_enabled && ((flags>>10)&1)==r->registers.direction;}
static void sync(work *w)
{w->r.carry=(uint16_t)(w->f.word&1);w->r.registers.interrupts_enabled=(uint16_t)((w->f.word>>9)&1);w->r.registers.direction=(uint16_t)((w->f.word>>10)&1);}
static void partial(work *w)
{w->f=(td2ega_input_flags){(uint16_t)(2|w->r.carry|(w->r.registers.interrupts_enabled<<9)|(w->r.registers.direction<<10)),0xf72b};}
static void logic(work *w,uint16_t value,unsigned width){w->f=td2ega_input_flag_logic(w->f,value,width,0);sync(w);}
static uint16_t add(work *w,uint16_t a,uint16_t b){w->f=td2ega_input_flag_add16(w->f,a,b);sync(w);return (uint16_t)(a+b);}
static int stop(work *w,uint16_t status,uint16_t site)
{w->out->status=status;w->out->halt_site=site;w->out->next_segment=w->cs;w->out->next_ip=site;return 0;}
static int step(work *w,uint16_t site){if(w->out->steps==w->caps->steps)return stop(w,3,site);++w->out->steps;return 1;}
static int call(work *w,uint16_t site,uint16_t ret,uint16_t stage)
{if(w->out->calls==w->caps->calls)return stop(w,3,site);++w->out->calls;push(w,w->parent);push(w,ret);w->out->stage=stage;return 1;}
static int continuation(work *w,uint16_t ip,uint16_t sp)
{if(w->out->next_segment!=w->parent || w->out->next_ip!=ip || w->sp!=sp){w->out->status=1;return 0;}w->cs=w->parent;w->out->stage=0;return 1;}
static int port(work *w,uint16_t site,uint16_t operation)
{
    td2ega_music_port_request q;uint8_t value=0;
    if(w->out->ports==w->caps->keyboard_ports)return stop(w,3,site);++w->out->ports;
    q=(td2ega_music_port_request){operation,0x21,(uint8_t)w->r.registers.ax,w->r.registers.interrupts_enabled};
    if(w->services->port==NULL || !w->services->port(w->services->context,&q,&value))return stop(w,4,site);
    if(!operation)w->r.registers.ax=(uint16_t)((w->r.registers.ax&0xff00)|value);return 1;
}
static int keyboard(work *w)
{
    uint16_t value;
    if(!step(w,0x68c4))return 0;if(!port(w,0x68c4,0))return 0;
    value=(uint8_t)w->r.registers.ax;w->r.registers.ax=(uint16_t)((value<<8)|(value|3));logic(w,(uint8_t)w->r.registers.ax,8);if(!port(w,0x68ca,1))return 0;
    w->r.registers.bx=0;logic(w,0,16);w->r.registers.es=0;w->r.registers.bx=word(w,w->r.registers.ds,0x62ae);logic(w,w->r.registers.bx,16);
    if(w->r.registers.bx){
        put(w,w->r.registers.es,0x24,w->r.registers.bx,2);w->r.registers.bx=word(w,w->r.registers.ds,0x62b0);put(w,w->r.registers.es,0x26,w->r.registers.bx,2);w->r.registers.bx=word(w,w->r.registers.ds,0x62b2);put(w,w->r.registers.es,0x58,w->r.registers.bx,2);w->r.registers.bx=word(w,w->r.registers.ds,0x62b4);put(w,w->r.registers.es,0x5a,w->r.registers.bx,2);
        value=w->m[address(w->r.registers.es,0x417)];w->r.registers.ax=(uint16_t)((w->r.registers.ax&0xff00)|(value&0xf0));logic(w,(uint8_t)w->r.registers.ax,8);put(w,w->r.registers.es,0x417,(uint8_t)w->r.registers.ax,1);
    }
    w->r.registers.ax=(uint16_t)((w->r.registers.ax&0xff00)|(w->r.registers.ax>>8));if(!port(w,0x6904,1))return 0;w->out->halt_site=0x6906;
    if(w->sp>0xfffc)return stop(w,7,0x6906);w->out->next_ip=pop(w);w->out->next_segment=pop(w);w->out->status=0;return 1;
}
static int formatter(work *w)
{
    td2ega_runtime_dispatch_request q;td2ega_runtime_dispatch_response r;
    q=(td2ega_runtime_dispatch_request){2,0x23,(uint16_t)(w->load+0x13a8),0xb00,w->ss,w->sp,w->f.word,w->f.mask,w->r};r=(td2ega_runtime_dispatch_response){0};
    if(w->services->formatter==NULL || !w->services->formatter(w->services->context,w->m,w->bytes,&q,&r) || r.status>7 || r.status==2 || r.status==6 || !valid(&r.returned,r.flags_word,r.flags_mask)){
        w->out->status=4;w->out->next_segment=q.target_segment;w->out->next_ip=q.target_ip;w->out->halt_site=0x23;return 0;
    }
    ++w->out->callbacks;w->out->bus_writes+=r.bus_writes;w->r=r.returned;w->f=(td2ega_input_flags){r.flags_word,r.flags_mask};w->sp=r.current_sp;w->out->next_segment=r.next_segment;w->out->next_ip=r.next_ip;w->out->halt_site=0x23;
    if(r.status){w->out->status=r.status;w->out->exit_request=r.exit_request;return 0;}return 1;
}
static void report(work *w)
{
    td2ega_video_reset_result video;td2ega_timer_control_bus_result timer;td2ega_runtime_dispatch_result runtime;uint16_t before,offset,site,value;
    if(!step(w,2))return;push(w,w->r.bp);w->r.bp=w->sp;before=w->sp;if(!call(w,5,0xa,1))return;
    td2ega_video_reset(w->m,w->bytes,w->load,w->ss,w->sp,&w->r,w->services->bios,w->services->context,w->services->device,w->services->context,w->caps->video_calls,w->caps->video_events,&video);
    w->r=video.returned;w->sp=video.current_sp;partial(w);w->out->services+=video.services;w->out->device_events+=video.events;w->out->device_bytes+=video.bytes;w->out->bus_writes+=video.bus_writes;w->out->next_segment=video.next_segment;w->out->next_ip=video.next_ip;w->out->halt_site=video.next_ip;
    if(video.status){w->out->status=(uint16_t)(video.status==5?7:video.status);return;}if(!continuation(w,0xa,before))return;
    before=w->sp;if(!call(w,0xa,0xf,2))return;w->cs=(uint16_t)(w->load+0x6c9);if(!keyboard(w) || !continuation(w,0xf,before))return;
    before=w->sp;if(!call(w,0xf,0x14,3))return;
    td2ega_timer_control_bus(w->m,w->bytes,w->load,w->ss,w->sp,2,w->f.word,w->f.mask,&w->r,w->services->port,w->services->context,w->caps->timer_steps,w->caps->timer_ports,&timer);
    w->r=timer.returned;w->sp=timer.current_sp;w->f=(td2ega_input_flags){timer.flags_word,timer.flags_mask};w->out->ports+=timer.ports;w->out->bus_writes+=timer.bus_writes;w->out->next_segment=timer.next_segment;w->out->next_ip=timer.next_ip;w->out->halt_site=timer.halt_site;
    if(timer.status){w->out->status=(uint16_t)(timer.status==5?7:timer.status);return;}if(!continuation(w,0x14,before))return;
    for(offset=0xe;offset>=6;offset=(uint16_t)(offset-2)){site=(uint16_t)(0x14+3*((0xe-offset)/2));if(!step(w,site))return;value=word(w,w->ss,(uint16_t)(w->r.bp+offset));push(w,value);}
    before=w->sp;if(!call(w,0x23,0x28,4))return;if(!formatter(w) || !continuation(w,0x28,before))return;w->sp=add(w,w->sp,10);
    if(!call(w,0x2b,0x30,5))return;
    td2ega_runtime_dispatch_bus(w->m,w->bytes,w->load,w->ss,w->sp,2,w->f.word,w->f.mask,&w->r,&w->caps->runtime,&w->services->runtime,&runtime);
    w->r=runtime.returned;w->sp=runtime.current_sp;w->f=(td2ega_input_flags){runtime.flags_word,runtime.flags_mask};w->out->services+=runtime.services;w->out->callbacks+=runtime.callbacks;w->out->bus_writes+=runtime.bus_writes;w->out->status=runtime.status;w->out->next_segment=runtime.next_segment;w->out->next_ip=runtime.next_ip;w->out->halt_site=runtime.halt_site;w->out->raw_target=runtime.raw_target;w->out->raw_segment=runtime.raw_segment;w->out->exit_request=runtime.exit_request;
}
void td2ega_runtime_report_bus(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,uint16_t sp,uint16_t entry,uint16_t flags,uint16_t mask,const td2ega_state_registers *in,const td2ega_runtime_report_limits *caps,const td2ega_runtime_report_services *services,td2ega_runtime_report_result *out)
{
    work w;
    if(out==NULL)return;*out=(td2ega_runtime_report_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || caps==NULL || services==NULL || entry>1 || (entry==0 && (sp<106 || sp>0xffe0)) || !valid(in,flags,mask))return;
    w=(work){m,bytes,load,(uint16_t)(load+(entry?0x6c9:0x16a7)),(uint16_t)(load+0x16a7),ss,sp,*in,{flags,mask},caps,services,out};if(entry)keyboard(&w);else report(&w);
    out->current_sp=w.sp;out->returned=w.r;out->flags_word=w.f.word;out->flags_mask=w.f.mask;
}
