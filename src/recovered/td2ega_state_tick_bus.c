#include "td2ega_state_tick_bus.h"
#include <stddef.h>

typedef struct work {
    uint8_t *m;uint32_t bytes;uint16_t load,ss,sp,cs;
    td2ega_state_registers r;const td2ega_mutable_control *code;
    const td2ega_state_tick_bus_limits *limits;
    const td2ega_input_poll_bus_services *services;
    td2ega_state_tick_bus_result *out;
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
static void cmp(work *w,uint16_t a,uint16_t b){w->r.carry=(uint16_t)(a<b);}
static uint16_t sub(work *w,uint16_t a,uint16_t b){w->r.carry=(uint16_t)(a<b);return (uint16_t)(a-b);}
static int begin(work *w,uint16_t site,uint16_t *expected)
{
    w->out->stage=site;
    if(w->out->root_calls==w->limits->root_calls){w->out->status=3;w->out->next_segment=w->cs;w->out->next_ip=site;return 0;}
    ++w->out->root_calls;*expected=w->sp;push(w,(uint16_t)(site+3));return 1;
}
static int finish(work *w,uint16_t status,uint16_t sp,uint16_t cs,uint16_t ip,uint16_t expected,uint16_t site)
{
    w->sp=sp;w->out->next_segment=cs;w->out->next_ip=ip;
    if(status!=0){w->out->status=status;return 0;}
    if(sp!=expected || cs!=w->cs || ip!=(uint16_t)(site+3)){w->out->status=1;return 0;}
    return 1;
}
static int invoke(work *w,uint16_t site)
{
    uint16_t expected;const td2ega_state_tick_bus_limits *caps=w->limits;
    if(!begin(w,site,&expected))return 0;
    switch(site){
    case 0x4046:case 0x4104:{
        td2ega_sample_fields_bus_result r;
        td2ega_sample_fields_bus(w->m,w->bytes,w->load,w->ss,w->sp,(uint16_t)(site==0x4104),&w->r,&r);w->r=r.returned;w->out->bus_writes+=r.bus_writes;
        return finish(w,r.status,r.current_sp,r.next_segment,r.next_ip,expected,site);
    }
    case 0x40d9:{
        td2ega_input_update_bus_result r;uint16_t f=(uint16_t)(2|w->r.carry|(w->r.registers.interrupts_enabled<<9)|(w->r.registers.direction<<10));
        /* 420A firstCMP definesallarithflags beforeanyFLAGScapture. */
        td2ega_input_update_bus(w->m,w->bytes,w->load,w->ss,w->sp,f,0xffff,&w->r,w->code,&caps->input,w->services,&r);w->r=r.returned;w->out->bus_writes+=r.bus_writes;w->out->raw_target=r.unresolved_target;
        return finish(w,r.status,r.current_sp,r.next_segment,r.next_ip,expected,site);
    }
    case 0x40f0:{
        td2ega_field_controller_result r;
        td2ega_field_controller(w->m,w->bytes,w->load,w->ss,w->sp,&w->r,caps->math_calls,caps->math_iterations,&r);w->r=r.returned;w->out->bus_writes+=r.bus_writes;
        return finish(w,r.status,r.current_sp,r.next_segment,r.next_ip,expected,site);
    }
    case 0x40f3:case 0x4124:{
        td2ega_control_controllers_result r;
        td2ega_control_controllers(w->m,w->bytes,w->load,w->ss,w->sp,(uint16_t)(site==0x40f3),&w->r,caps->control_calls,caps->control_nested_calls,&r);w->r=r.returned;w->out->bus_writes+=r.bus_writes;
        return finish(w,r.status,r.current_sp,r.next_segment,r.next_ip,expected,site);
    }
    case 0x4107:{
        td2ega_sim_controller_result r;
        td2ega_sim_controller(w->m,w->bytes,w->load,w->ss,w->sp,&w->r,&caps->simulation,&r);w->r=r.returned;w->out->bus_writes+=r.bus_writes;w->out->raw_target=r.unresolved_target;
        return finish(w,r.status,r.current_sp,r.next_segment,r.next_ip,expected,site);
    }
    case 0x4111:{
        td2ega_secondary_fields_result r;
        td2ega_secondary_fields(w->m,w->bytes,w->load,w->ss,w->sp,&w->r,caps->math_calls,caps->math_iterations,&r);w->r=r.returned;w->out->bus_writes+=r.bus_writes;
        return finish(w,r.status,r.current_sp,r.next_segment,r.next_ip,expected,site);
    }
    case 0x4114:{
        td2ega_mode_controller_result r;
        td2ega_mode_controller(w->m,w->bytes,w->load,w->ss,w->sp,&w->r,caps->mode_calls,caps->mode_nested_calls,caps->mode_iterations,&r);w->r=r.returned;w->out->bus_writes+=r.bus_writes;w->out->raw_target=r.raw_target;w->out->mode_exit_kind=r.exit_kind;
        /* exit_kind1 alreadyPOPs/RETs to4117; checkitsactualcoordinates. */
        return finish(w,r.status,r.current_sp,r.next_segment,r.next_ip,expected,site);
    }
    case 0x4117:{
        td2ega_record_controller_result r;
        td2ega_record_controller(w->m,w->bytes,w->load,w->ss,w->sp,&w->r,w->services->undefined_af,caps->record_steps,caps->record_calls,&r);w->r=r.returned;w->out->bus_writes+=r.bus_writes;
        return finish(w,r.status,r.current_sp,r.next_segment,r.next_ip,expected,site);
    }
    case 0x411a:{
        td2ega_pair_controller_result r;
        td2ega_pair_controller(w->m,w->bytes,w->load,w->ss,w->sp,&w->r,caps->pair_calls,&r);w->r=r.returned;w->out->bus_writes+=r.bus_writes;
        return finish(w,r.status,r.current_sp,r.next_segment,r.next_ip,expected,site);
    }
    default:w->out->status=2;return 0;
    }
}
void td2ega_state_tick_bus(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,uint16_t sp,const td2ega_state_registers *in,const td2ega_mutable_control *code,const td2ega_state_tick_bus_limits *limits,const td2ega_input_poll_bus_services *services,td2ega_state_tick_bus_result *out)
{
    work w;uint16_t v;uint8_t b;
    if(out==NULL)return;*out=(td2ega_state_tick_bus_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || code==NULL || limits==NULL || services==NULL || sp<46 || sp>UINT16_C(0xffe0) || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1 || services->undefined_af>1 || (code->branch_424a!=0 && code->branch_424a!=2) || (code->branch_4275!=0 && code->branch_4275!=2) || (code->branch_42ad!=1 && code->branch_42ad!=2))return;
    w=(work){m,bytes,load,ss,sp,(uint16_t)(load+0x6c9),*in,code,limits,services,out};
    push(&w,w.r.registers.ds);push(&w,w.r.registers.es);push(&w,w.r.registers.di);push(&w,w.r.bp);w.r.registers.ax=(uint16_t)(load+0x178f);w.r.registers.ds=w.r.registers.ax;w.r.registers.es=w.r.registers.ax;
    if(!invoke(&w,0x4046))goto done;b=(uint8_t)(byte(&w,0x3368)-1);wb(&w,0x3368,b);if(b!=0)goto epilogue;
    w.r.registers.direction=0;w.r.registers.ax=0;w.r.carry=0;w.r.registers.bx=(uint16_t)((w.r.registers.bx&0xff00)|10);wb(&w,0x3368,(uint8_t)w.r.registers.bx);wr(&w,0x3346,(uint16_t)(rd(&w,0x3346)+1));b=byte(&w,0x5490);cmp(&w,b,2);if(b>=2)goto epilogue;
    b=byte(&w,0x336b);cmp(&w,b,(uint8_t)w.r.registers.ax);if(b!=(uint8_t)w.r.registers.ax)wr(&w,0x331e,(uint16_t)(rd(&w,0x331e)+1));b=byte(&w,0x33d5);cmp(&w,b,0);if(b!=0){w.r.registers.dx=rd(&w,0x3356);wr(&w,0x331e,w.r.registers.dx);}
    b=byte(&w,0x3378);cmp(&w,b,(uint8_t)w.r.registers.ax);if(b!=0)goto counter;b=byte(&w,0x3375);cmp(&w,b,(uint8_t)w.r.registers.ax);if(b!=0)goto counter;v=rd(&w,0x331e);cmp(&w,v,w.r.registers.ax);if(v!=w.r.registers.ax)wr(&w,0x5372,(uint16_t)(rd(&w,0x5372)+1));
counter:
    b=(uint8_t)(byte(&w,0x3369)-1);wb(&w,0x3369,b);if(b!=0)goto input;
    wb(&w,0x3369,(uint8_t)w.r.registers.bx);wb(&w,0x2f5c,(uint8_t)w.r.registers.bx);wr(&w,0x5346,(uint16_t)(rd(&w,0x5346)+1));b=byte(&w,0x33d5);cmp(&w,b,0);if(b!=0)goto input;
    wr(&w,0x942e,(uint16_t)(rd(&w,0x942e)+1));v=rd(&w,0x942e);cmp(&w,v,0x708);if(v>=0x708){wr(&w,0x8424,1);wb(&w,0x5490,2);}b=byte(&w,0x336b);cmp(&w,b,(uint8_t)w.r.registers.ax);if(b==(uint8_t)w.r.registers.ax){wb(&w,0x3369,(uint8_t)w.r.registers.bx);wr(&w,0x942e,(uint16_t)(rd(&w,0x942e)-1));}
input:
    wb(&w,0x336c,(uint8_t)w.r.registers.ax);wb(&w,0x336d,(uint8_t)w.r.registers.ax);if(!invoke(&w,0x40d9))goto done;b=byte(&w,0x33d4);cmp(&w,b,0);if(b!=0)goto paused;
    w.r.registers.ax=rd(&w,0x52ce);wr(&w,0x332e,w.r.registers.ax);v=rd(&w,0x8a9a);cmp(&w,v,1);if(v==1 && !invoke(&w,0x40f0))goto done;if(!invoke(&w,0x40f3))goto done;w.r.registers.ax=rd(&w,0x52ce);w.r.registers.ax=sub(&w,w.r.registers.ax,rd(&w,0x332e));if(w.r.carry)w.r.registers.ax=sub(&w,0,w.r.registers.ax);wr(&w,0x332e,w.r.registers.ax);
    if(!invoke(&w,0x4104) || !invoke(&w,0x4107))goto done;v=rd(&w,0x942e);cmp(&w,v,0);if(v==0)goto epilogue;
    if(!invoke(&w,0x4111) || !invoke(&w,0x4114) || !invoke(&w,0x4117) || !invoke(&w,0x411a))goto done;b=byte(&w,0x33d4);cmp(&w,b,0);if(b==0)goto epilogue;
paused:
    if(!invoke(&w,0x4124))goto done;
epilogue:
    w.r.bp=pop(&w);w.r.registers.di=pop(&w);w.r.registers.es=pop(&w);w.r.registers.ds=pop(&w);out->next_ip=pop(&w);out->next_segment=pop(&w);out->status=0;
done:
    out->current_sp=w.sp;out->returned=w.r;
}
