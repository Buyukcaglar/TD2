#include "td2ega_session_init_bus.h"
#include <stddef.h>
typedef struct work {
    uint8_t *m;uint32_t bytes;uint16_t load,cs,ss,sp;
    td2ega_state_registers r;td2ega_input_flags f;
    const td2ega_session_init_bus_limits *caps;
    td2ega_music_port_service port;void *context;
    td2ega_session_init_bus_result *out;
} work;
typedef struct field {uint16_t site,offset;unsigned width;} field;
static uint32_t address(uint16_t s,uint16_t o){return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(work *w,uint16_t s,uint16_t o)
{uint32_t a=address(s,o);return (uint16_t)(w->m[a]|((uint16_t)w->m[(a+1)&UINT32_C(0xfffff)]<<8));}
static uint16_t rd(work *w,uint16_t o){return word(w,w->r.registers.ds,o);}
static uint8_t rb(work *w,uint16_t o){return w->m[address(w->r.registers.ds,o)];}
static void put(work *w,uint16_t s,uint16_t o,uint16_t v,unsigned width)
{uint32_t a=address(s,o);w->m[a]=(uint8_t)v;if(width==2)w->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++w->out->bus_writes;}
static void push(work *w,uint16_t v){w->sp=(uint16_t)(w->sp-2);put(w,w->ss,w->sp,v,2);}
static uint16_t pop(work *w){uint16_t v=word(w,w->ss,w->sp);w->sp=(uint16_t)(w->sp+2);return v;}
static void sync(work *w)
{w->r.carry=(uint16_t)(w->f.word&1);w->r.registers.interrupts_enabled=(uint16_t)((w->f.word>>9)&1);w->r.registers.direction=(uint16_t)((w->f.word>>10)&1);}
static void logic(work *w,uint16_t v,unsigned width){w->f=td2ega_input_flag_logic(w->f,v,width,0);sync(w);}
static void cmp8(work *w,uint16_t a,uint16_t b){w->f=td2ega_input_flag_sub(w->f,a,b,8);sync(w);}
static uint16_t add(work *w,uint16_t a,uint16_t b){w->f=td2ega_input_flag_add16(w->f,a,b);sync(w);return (uint16_t)(a+b);}
static uint16_t inc(work *w,uint16_t v)
{uint16_t cf=(uint16_t)(w->f.word&1),known=(uint16_t)(w->f.mask&1);w->f=td2ega_input_flag_add16(w->f,v,1);w->f.word=(uint16_t)((w->f.word&~1)|cf);w->f.mask=(uint16_t)((w->f.mask&~1)|known);sync(w);return (uint16_t)(v+1);}
static uint16_t shl(work *w,uint16_t v){w->f=td2ega_input_flag_shl1(w->f,v,0);sync(w);return (uint16_t)(v<<1);}
static int stop(work *w,uint16_t status,uint16_t site)
{w->out->status=status;w->out->halt_site=site;w->out->next_segment=w->cs;w->out->next_ip=site;return 0;}
static int step(work *w,uint16_t site){if(w->out->steps==w->caps->steps)return stop(w,3,site);++w->out->steps;return 1;}
static int store(work *w,uint16_t site,uint16_t offset,uint16_t value,unsigned width)
{if(!step(w,site))return 0;put(w,w->r.registers.ds,offset,value,width);return 1;}
static int retire(work *w,uint16_t site,int far_return)
{w->out->halt_site=site;if(w->sp>(far_return?0xfffc:0xfffe))return stop(w,5,site);w->out->next_ip=pop(w);w->out->next_segment=far_return?pop(w):w->cs;w->out->status=0;return 1;}
static int call(work *w,uint16_t site,uint16_t ret,uint16_t stage,int far_call)
{if(w->out->init_calls==w->caps->init_calls)return stop(w,3,site);++w->out->init_calls;if(far_call)push(w,w->cs);push(w,ret);w->out->stage=stage;return 1;}
static int continuation(work *w,uint16_t ip,uint16_t sp,uint16_t parent)
{if(w->out->next_segment!=w->cs || w->out->next_ip!=ip || w->sp!=sp){w->out->status=1;return 0;}w->out->stage=parent;return 1;}
#define AX w->r.registers.ax
#define BX w->r.registers.bx
#define CX w->r.registers.cx
#define SI w->r.registers.si
#define DI w->r.registers.di
#define ES w->r.registers.es
#define STORE(site,offset,value,width) do{if(!store(w,(site),(offset),(value),(width)))return 0;}while(0)
static int clear_transition(work *w)
{
    if(!step(w,0x5427))return 0;AX=0;logic(w,0,16);
    STORE(0x5429,0x52da,AX,2);STORE(0x542c,0x33b6,(uint8_t)AX,1);STORE(0x542f,0x33b7,(uint8_t)AX,1);STORE(0x5432,0x33b8,(uint8_t)AX,1);STORE(0x5435,0x33ba,(uint8_t)AX,1);return retire(w,0x5438,0);
}
static int zero_simulation(work *w)
{
    static const field fields[]={
        {0x3ffb,0x3365,1},{0x3ffe,0x3367,1},{0x4001,0x52ce,2},{0x4004,0x332c,2},{0x4007,0x332a,2},{0x400a,0x336b,1},{0x400d,0x33b2,1},{0x4010,0x337b,1},{0x4013,0x33b3,1},{0x4016,0x33bf,2},{0x4019,0x33c1,2},{0x401c,0x33c3,2},{0x401f,0x33c5,1},{0x4022,0x33c6,1},{0x4025,0x33c8,2},{0x4028,0x33cc,2}};
    unsigned i;uint16_t before,parent=w->out->stage;
    if(!step(w,0x3ff9))return 0;AX=0;logic(w,0,16);
    for(i=0;i<sizeof fields/sizeof fields[0];++i)STORE(fields[i].site,fields[i].offset,AX,fields[i].width);
    STORE(0x402b,0x33ca,0xfa,2);STORE(0x4031,0x5490,(uint8_t)AX,1);STORE(0x4034,0x33d4,(uint8_t)AX,1);
    before=w->sp;if(!call(w,0x4037,0x403a,2,0))return 0;if(!clear_transition(w) || !continuation(w,0x403a,before,parent))return 0;return retire(w,0x403a,1);
}
static int reset_view(work *w)
{
    if(!step(w,0x38f2))return 0;AX=0;logic(w,0,16);
    STORE(0x38f4,0x2f56,(uint8_t)AX,1);STORE(0x38f7,0x2f46,AX,2);STORE(0x38fa,0x2f48,AX,2);STORE(0x38fd,0x2f4a,AX,2);AX=inc(w,AX);
    STORE(0x3901,0x2f57,(uint8_t)AX,1);STORE(0x3904,0x2f5a,(uint8_t)AX,1);STORE(0x3907,0x2f5b,(uint8_t)AX,1);STORE(0x390a,0x2f5c,(uint8_t)AX,1);STORE(0x390d,0x2f59,0xa,1);
    AX=rd(w,0x23c6);STORE(0x3915,0x2f4c,AX,2);AX=rd(w,0x23c8);STORE(0x391b,0x2f4e,AX,2);return retire(w,0x391e,1);
}
static int reset_session(work *w)
{
    uint16_t before;
    if(!step(w,0x1e31))return 0;before=w->sp;if(!call(w,0x1e31,0x1e36,1,1))return 0;if(!zero_simulation(w) || !continuation(w,0x1e36,before,0))return 0;
    AX=0;logic(w,0,16);STORE(0x1e38,0x52cc,0xa0,2);STORE(0x1e3e,0x5490,(uint8_t)AX,1);STORE(0x1e41,0x5fd8,0xffff,2);STORE(0x1e47,0x5fda,0xffff,2);STORE(0x1e4d,0x5fdc,0xffff,2);
    before=w->sp;if(!call(w,0x1e53,0x1e58,3,1))return 0;if(!reset_view(w) || !continuation(w,0x1e58,before,0))return 0;return retire(w,0x1e58,1);
}
static int install_simulation(work *w)
{
    static const field fields[]={
        {0x3f4f,0x5344,2},{0x3f52,0x5346,2},{0x3f55,0x3322,2},{0x3f58,0x942e,2},{0x3f5b,0x331c,2},{0x3f5e,0x5372,2},{0x3f61,0x331e,2},{0x3f64,0x336b,1},{0x3f67,0x3371,1},{0x3f6a,0x533e,2},{0x3f6d,0x330c,2},{0x3f70,0x330e,2},{0x3f73,0x3310,2},{0x3f76,0x3312,2},{0x3f79,0x3352,2},{0x3f7c,0x33b6,1},{0x3f7f,0x33b7,1},{0x3f82,0x33bc,1},{0x3f85,0x3374,1},{0x3f88,0x3375,1},{0x3f8b,0x52d8,2},{0x3f8e,0x52da,2},{0x3f91,0x52d6,2},{0x3f94,0x3376,1},{0x3f97,0x3377,1},{0x3f9a,0x3378,1},{0x3f9d,0x33d5,1}};
    unsigned i;uint16_t value;td2ega_timer_startup_tail_result tail;
    if(!step(w,0x3f40))return 0;AX=w->r.registers.ds;ES=AX;AX=0;logic(w,0,16);CX=8;DI=0x335d;w->f.word=(uint16_t)(w->f.word&~0x400);sync(w);
    while(CX){if(!step(w,0x3f4d))return 0;put(w,ES,DI,(uint8_t)AX,1);DI=(uint16_t)(DI+1);CX=(uint16_t)(CX-1);}
    for(i=0;i<sizeof fields/sizeof fields[0];++i)STORE(fields[i].site,fields[i].offset,AX,fields[i].width);
    value=rb(w,0x90a8);cmp8(w,value,0);if(value)STORE(0x3fa7,0x33af,0,1);
    AX=(uint16_t)((AX&0xff00)|rb(w,0x843e));STORE(0x3faf,0x3379,(uint8_t)AX,1);STORE(0x3fb2,0x337a,0x20,1);SI=0x3b51;CX=0x47;AX=(uint16_t)(AX&0xff00);logic(w,0,8);
    do{
        if(!step(w,0x3fbf))return 0;BX=(uint16_t)((BX&0xff00)|rb(w,SI));BX=shl(w,BX);BX=(uint16_t)(BX&255);logic(w,0,8);BX=shl(w,BX);
        AX=(uint16_t)((AX&255)|((uint16_t)rb(w,(uint16_t)(BX+0x347e))<<8));AX=(uint16_t)((AX&0xff00)|((uint8_t)AX^(uint8_t)(AX>>8)));logic(w,(uint8_t)AX,8);SI=inc(w,SI);CX=(uint16_t)(CX-1);
    }while(CX);
    STORE(0x3fd0,0x33bd,(uint8_t)AX,1);if(!step(w,0x3fd3))return 0;value=add(w,rd(w,0x3811),0x3b33);put(w,w->r.registers.ds,0x3811,value,2);
    td2ega_timer_startup_tail_bus(w->m,w->bytes,w->load,w->ss,w->sp,w->f.word,w->f.mask,&w->r,&w->caps->tail,w->port,w->context,&tail);
    w->r=tail.returned;w->f=(td2ega_input_flags){tail.flags_word,tail.flags_mask};w->sp=tail.current_sp;w->out->tail_calls=tail.calls;w->out->ports=tail.ports;w->out->bus_writes+=tail.bus_writes;w->out->status=tail.status;w->out->stage=tail.status?(uint16_t)(100+tail.stage):0;w->out->halt_site=tail.halt_site;w->out->next_segment=tail.next_segment;w->out->next_ip=tail.next_ip;w->out->call_segment=tail.call_segment;w->out->call_offset=tail.call_offset;return tail.status==0;
}
void td2ega_session_init_bus(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,uint16_t sp,uint16_t entry,uint16_t flags,uint16_t mask,const td2ega_state_registers *in,const td2ega_session_init_bus_limits *caps,td2ega_music_port_service port,void *context,td2ega_session_init_bus_result *out)
{
    work w;
    if(out==NULL)return;*out=(td2ega_session_init_bus_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || caps==NULL || entry>4 || (entry==0 && (sp<10 || sp>0xffe0 || port==NULL)) || (entry==1 && sp<2) || (entry==3 && sp<6) || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1 || (flags&~UINT16_C(0x0ed7)) || !(flags&2) || (mask!=0xffff && mask!=0xffef && mask!=0xf72b && mask!=0xf72a) || (flags&1)!=in->carry || ((flags>>9)&1)!=in->registers.interrupts_enabled || ((flags>>10)&1)!=in->registers.direction)return;
    w=(work){m,bytes,load,(uint16_t)(load+0x6c9),ss,sp,*in,{flags,mask},caps,port,context,out};
    if(entry==0)install_simulation(&w);else if(entry==1)zero_simulation(&w);else if(entry==2)reset_view(&w);else if(entry==3)reset_session(&w);else clear_transition(&w);
    out->current_sp=w.sp;out->returned=w.r;out->flags_word=w.f.word;out->flags_mask=w.f.mask;
}
