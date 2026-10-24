#include "td2ega_runtime_dispatch_bus.h"
#include <stddef.h>
typedef struct work {
    uint8_t *m;uint32_t bytes;uint16_t load,cs,ss,sp;
    td2ega_state_registers r;td2ega_input_flags f;
    const td2ega_runtime_dispatch_limits *caps;
    const td2ega_runtime_dispatch_services *services;
    td2ega_runtime_dispatch_result *out;
} work;
static uint32_t address(uint16_t s,uint16_t o){return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(work *w,uint16_t s,uint16_t o)
{uint32_t a=address(s,o);return (uint16_t)(w->m[a]|((uint16_t)w->m[(a+1)&UINT32_C(0xfffff)]<<8));}
static void put(work *w,uint16_t s,uint16_t o,uint16_t v)
{uint32_t a=address(s,o);w->m[a]=(uint8_t)v;w->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++w->out->bus_writes;}
static void push(work *w,uint16_t v){w->sp=(uint16_t)(w->sp-2);put(w,w->ss,w->sp,v);}
static uint16_t pop(work *w){uint16_t v=word(w,w->ss,w->sp);w->sp=(uint16_t)(w->sp+2);return v;}
static int valid_state(const td2ega_state_registers *r)
{return r->carry<=1 && r->registers.interrupts_enabled<=1 && r->registers.direction<=1;}
static int valid_flags(uint16_t word_value,uint16_t mask,const td2ega_state_registers *r)
{return valid_state(r) && !(word_value&~UINT16_C(0x0ed7)) && (word_value&2) && (mask==0xffff || mask==0xffef || mask==0xf72b || mask==0xf72a) && (word_value&1)==r->carry && ((word_value>>9)&1)==r->registers.interrupts_enabled && ((word_value>>10)&1)==r->registers.direction;}
static void sync(work *w)
{w->r.carry=(uint16_t)(w->f.word&1);w->r.registers.interrupts_enabled=(uint16_t)((w->f.word>>9)&1);w->r.registers.direction=(uint16_t)((w->f.word>>10)&1);}
static void partial(work *w)
{w->f=(td2ega_input_flags){(uint16_t)(2|w->r.carry|(w->r.registers.interrupts_enabled<<9)|(w->r.registers.direction<<10)),0xf72b};}
static void carry(work *w,uint16_t v){w->f.word=(uint16_t)((w->f.word&~1)|v);w->f.mask|=1;sync(w);}
static void logic(work *w,uint16_t v){w->f=td2ega_input_flag_logic(w->f,v,16,0);sync(w);}
static void cmp(work *w,uint16_t a,uint16_t b,unsigned width){w->f=td2ega_input_flag_sub(w->f,a,b,width);sync(w);}
static uint16_t add(work *w,uint16_t a,uint16_t b){w->f=td2ega_input_flag_add16(w->f,a,b);sync(w);return (uint16_t)(a+b);}
static uint16_t sub(work *w,uint16_t a,uint16_t b){w->f=td2ega_input_flag_sub(w->f,a,b,16);sync(w);return (uint16_t)(a-b);}
static uint16_t dec(work *w,uint16_t v)
{uint16_t cf=(uint16_t)(w->f.word&1),known=(uint16_t)(w->f.mask&1);w->f=td2ega_input_flag_sub(w->f,v,1,16);w->f.word=(uint16_t)((w->f.word&~1)|cf);w->f.mask=(uint16_t)((w->f.mask&~1)|known);sync(w);return (uint16_t)(v-1);}
static uint16_t shl(work *w,uint16_t v){w->f=td2ega_input_flag_shl1(w->f,v,0);sync(w);return (uint16_t)(v<<1);}
static int stop(work *w,uint16_t status,uint16_t site)
{w->out->status=status;w->out->halt_site=site;w->out->next_segment=w->cs;w->out->next_ip=site;return 0;}
static int step(work *w,uint16_t site){if(w->out->steps==w->caps->steps)return stop(w,3,site);++w->out->steps;return 1;}
static int store(work *w,uint16_t site,uint16_t s,uint16_t o,uint16_t v)
{if(!step(w,site))return 0;put(w,s,o,v);return 1;}
static int call(work *w,uint16_t site,uint16_t ret,uint16_t stage)
{if(w->out->calls==w->caps->calls)return stop(w,3,site);++w->out->calls;push(w,w->cs);push(w,ret);w->out->stage=stage;return 1;}
static int continuation(work *w,uint16_t ip,uint16_t sp,uint16_t parent)
{if(w->out->next_segment!=w->cs || w->out->next_ip!=ip || w->sp!=sp){w->out->status=1;return 0;}w->out->stage=parent;return 1;}
static int retire(work *w,uint16_t site)
{w->out->halt_site=site;if(w->sp>0xfffc)return stop(w,7,site);w->out->next_ip=pop(w);w->out->next_segment=pop(w);w->out->status=0;return 1;}
static int dos(work *w,uint16_t site,uint16_t vector)
{
    td2ega_small_platform_request q;td2ega_state_registers response;
    if(!step(w,site))return 0;q=(td2ega_small_platform_request){vector,site,w->cs,w->ss,w->sp,w->r};response=w->r;
    if(w->services->dos==NULL || !w->services->dos(w->services->context,w->m,&q,&response) || !valid_state(&response))return stop(w,4,site);
    ++w->out->services;w->r=response;partial(w);return 1;
}
static int exit_child(work *w,uint16_t site,uint16_t ret,uint16_t stage)
{
    td2ega_runtime_exit_result r;
    if(!call(w,site,ret,stage))return 0;
    td2ega_runtime_exit(w->m,w->bytes,w->load,w->ss,w->sp,&w->r,w->services->dos,w->services->finalizer,w->services->context,w->caps->exit_operations,&r);
    w->r=r.returned;w->sp=r.current_sp;partial(w);w->out->services+=r.services;w->out->callbacks+=r.callbacks;w->out->bus_writes+=r.bus_writes;w->out->status=r.status;w->out->next_segment=r.next_segment;w->out->next_ip=r.next_ip;w->out->halt_site=r.next_ip;w->out->exit_request=r.exit_request;return 0;
}
static int handler(work *w,uint16_t site,uint16_t ret,uint16_t stage,uint16_t segment,uint16_t ip,uint16_t parent)
{
    td2ega_runtime_dispatch_request q;td2ega_runtime_dispatch_response response;uint16_t before=w->sp;
    if(!call(w,site,ret,stage))return 0;q=(td2ega_runtime_dispatch_request){(uint16_t)(site==0x2c83?0:1),site,segment,ip,w->ss,w->sp,w->f.word,w->f.mask,w->r};response=(td2ega_runtime_dispatch_response){0};
    if(w->services->handler==NULL || !w->services->handler(w->services->context,w->m,w->bytes,&q,&response) || response.status>7 || response.status==2 || response.status==6 || !valid_flags(response.flags_word,response.flags_mask,&response.returned)){
        w->out->status=4;w->out->next_segment=segment;w->out->next_ip=ip;w->out->halt_site=site;return 0;
    }
    ++w->out->callbacks;w->out->bus_writes+=response.bus_writes;w->r=response.returned;w->sp=response.current_sp;w->f=(td2ega_input_flags){response.flags_word,response.flags_mask};w->out->next_segment=response.next_segment;w->out->next_ip=response.next_ip;w->out->halt_site=site;
    if(response.status){w->out->status=response.status;w->out->exit_request=response.exit_request;return 0;}return continuation(w,ret,before,parent);
}
#define AX w->r.registers.ax
#define BX w->r.registers.bx
#define CX w->r.registers.cx
#define DX w->r.registers.dx
#define BP w->r.bp
#define DS w->r.registers.ds
#define ES w->r.registers.es
#define DI w->r.registers.di
#define SI w->r.registers.si
#define STORE(site,s,o,v) do{if(!store(w,(site),(s),(o),(v)))return 0;}while(0)
static int lookup(work *w)
{
    uint8_t key;
    if(!step(w,0x2d57))return 0;push(w,BP);BP=w->sp;BX=0x2cb3;CX=6;
    do{
        if(!step(w,0x2d61))return 0;key=w->m[address(w->cs,BX)];cmp(w,key,(uint8_t)AX,8);if(key==(uint8_t)AX)goto found;BX=dec(w,BX);CX=(uint16_t)(CX-1);
    }while(CX);
    carry(w,1);goto finish;
found:
    CX=dec(w,CX);AX=CX;AX=shl(w,AX);AX=shl(w,AX);BX=0x7058;BX=add(w,BX,AX);carry(w,0);
finish:
    w->sp=BP;BP=pop(w);return retire(w,0x2d7e);
}
static int dispatch(work *w)
{
    uint16_t before,parent=w->out->stage,target,segment;
    if(!step(w,0x2c1c))return 0;push(w,BP);BP=w->sp;w->sp=sub(w,w->sp,4);AX=word(w,w->ss,(uint16_t)(BP+6));cmp(w,AX,2,16);
    if(AX==2){carry(w,0);if(!dos(w,0x2c2b,0x23))return 0;if(!w->r.carry)goto returned_zero;AX=(uint16_t)((AX&255)|0x4c00);if(!step(w,0x2c31))return 0;w->out->exit_request=(td2ega_small_platform_request){0x21,0x2c31,w->cs,w->ss,w->sp,w->r};return stop(w,5,0x2c31);}
    cmp(w,AX,8,16);if(AX==8){BX=word(w,DS,0x7076);BX=(uint16_t)(BX|word(w,DS,0x7078));logic(w,BX);if(!BX)goto returned_error;}
    before=w->sp;if(!call(w,0x2c42,0x2c47,1))return 0;if(!lookup(w) || !continuation(w,0x2c47,before,parent))return 0;if(w->r.carry)goto returned_error;
    AX=word(w,DS,BX);DX=word(w,DS,(uint16_t)(BX+2));logic(w,DX);
    if(DX==0){cmp(w,AX,1,16);if(AX<=1){logic(w,AX);if(AX)goto returned_zero;BX=CX;BX=shl(w,BX);target=word(w,w->cs,(uint16_t)(BX+0x2c10));
        if(target==0x2ca7)goto returned_zero;if(target==0x2ca1)goto returned_error;if(target==0x2c98)goto exit_three;if(target==0x2c90)goto fallback;
        w->out->raw_target=target;w->out->raw_segment=w->cs;return stop(w,6,0x2c5f);
    }}
    STORE(0x2c64,w->ss,(uint16_t)(BP-4),AX);STORE(0x2c67,w->ss,(uint16_t)(BP-2),DX);push(w,ES);push(w,BP);push(w,DI);push(w,SI);CX=word(w,w->ss,(uint16_t)(BP+6));cmp(w,CX,8,16);
    if(CX!=8){AX=0;logic(w,0);STORE(0x2c78,DS,BX,AX);STORE(0x2c7a,DS,(uint16_t)(BX+2),AX);}
    AX=0x8c;push(w,AX);push(w,CX);w->f.word=(uint16_t)(w->f.word&~0x400);sync(w);target=word(w,w->ss,(uint16_t)(BP-4));segment=word(w,w->ss,(uint16_t)(BP-2));if(!handler(w,0x2c83,0x2c86,2,segment,target,parent))return 0;
    w->sp=add(w,w->sp,4);SI=pop(w);DI=pop(w);BP=pop(w);ES=pop(w);goto returned_zero;
fallback:
    AX=0x8c;target=word(w,w->ss,0x707e);segment=word(w,w->ss,0x7080);if(!handler(w,0x2c93,0x2c98,3,segment,target,parent))return 0;
exit_three:
    AX=3;push(w,AX);return exit_child(w,0x2c9c,0x2ca1,4);
returned_error:
    AX=0xffff;goto returned;
returned_zero:
    AX=0;logic(w,0);
returned:
    w->sp=BP;BP=pop(w);return retire(w,0x2cac);
}
static int wrapper(work *w)
{
    uint16_t before;td2ega_runtime_message_result message;
    if(!step(w,0x29f6))return 0;push(w,BP);BP=w->sp;AX=0xa;push(w,AX);before=w->sp;
    if(!call(w,0x29fd,0x2a02,5))return 0;td2ega_runtime_message(w->m,w->bytes,w->load,w->ss,w->sp,1,&w->r,w->services->dos,w->services->context,w->caps->message_operations,&message);
    w->r=message.returned;w->sp=message.current_sp;partial(w);w->out->services+=message.services;w->out->bus_writes+=message.bus_writes;w->out->next_segment=message.next_segment;w->out->next_ip=message.next_ip;w->out->halt_site=message.next_ip;
    if(message.status){w->out->status=message.status;return 0;}if(!continuation(w,0x2a02,(uint16_t)(before+2),0))return 0;
    AX=0x16;push(w,AX);before=w->sp;if(!call(w,0x2a06,0x2a0b,6))return 0;if(!dispatch(w) || !continuation(w,0x2a0b,before,0))return 0;
    AX=3;push(w,AX);return exit_child(w,0x2a0f,0x2a14,7);
}
void td2ega_runtime_dispatch_bus(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,uint16_t sp,uint16_t entry,uint16_t flags,uint16_t mask,const td2ega_state_registers *in,const td2ega_runtime_dispatch_limits *caps,const td2ega_runtime_dispatch_services *services,td2ega_runtime_dispatch_result *out)
{
    work w;
    if(out==NULL)return;*out=(td2ega_runtime_dispatch_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || caps==NULL || services==NULL || entry>2 || (entry==0 && sp<2) || (entry==1 && (sp<92 || sp>0xffe0)) || (entry==2 && (sp<100 || sp>0xffe0)) || !valid_flags(flags,mask,in))return;
    w=(work){m,bytes,load,(uint16_t)(load+0x13a8),ss,sp,*in,{flags,mask},caps,services,out};if(entry==0)lookup(&w);else if(entry==1)dispatch(&w);else wrapper(&w);
    out->current_sp=w.sp;out->returned=w.r;out->flags_word=w.f.word;out->flags_mask=w.f.mask;
}
