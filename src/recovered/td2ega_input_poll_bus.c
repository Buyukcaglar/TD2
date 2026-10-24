#include "td2ega_input_poll_bus.h"
#include <stddef.h>
typedef struct work {uint8_t *m;uint32_t bytes;uint16_t load,cs,ss,sp;td2ega_input_flags f;td2ega_state_registers r;const td2ega_input_poll_bus_limits *limits;const td2ega_input_poll_bus_services *services;td2ega_input_poll_bus_result *o;} work;
static uint32_t address(uint16_t s,uint16_t o){return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(work *w,uint16_t s,uint16_t o){uint32_t a=address(s,o);return (uint16_t)(w->m[a]|((uint16_t)w->m[(a+1)&UINT32_C(0xfffff)]<<8));}
static uint16_t rd(work *w,uint16_t o){return word(w,w->r.registers.ds,o);}
static uint8_t byte(work *w,uint16_t o){return w->m[address(w->r.registers.ds,o)];}
static void put(work *w,uint16_t s,uint16_t o,uint16_t v){uint32_t a=address(s,o);w->m[a]=(uint8_t)v;w->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++w->o->bus_writes;}
static void wr(work *w,uint16_t o,uint16_t v){put(w,w->r.registers.ds,o,v);}
static void push(work *w,uint16_t v){w->sp=(uint16_t)(w->sp-2);put(w,w->ss,w->sp,v);}
static uint16_t pop(work *w){uint16_t v=word(w,w->ss,w->sp);w->sp=(uint16_t)(w->sp+2);return v;}
static void sync(work *w){w->r.carry=(uint16_t)(w->f.word&1);w->r.registers.interrupts_enabled=(uint16_t)((w->f.word>>9)&1);w->r.registers.direction=(uint16_t)((w->f.word>>10)&1);}
static void child_flags(work *w,int zf_valid,uint16_t zf)
{
    uint16_t known=(uint16_t)(0x601|(zf_valid?0x40:0));
    w->f.word=(uint16_t)((w->f.word&~known)|w->r.carry|(w->r.registers.interrupts_enabled<<9)|(w->r.registers.direction<<10)|(zf_valid?(zf<<6):0));
    w->f.mask=(uint16_t)((w->f.mask&~TD2EGA_INPUT_ARITH_FLAGS)|known);
}
static void logic(work *w,uint16_t v,unsigned width){w->f=td2ega_input_flag_logic(w->f,v,width,w->services->undefined_af);sync(w);}
static void cmp(work *w,uint16_t a,uint16_t b,unsigned width){w->f=td2ega_input_flag_sub(w->f,a,b,width);sync(w);}
static int bios(work *w,uint16_t site)
{
    td2ega_keyboard_bios_bus_result h;td2ega_input_flags before=w->f;uint16_t expected=w->sp,frame,operation=(uint16_t)(w->r.registers.ax>>8),saved,mask;uint32_t fa,ca,cb;
    w->o->next_segment=w->cs;w->o->next_ip=site;
    if(w->o->bios_calls==w->limits->bios_calls){w->o->status=3;return 0;}
    ++w->o->bios_calls;push(w,w->f.word);push(w,w->cs);push(w,(uint16_t)(site+2));frame=w->sp;w->f.word&=UINT16_C(0xfcff);sync(w);
    td2ega_keyboard_bios_bus(w->m,w->bytes,w->load,w->ss,w->sp,&w->r,&h);w->r=h.returned;w->sp=h.current_sp;w->o->bus_writes+=h.bus_writes;w->o->next_segment=h.next_segment;w->o->next_ip=h.next_ip;
    if(operation==1){w->f=td2ega_input_flag_logic(before,w->r.registers.ax,16,w->services->undefined_af);w->f.word=(uint16_t)((w->f.word&~0x600)|(w->r.registers.interrupts_enabled<<9)|(w->r.registers.direction<<10));w->f.mask|=0x600;}
    else if(h.status==0){
        saved=word(w,w->ss,(uint16_t)(frame+4));mask=before.mask;
        fa=address(w->ss,(uint16_t)(frame+4));ca=address((uint16_t)(w->load+0x178f),0x62b6);cb=(ca+1)&UINT32_C(0xfffff);
        if(ca==fa || cb==fa)mask|=0x00ff;
        if(ca==((fa+1)&UINT32_C(0xfffff)) || cb==((fa+1)&UINT32_C(0xfffff)))mask|=0xff00;
        w->f=(td2ega_input_flags){(uint16_t)((saved&0x0ed5)|2),(uint16_t)(mask|UINT16_C(0xf12a))};
    }else{w->f=td2ega_input_flag_sub(before,0,0,8);w->f.word=(uint16_t)((w->f.word&~0x600)|(w->r.registers.interrupts_enabled<<9)|(w->r.registers.direction<<10));}
    sync(w);
    if(h.status!=0){w->o->status=(uint16_t)(h.status==2?4:h.status);return 0;}
    if(h.next_segment!=w->cs || h.next_ip!=(uint16_t)(site+2) || w->sp!=expected){w->o->status=1;return 0;}return 1;
}
static int call(work *w,uint16_t site,int dispatch)
{
    uint16_t expected=w->sp;td2ega_key_dispatch_bus_result k;td2ega_gameport_bus_result p;
    w->o->next_segment=w->cs;w->o->next_ip=site;
    if(w->o->calls==w->limits->calls){w->o->status=3;return 0;}
    ++w->o->calls;push(w,w->cs);push(w,(uint16_t)(site+5));
    if(dispatch){
        td2ega_key_dispatch_bus(w->m,w->bytes,w->load,w->ss,w->sp,&w->r,w->limits->callback_calls,w->services->key,w->services->key_context,&k);w->r=k.returned;w->sp=k.current_sp;w->o->callback_calls+=k.calls;w->o->bus_writes+=k.bus_writes;w->o->next_segment=k.next_segment;w->o->next_ip=k.next_ip;child_flags(w,k.flags_valid,k.zero_flag);
        if(k.status!=0){w->o->status=(uint16_t)(k.status==2?4:k.status);return 0;}
    }else{
        td2ega_gameport_bus(w->m,w->bytes,w->load,w->ss,w->sp,0,(uint16_t)((w->f.word>>6)&1),&w->r,w->limits->port_reads,w->services->port,w->services->port_context,&p);w->r=p.returned;w->sp=p.current_sp;w->o->port_reads+=p.reads;w->o->port_transfers+=p.transfers;w->o->bus_writes+=p.bus_writes;w->o->next_segment=p.next_segment;w->o->next_ip=p.next_ip;child_flags(w,p.flags_valid,p.zero_flag);
        if(p.status==0 || (p.status==5 && (p.next_ip==0x668f || p.next_ip==0x6802))){logic(w,0,8);}
        if(p.status!=0){w->o->status=(uint16_t)(p.status==2?4:p.status);return 0;}
    }
    if(w->o->next_segment!=w->cs || w->o->next_ip!=(uint16_t)(site+5) || w->sp!=expected){w->o->status=1;return 0;}return 1;
}
#define AX w.r.registers.ax
#define BX w.r.registers.bx
#define CX w.r.registers.cx
void td2ega_input_poll_bus(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,uint16_t sp,uint16_t entry,uint16_t flags,uint16_t flags_mask,const td2ega_state_registers *in,const td2ega_input_poll_bus_limits *limits,const td2ega_input_poll_bus_services *services,td2ega_input_poll_bus_result *out)
{
    static const uint16_t fields[10]={0x62f3,0x62d6,0x6301,0x6302,0x6303,0x6307,0x630b,0x630a,0x6309,0x6305};
    static const uint16_t bits[10]={0x10,0x20,9,1,5,4,6,2,10,8};
    work w;uint16_t v,old,ret_site=0;unsigned i;
    if(out==NULL)return;
    *out=(td2ega_input_poll_bus_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || limits==NULL || services==NULL || entry>2 || services->undefined_af>1 || (flags&~UINT16_C(0x0ed7))!=0 || (flags&2)==0 || (flags_mask!=UINT16_C(0xffff) && flags_mask!=UINT16_C(0xffef)) || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1 || in->carry!=(flags&1) || in->registers.interrupts_enabled!=((flags>>9)&1) || in->registers.direction!=((flags>>10)&1))return;
    w=(work){m,bytes,load,(uint16_t)(load+0x6c9),ss,sp,{flags,flags_mask},*in,limits,services,out};
    if(entry==2){
        AX=0;logic(&w,AX,16);
        for(i=0;i<10;++i){v=byte(&w,fields[i]);cmp(&w,v,0,8);if(v!=0){AX=(uint16_t)((AX&0xff00)|((uint8_t)AX|bits[i]));logic(&w,(uint8_t)AX,8);}}
        logic(&w,AX,16);if(AX==0 && !call(&w,0x6680,0))goto done;ret_site=0x6685;goto root;
    }
    AX=(uint16_t)((AX&255)|0x100);if(!bios(&w,(uint16_t)(entry==0?0x65c7:0x6603)))goto done;
    if(entry==1){
        if(w.f.word&0x40){AX=0;logic(&w,0,16);ret_site=0x6609;goto root;}
        BX=ss;CX=w.r.registers.ds;cmp(&w,BX,CX,16);if(BX!=CX){ret_site=0x661f;goto root;}
        AX=(uint16_t)(AX&255);if(!bios(&w,0x6614))goto done;push(&w,AX);if(!call(&w,0x6617,1))goto done;old=w.sp;w.sp=(uint16_t)(old+2);w.f=td2ega_input_flag_add16(w.f,old,2);sync(&w);ret_site=0x661f;goto root;
    }
    if((w.f.word&0x40)==0){AX=(uint16_t)(AX&255);if(!bios(&w,0x65cd))goto done;push(&w,AX);if(!call(&w,0x65d0,1))goto done;old=w.sp;w.sp=(uint16_t)(old+2);w.f=td2ega_input_flag_add16(w.f,old,2);sync(&w);ret_site=0x65d8;goto root;}
    if(!call(&w,0x65d9,0))goto done;BX=AX;logic(&w,(uint16_t)(AX&0x30),16);
    if((AX&0x30)!=0)AX=0x0d;
    else{BX=(uint16_t)(BX&15);logic(&w,BX,16);old=BX;BX=(uint16_t)(BX<<1);w.f=td2ega_input_flag_shl1(w.f,old,services->undefined_af);sync(&w);AX=rd(&w,(uint16_t)(BX+0x6254));}
    v=rd(&w,0x6274);cmp(&w,AX,v,16);if(AX==v){AX=0;logic(&w,0,16);ret_site=0x65fc;}else{wr(&w,0x6274,AX);ret_site=0x6600;}
root:
    if(w.sp>UINT16_C(0xfffc)){out->status=5;out->next_segment=w.cs;out->next_ip=ret_site;goto done;}
    out->next_ip=pop(&w);out->next_segment=pop(&w);out->status=0;out->zero_flag=(uint16_t)((w.f.word>>6)&1);out->flags_valid=1;
done:
    out->current_sp=w.sp;out->returned=w.r;out->flags_word=w.f.word;out->flags_mask=w.f.mask;
}
