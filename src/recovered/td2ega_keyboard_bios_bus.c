#include "td2ega_keyboard_bios_bus.h"
#include <stddef.h>
typedef struct work {uint8_t *m;uint16_t ss,sp;td2ega_state_registers r;td2ega_keyboard_bios_bus_result *o;} work;
static uint32_t address(uint16_t s,uint16_t o){return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(work *w,uint16_t s,uint16_t o){uint32_t a=address(s,o);return (uint16_t)(w->m[a]|((uint16_t)w->m[(a+1)&UINT32_C(0xfffff)]<<8));}
static uint8_t byte(work *w,uint16_t o){return w->m[address(w->r.registers.ds,o)];}
static void put(work *w,uint16_t s,uint16_t o,uint16_t v){uint32_t a=address(s,o);w->m[a]=(uint8_t)v;w->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++w->o->bus_writes;}
static void push(work *w,uint16_t v){w->sp=(uint16_t)(w->sp-2);put(w,w->ss,w->sp,v);}
static uint16_t pop(work *w){uint16_t v=word(w,w->ss,w->sp);w->sp=(uint16_t)(w->sp+2);return v;}
void td2ega_keyboard_bios_bus(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,uint16_t sp,const td2ega_state_registers *in,td2ega_keyboard_bios_bus_result *out)
{
    work w;uint16_t ah,flags,zf=0,site;uint8_t b;
    if(out==NULL)return;
    *out=(td2ega_keyboard_bios_bus_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1)return;
    w=(work){m,ss,sp,*in,out};push(&w,w.r.registers.bx);push(&w,w.r.registers.ds);w.r.registers.bx=(uint16_t)(load+0x178f);w.r.registers.ds=w.r.registers.bx;ah=(uint16_t)(w.r.registers.ax>>8);
    if(ah==1){w.r.registers.ax=word(&w,w.r.registers.ds,0x62b6);w.r.registers.interrupts_enabled=1;w.r.carry=0;zf=(uint16_t)(w.r.registers.ax==0);w.r.registers.ds=pop(&w);w.r.registers.bx=pop(&w);out->return_kind=1;site=0x69e6;}
    else{
        if(ah==0){w.r.registers.interrupts_enabled=0;w.r.registers.ax=word(&w,w.r.registers.ds,0x62b6);put(&w,w.r.registers.ds,0x62b6,0);w.r.carry=0;zf=1;}
        else if(ah==2){b=byte(&w,0x62e4);w.r.registers.ax=(uint16_t)((w.r.registers.ax&0xff00)|b);b=(uint8_t)(b|byte(&w,0x62f0));w.r.registers.ax=(uint16_t)((w.r.registers.ax&0xff00)|b);w.r.carry=0;zf=(uint16_t)(b==0);}
        else{w.r.registers.ax=0;w.r.carry=0;zf=1;}
        w.r.registers.ds=pop(&w);w.r.registers.bx=pop(&w);out->return_kind=0;site=0x69d1;
    }
    if(w.sp>(out->return_kind?UINT16_C(0xfffc):UINT16_C(0xfffa))){out->status=5;out->next_segment=(uint16_t)(load+0x6c9);out->next_ip=site;goto done;}
    out->next_ip=pop(&w);out->next_segment=pop(&w);
    if(out->return_kind)w.sp=(uint16_t)(w.sp+2);
    else{flags=pop(&w);w.r.carry=(uint16_t)(flags&1);w.r.registers.interrupts_enabled=(uint16_t)((flags>>9)&1);w.r.registers.direction=(uint16_t)((flags>>10)&1);zf=(uint16_t)((flags>>6)&1);}
    out->status=0;out->zero_flag=zf;out->flags_valid=1;
done:
    out->current_sp=w.sp;out->returned=w.r;
}
