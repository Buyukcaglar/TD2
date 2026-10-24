#include "td2ega_timer_callback_bus.h"
#include <stddef.h>
typedef struct work {
    uint8_t *m;uint16_t cs,ss,sp;td2ega_state_registers r;td2ega_input_flags f;
    uint32_t max_steps;td2ega_timer_callback_bus_result *out;
} work;
static uint32_t address(uint16_t s,uint16_t o){return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(work *w,uint16_t s,uint16_t o)
{uint32_t a=address(s,o);return (uint16_t)(w->m[a]|((uint16_t)w->m[(a+1)&UINT32_C(0xfffff)]<<8));}
static uint16_t rd(work *w,uint16_t o){return word(w,w->r.registers.ds,o);}
static void put(work *w,uint16_t s,uint16_t o,uint16_t v)
{uint32_t a=address(s,o);w->m[a]=(uint8_t)v;w->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++w->out->bus_writes;}
static void push(work *w,uint16_t v){w->sp=(uint16_t)(w->sp-2);put(w,w->ss,w->sp,v);}
static uint16_t pop(work *w){uint16_t v=word(w,w->ss,w->sp);w->sp=(uint16_t)(w->sp+2);return v;}
static void sync(work *w)
{w->r.carry=(uint16_t)(w->f.word&1);w->r.registers.interrupts_enabled=(uint16_t)((w->f.word>>9)&1);w->r.registers.direction=(uint16_t)((w->f.word>>10)&1);}
static void cmp(work *w,uint16_t a,uint16_t b){w->f=td2ega_input_flag_sub(w->f,a,b,16);sync(w);}
static uint16_t add(work *w,uint16_t a,uint16_t b){w->f=td2ega_input_flag_add16(w->f,a,b);sync(w);return (uint16_t)(a+b);}
static uint16_t dec(work *w,uint16_t v)
{uint16_t cf=(uint16_t)(w->f.word&1),known=(uint16_t)(w->f.mask&1);w->f=td2ega_input_flag_sub(w->f,v,1,16);w->f.word=(uint16_t)((w->f.word&~1)|cf);w->f.mask=(uint16_t)((w->f.mask&~1)|known);sync(w);return (uint16_t)(v-1);}
static void enable(work *w,uint16_t v){w->f.word=(uint16_t)((w->f.word&~0x200)|(v<<9));sync(w);}
static int stop(work *w,uint16_t status,uint16_t site)
{w->out->status=status;w->out->halt_site=site;w->out->next_segment=w->cs;w->out->next_ip=site;return 0;}
static int step(work *w,uint16_t site){if(w->out->steps==w->max_steps)return stop(w,3,site);++w->out->steps;return 1;}
static int store(work *w,uint16_t site,uint16_t offset,uint16_t value)
{if(!step(w,site))return 0;put(w,w->r.registers.ds,offset,value);return 1;}
#define AX w.r.registers.ax
#define BX w.r.registers.bx
#define CX w.r.registers.cx
#define DX w.r.registers.dx
#define STORE(site,o,v) do{if(!store(&w,(site),(o),(v)))goto done;}while(0)
void td2ega_timer_callback_bus(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,uint16_t sp,uint16_t entry,uint16_t flags,uint16_t mask,const td2ega_state_registers *in,uint32_t max_steps,td2ega_timer_callback_bus_result *out)
{
    work w;uint16_t site=0x617f;
    if(out==NULL)return;*out=(td2ega_timer_callback_bus_result){0};out->status=2;out->slot=5;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || sp<2 || entry>1 || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1 || (flags&~UINT16_C(0x0ed7)) || !(flags&2) || (mask!=0xffff && mask!=0xffef && mask!=0xf72b && mask!=0xf72a) || (flags&1)!=in->carry || ((flags>>9)&1)!=in->registers.interrupts_enabled || ((flags>>10)&1)!=in->registers.direction)return;
    w=(work){m,(uint16_t)(load+0x6c9),ss,sp,*in,{flags,mask},max_steps,out};
    if(!step(&w,(uint16_t)(entry?0x6180:0x614c)))goto done;
    push(&w,w.r.bp);w.r.bp=w.sp;CX=5;BX=0x5f12;
    if(entry)goto remove;
    do{
        if(!step(&w,0x6155))goto done;cmp(&w,rd(&w,(uint16_t)(BX+2)),0);
        if(w.f.word&0x40)goto found;
        BX=add(&w,BX,4);CX=(uint16_t)(CX-1);
    }while(CX);
    AX=0x5fe8;push(&w,AX);out->call_segment=(uint16_t)(load+0x16a7);out->call_offset=2;stop(&w,6,0x6164);goto done;
found:
    out->slot=(uint16_t)(5-CX);AX=word(&w,w.ss,(uint16_t)(w.r.bp+6));STORE(0x616c,BX,AX);STORE(0x616e,(uint16_t)(BX+2),0);
    AX=word(&w,w.ss,(uint16_t)(w.r.bp+8));STORE(0x6176,(uint16_t)(BX+2),AX);STORE(0x6179,(uint16_t)(BX+6),0);w.r.bp=pop(&w);goto returned;
remove:
    AX=word(&w,w.ss,(uint16_t)(w.r.bp+6));DX=word(&w,w.ss,(uint16_t)(w.r.bp+8));
    do{
        if(!step(&w,0x618f))goto done;cmp(&w,rd(&w,BX),AX);
        if(w.f.word&0x40){cmp(&w,rd(&w,(uint16_t)(BX+2)),DX);if(w.f.word&0x40)goto matched;}
        BX=add(&w,BX,4);CX=(uint16_t)(CX-1);
    }while(CX);
    w.r.bp=pop(&w);site=0x619e;goto returned;
matched:
    out->slot=(uint16_t)(5-CX);enable(&w,0);CX=dec(&w,CX);
    if(CX)do{
        AX=rd(&w,(uint16_t)(BX+4));STORE(0x61a6,BX,AX);AX=rd(&w,(uint16_t)(BX+6));STORE(0x61ab,(uint16_t)(BX+2),AX);BX=add(&w,BX,4);CX=(uint16_t)(CX-1);
    }while(CX);
    STORE(0x61b3,BX,0);STORE(0x61b7,(uint16_t)(BX+2),0);enable(&w,1);w.r.bp=pop(&w);site=0x61be;
returned:
    out->halt_site=site;if(w.sp>0xfffc){stop(&w,5,site);goto done;}
    out->next_ip=pop(&w);out->next_segment=pop(&w);out->status=0;
done:
    out->current_sp=w.sp;out->returned=w.r;out->flags_word=w.f.word;out->flags_mask=w.f.mask;
}
