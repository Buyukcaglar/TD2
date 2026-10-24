#include "td2ega_relative_wait.h"
#include <stddef.h>
typedef struct work {
    uint8_t *m;uint32_t bytes;uint16_t load,cs,ss,sp;uint32_t limit;
    td2ega_state_registers r;td2ega_wait_roots_observer observer;void *context;
    td2ega_relative_wait_result *out;
} work;
static uint32_t address(uint16_t s,uint16_t o)
{return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(work *w,uint16_t s,uint16_t o)
{uint32_t a=address(s,o);return (uint16_t)(w->m[a]|((uint16_t)w->m[(a+1)&UINT32_C(0xfffff)]<<8));}
static void put(work *w,uint16_t s,uint16_t o,uint16_t v)
{uint32_t a=address(s,o);w->m[a]=(uint8_t)v;w->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++w->out->bus_writes;}
static void push(work *w,uint16_t v)
{w->sp=(uint16_t)(w->sp-2);put(w,w->ss,w->sp,v);}
static uint16_t pop(work *w)
{uint16_t v=word(w,w->ss,w->sp);w->sp=(uint16_t)(w->sp+2);return v;}
static int read_counter(work *w,uint16_t site)
{
    td2ega_wait_roots_counter_request request;td2ega_small_state_result result;uint16_t expected_sp=w->sp,ret=(uint16_t)(site+5);
    if(w->out->reads==w->limit){w->out->status=3;w->out->next_segment=w->cs;w->out->next_ip=site;return 0;}++w->out->reads;push(w,w->cs);push(w,ret);request=(td2ega_wait_roots_counter_request){site,w->cs,0xc692,w->ss,w->sp,w->r};
    if(w->observer!=NULL && !w->observer(w->context,w->m,&request)){w->out->status=4;w->out->next_segment=w->cs;w->out->next_ip=0xc692;return 0;}
    td2ega_small_state(w->m,w->bytes,w->load,w->ss,w->sp,4,&w->r,&result);w->r=result.returned;w->sp=result.current_sp;w->out->bus_writes+=result.writes;w->out->next_segment=result.next_segment;w->out->next_ip=result.next_ip;if(result.status!=0){w->out->status=result.status;return 0;}if(result.next_segment!=w->cs || result.next_ip!=ret || w->sp!=expected_sp){w->out->status=1;return 0;}return 1;
}
void td2ega_relative_wait(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,
    uint16_t sp,const td2ega_state_registers *in,td2ega_wait_roots_observer observer,
    void *context,uint32_t limit,td2ega_relative_wait_result *out)
{
    work w;uint32_t wide;
    if(out==NULL)return;
    *out=(td2ega_relative_wait_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || sp<32 || sp>UINT16_C(0xffe0) || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1)return;
    w=(work){m,bytes,load,(uint16_t)(load+0x6c9),ss,sp,limit,*in,observer,context,out};push(&w,w.r.bp);w.r.bp=w.sp;w.sp=(uint16_t)(w.sp-4);w.r.carry=0;
    if(!read_counter(&w,0xc6cb))goto finish;
    wide=(uint32_t)w.r.registers.ax+word(&w,ss,(uint16_t)(w.r.bp+6));w.r.registers.ax=(uint16_t)wide;w.r.carry=(uint16_t)(wide>65535);wide=(uint32_t)w.r.registers.dx+word(&w,ss,(uint16_t)(w.r.bp+8))+w.r.carry;w.r.registers.dx=(uint16_t)wide;w.r.carry=(uint16_t)(wide>65535);put(&w,ss,(uint16_t)(w.r.bp-4),w.r.registers.ax);put(&w,ss,(uint16_t)(w.r.bp-2),w.r.registers.dx);
    for(;;){
        if(!read_counter(&w,0xc6dc))goto finish;
        w.r.carry=(uint16_t)(w.r.registers.dx<word(&w,ss,(uint16_t)(w.r.bp-2)));if(w.r.carry)continue;w.r.carry=(uint16_t)(w.r.registers.ax<word(&w,ss,(uint16_t)(w.r.bp-4)));if(!w.r.carry)break;
    }
    w.sp=w.r.bp;w.r.bp=pop(&w);out->next_ip=pop(&w);out->next_segment=pop(&w);out->status=0;
finish:
    out->current_sp=w.sp;out->returned=w.r;
}
