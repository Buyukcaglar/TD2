#include "td2ega_discard_wrappers.h"
#include <stddef.h>
typedef struct work {uint8_t *m;uint32_t bytes;uint16_t load,ss,sp,cs;td2ega_state_registers r;uint32_t calls,scans;td2ega_discard_object_result *o;} work;
static uint32_t address(uint16_t s,uint16_t o){return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(work *w,uint16_t s,uint16_t o){uint32_t a=address(s,o);return (uint16_t)(w->m[a]|((uint16_t)w->m[(a+1)&UINT32_C(0xfffff)]<<8));}
static void push(work *w,uint16_t v){uint32_t a;w->sp=(uint16_t)(w->sp-2);a=address(w->ss,w->sp);w->m[a]=(uint8_t)v;w->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++w->o->bus_writes;}
static uint16_t pop(work *w){uint16_t v=word(w,w->ss,w->sp);w->sp=(uint16_t)(w->sp+2);return v;}
static int invoke(work *w,uint16_t site,uint16_t next)
{
    td2ega_discard_object_result h;uint16_t expected=w->sp;
    w->o->next_segment=w->cs;w->o->next_ip=site;
    if(w->o->calls==w->calls){w->o->status=3;return 0;}
    ++w->o->calls;push(w,w->cs);push(w,next);
    td2ega_discard_object(w->m,w->bytes,w->load,w->ss,w->sp,&w->r,w->calls-w->o->calls,w->scans-w->o->scans-w->o->trims,&h);
    w->r=h.returned;w->sp=h.current_sp;w->o->calls+=h.calls;w->o->scans+=h.scans;w->o->trims+=h.trims;w->o->bus_writes+=h.bus_writes;w->o->next_segment=h.next_segment;w->o->next_ip=h.next_ip;
    if(h.status!=0){w->o->status=h.status;return 0;}
    if(h.next_segment!=w->cs || h.next_ip!=next || h.current_sp!=expected){w->o->status=1;return 0;}
    return 1;
}
void td2ega_discard_wrappers(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,uint16_t sp,uint16_t entry,const td2ega_state_registers *in,uint32_t calls,uint32_t scans,td2ega_discard_object_result *out)
{
    work w;uint16_t v,drop;uint32_t wide;
    if(out==NULL)return;
    *out=(td2ega_discard_object_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || entry>1 || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1)return;
    w=(work){m,bytes,load,ss,sp,(uint16_t)(load+0x6c9),*in,calls,scans,out};
    v=word(&w,w.r.registers.ds,entry?0x2f62:0x9b4);push(&w,v);v=word(&w,w.r.registers.ds,entry?0x2f60:0x9b2);push(&w,v);
    if(!invoke(&w,entry?0x38dc:0x8b,entry?0x38e1:0x90))goto done;
    if(entry){v=word(&w,w.r.registers.ds,0x2f6a);push(&w,v);v=word(&w,w.r.registers.ds,0x2f68);push(&w,v);if(!invoke(&w,0x38e9,0x38ee))goto done;}
    drop=entry?8:4;wide=(uint32_t)w.sp+drop;w.r.carry=(uint16_t)(wide>65535);w.sp=(uint16_t)wide;
    if(w.sp>0xfffc){out->status=5;out->next_segment=w.cs;out->next_ip=entry?0x38f1:0x93;goto done;}
    out->next_ip=pop(&w);out->next_segment=pop(&w);out->status=0;
done:
    out->current_sp=w.sp;out->returned=w.r;
}
