#include "td2ega_discard_object.h"
#include <stddef.h>
typedef struct work {uint8_t *m;uint16_t load,ss,sp,cs;td2ega_state_registers r;uint32_t call_limit,scan_limit;td2ega_discard_object_result *o;} work;
static uint32_t address(uint16_t s,uint16_t o){return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(work *w,uint16_t s,uint16_t o){uint32_t a=address(s,o);return (uint16_t)(w->m[a]|((uint16_t)w->m[(a+1)&UINT32_C(0xfffff)]<<8));}
static void put(work *w,uint16_t s,uint16_t o,uint16_t v){uint32_t a=address(s,o);w->m[a]=(uint8_t)v;w->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++w->o->bus_writes;}
static void push(work *w,uint16_t v){w->sp=(uint16_t)(w->sp-2);put(w,w->ss,w->sp,v);}
static uint16_t pop(work *w){uint16_t v=word(w,w->ss,w->sp);w->sp=(uint16_t)(w->sp+2);return v;}
static uint16_t sub(work *w,uint16_t a,uint16_t b){w->r.carry=(uint16_t)(a<b);return (uint16_t)(a-b);}
static int scan(work *w,uint16_t site,int trim){w->o->next_segment=w->cs;w->o->next_ip=site;if(w->o->scans+w->o->trims==w->scan_limit){w->o->status=3;return 0;}if(trim)++w->o->trims;else ++w->o->scans;return 1;}
#define AX w->r.registers.ax
#define SI w->r.registers.si
#define DI w->r.registers.di
#define DS w->r.registers.ds
#define BP w->r.bp
static int discard(work *w)
{
    uint16_t a,b;
    push(w,BP);BP=w->sp;push(w,SI);push(w,DI);
    AX=word(w,w->ss,(uint16_t)(BP+8));SI=word(w,DS,0x6c68);
    for(;;){
        if(!scan(w,0x749c,0))return 0;
        b=word(w,DS,0x6c66);(void)sub(w,SI,b);
        if(SI==b){a=word(w,w->ss,(uint16_t)(BP+8));push(w,a);AX=0x65a5;push(w,AX);w->o->status=6;w->o->next_segment=w->cs;w->o->next_ip=0x74b3;return 0;}
        b=word(w,DS,(uint16_t)(SI+0xe));(void)sub(w,AX,b);if(AX==b)break;
        SI=sub(w,SI,0x12);
    }
    put(w,DS,(uint16_t)(SI+0x10),0);
    b=word(w,DS,0x6c68);(void)sub(w,SI,b);
    if(SI==b){
        do{if(!scan(w,0x74c3,1))return 0;SI=sub(w,SI,0x12);a=word(w,DS,(uint16_t)(SI+0x10));w->r.carry=0;}while(a==0);
        put(w,DS,0x6c68,SI);
    }
    DI=pop(w);SI=pop(w);BP=pop(w);
    if(w->sp>0xfffc){w->o->status=5;w->o->next_segment=w->cs;w->o->next_ip=0x74d3;return 0;}
    w->o->next_ip=pop(w);w->o->next_segment=pop(w);return 1;
}
#undef AX
#undef SI
#undef DI
#undef DS
#undef BP
void td2ega_discard_object(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,uint16_t sp,const td2ega_state_registers *in,uint32_t calls,uint32_t scans,td2ega_discard_object_result *out)
{
    work w;uint32_t wide;uint16_t expected;
    if(out==NULL)return;
    *out=(td2ega_discard_object_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1)return;
    w=(work){m,load,ss,sp,(uint16_t)(load+0x6c9),*in,calls,scans,out};
    push(&w,w.r.bp);w.r.bp=w.sp;push(&w,w.r.registers.ds);push(&w,w.r.registers.si);push(&w,w.r.registers.di);
    w.r.registers.es=word(&w,ss,(uint16_t)(w.r.bp+8));w.r.registers.di=word(&w,ss,(uint16_t)(w.r.bp+6));
    w.r.registers.ds=word(&w,w.r.registers.es,(uint16_t)(w.r.registers.di+2));w.r.registers.si=word(&w,w.r.registers.es,w.r.registers.di);
    w.r.registers.ax=word(&w,w.r.registers.ds,(uint16_t)(w.r.registers.si+2));wide=(uint32_t)w.r.registers.ax+0xd;w.r.registers.ax=(uint16_t)wide;w.r.carry=(uint16_t)((w.r.registers.ax>>15)&1);w.r.registers.ax=(uint16_t)(w.r.registers.ax<<1);
    w.r.registers.bx=word(&w,w.cs,0xb269);w.r.registers.bx=sub(&w,w.r.registers.bx,w.r.registers.ax);put(&w,w.cs,0xb269,w.r.registers.bx);
    push(&w,w.r.registers.ds);push(&w,w.r.registers.si);w.r.registers.ds=word(&w,ss,(uint16_t)(w.r.bp-2));expected=w.sp;
    if(out->calls==w.call_limit){out->status=3;out->next_segment=w.cs;out->next_ip=0x7858;goto done;}
    ++out->calls;push(&w,w.cs);push(&w,0x785d);if(!discard(&w))goto done;
    if(out->next_segment!=w.cs || out->next_ip!=0x785d || w.sp!=expected){out->status=1;goto done;}
    wide=(uint32_t)w.sp+4;w.r.carry=(uint16_t)(wide>65535);w.sp=(uint16_t)wide;
    w.r.registers.di=pop(&w);w.r.registers.si=pop(&w);w.r.registers.ds=pop(&w);w.r.bp=pop(&w);
    if(w.sp>0xfffc){out->status=5;out->next_segment=w.cs;out->next_ip=0x7864;goto done;}
    out->next_ip=pop(&w);out->next_segment=pop(&w);out->status=0;
done:
    out->current_sp=w.sp;out->returned=w.r;
}
