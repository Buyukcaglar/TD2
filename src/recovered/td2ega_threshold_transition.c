#include "td2ega_threshold_transition.h"
#include <stddef.h>
typedef struct work {uint8_t *m;uint32_t bytes;uint16_t load,ss,sp,cs,zf;td2ega_state_registers r;const td2ega_threshold_transition_limits *limits;td2ega_threshold_transition_result *o;} work;
static uint32_t address(uint16_t s,uint16_t o){return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(work *w,uint16_t s,uint16_t o){uint32_t a=address(s,o);return (uint16_t)(w->m[a]|((uint16_t)w->m[(a+1)&UINT32_C(0xfffff)]<<8));}
static uint16_t rd(work *w,uint16_t o){return word(w,w->r.registers.ds,o);}
static uint8_t byte(work *w,uint16_t o){return w->m[address(w->r.registers.ds,o)];}
static void put(work *w,uint16_t s,uint16_t o,uint16_t v){uint32_t a=address(s,o);w->m[a]=(uint8_t)v;w->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++w->o->bus_writes;}
static void wr(work *w,uint16_t o,uint16_t v){put(w,w->r.registers.ds,o,v);}
static void wb(work *w,uint16_t o,uint8_t v){w->m[address(w->r.registers.ds,o)]=v;++w->o->bus_writes;}
static uint16_t pop(work *w){uint16_t v=word(w,w->ss,w->sp);w->sp=(uint16_t)(w->sp+2);return v;}
static int32_t sw(uint16_t v){return v<0x8000?v:(int32_t)v-65536;}
static uint16_t sub(work *w,uint16_t a,uint16_t b){uint16_t v=(uint16_t)(a-b);w->r.carry=(uint16_t)(a<b);w->zf=(uint16_t)(v==0);return v;}
static uint16_t add(work *w,uint16_t a,uint16_t b){uint32_t v=(uint32_t)a+b;w->r.carry=(uint16_t)(v>65535);w->zf=(uint16_t)((uint16_t)v==0);return (uint16_t)v;}
static void cmp(work *w,uint16_t a,uint16_t b){w->r.carry=(uint16_t)(a<b);w->zf=(uint16_t)(a==b);}
static int test(work *w,uint16_t a,uint16_t mask){w->r.carry=0;w->zf=(uint16_t)((a&mask)==0);return !w->zf;}
#define AX w.r.registers.ax
#define BX w.r.registers.bx
#define CX w.r.registers.cx
#define DX w.r.registers.dx
#define SI w.r.registers.si
#define BP w.r.bp
#define CF w.r.carry
void td2ega_threshold_transition(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,uint16_t sp,const td2ega_state_registers *in,const td2ega_threshold_transition_limits *limits,td2ega_threshold_transition_result *out)
{
    work w;uint16_t v,ret,expected;uint32_t product;int64_t wide,q,remainder;td2ega_control_bus_result h;
    if(out==NULL)return;
    *out=(td2ega_threshold_transition_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || limits==NULL || sp<20 || sp>UINT16_C(0xffe0) || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1)return;
    w=(work){m,bytes,load,ss,sp,(uint16_t)(load+0x6c9),0,*in,limits,out};DX=(uint16_t)((DX&0xff00)|byte(&w,0x5491));AX=rd(&w,0x3332);test(&w,AX,0xffff);
    if(sw(AX)<0){
        if(test(&w,DX,0x80))BX=0xfe70;else{BX=0xfe0c;if(test(&w,DX,1))BX=0xfc7c;}
        v=rd(&w,0x3334);cmp(&w,v,BX);if(sw(v)>=sw(BX))goto root;
        if(test(&w,DX,0x80))goto negative_state;
        if(test(&w,DX,0x20)){wb(&w,0x33d4,1);BX=sub(&w,BX,150);goto transition;}
        if(!test(&w,DX,0x10))goto control;
negative_state:
        BX=sub(&w,BX,0xffce);goto state2;
    }
    if(test(&w,DX,0x80))BX=400;else{BX=500;if(test(&w,DX,1))BX=900;}
    v=rd(&w,0x3336);cmp(&w,v,BX);if(sw(v)<=sw(BX))goto root;
    if(test(&w,DX,0x80))goto positive_state;
    if(test(&w,DX,4)){wb(&w,0x33d4,2);BX=sub(&w,BX,0xffba);goto transition;}
    if(test(&w,DX,2)){
positive_state:
        BX=sub(&w,BX,130);goto state2;
    }
    SI=0;CF=0;w.zf=1;DX=rd(&w,0x52ca);DX=sub(&w,DX,0x3b33);
    for(;;){
        out->next_segment=w.cs;out->next_ip=0x4c3e;if(out->rows==limits->rows){out->status=3;goto done;}++out->rows;
        v=rd(&w,(uint16_t)(SI+0x37a6));cmp(&w,v,0);if(v==0)goto control;
        BP=rd(&w,(uint16_t)(SI+0x37a8));cmp(&w,DX,BP);if(DX<=BP)break;SI=add(&w,SI,8);
    }
    AX=rd(&w,(uint16_t)(SI+0x37a6));DX=sub(&w,DX,AX);if(CF)goto control;BP=sub(&w,BP,AX);AX=rd(&w,(uint16_t)(SI+0x37ac));CX=rd(&w,(uint16_t)(SI+0x37aa));AX=sub(&w,AX,CX);wide=(int64_t)sw(AX)*sw(DX);AX=(uint16_t)wide;DX=(uint16_t)((uint64_t)wide>>16);CF=(uint16_t)(wide<-32768 || wide>32767);out->next_segment=w.cs;out->next_ip=0x4c68;
    if(BP==0){out->status=4;goto done;}q=wide/sw(BP);if(q<-32768 || q>32767){out->status=4;goto done;}remainder=wide%sw(BP);AX=(uint16_t)q;DX=(uint16_t)remainder;AX=add(&w,AX,CX);v=AX;AX=(uint16_t)(AX<<1);CF=(uint16_t)(v>>15);w.zf=(uint16_t)(AX==0);BX=add(&w,BX,AX);v=rd(&w,0x3334);cmp(&w,v,BX);if(sw(v)<sw(BX))goto control;wb(&w,0x33d4,4);
transition:
    wr(&w,0x33d0,BX);AX=0;CF=0;w.zf=1;wr(&w,0x33d2,AX);wr(&w,0x33ce,AX);wb(&w,0x33b2,0);wb(&w,0x336f,0);goto root;
state2:
    wr(&w,0x52cc,BX);wb(&w,0x5490,2);goto root;
control:
    DX=1000;expected=w.sp;w.sp=(uint16_t)(w.sp-2);put(&w,w.ss,w.sp,0x4c84);td2ega_control_bus(w.m,w.bytes,w.load,w.ss,w.sp,4,&w.r,w.limits->control_calls,&h);w.r=h.returned;w.sp=h.current_sp;out->control_calls=h.calls;out->bus_writes+=h.bus_writes;out->next_segment=h.next_segment;out->next_ip=h.next_ip;
    if(h.status!=0){out->status=h.status;goto done;}if(h.next_segment!=w.cs || h.next_ip!=0x4c84 || w.sp!=expected){out->status=1;goto done;}
    /* Literal45FC finalZF: zerochange return, selectorOR, orMUL-high CMP800.
     * These operands areunchangedaftertheiractualread in thisflatRAMfamily. */
    if(h.calls==0 || byte(&w,0x2f56)==0)w.zf=1;else{product=(uint32_t)rd(&w,0x3328)*rd(&w,0x52ce);w.zf=(uint16_t)((product>>16)==800);}
root:
    ret=pop(&w);out->status=0;out->next_segment=w.cs;out->next_ip=ret;out->zero_flag=w.zf;out->flags_valid=1;
done:
    out->current_sp=w.sp;out->returned=w.r;
}
