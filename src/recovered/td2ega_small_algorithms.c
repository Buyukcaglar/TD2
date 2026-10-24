#include "td2ega_small_algorithms.h"
#include <stddef.h>
typedef struct work {
    uint8_t *m;uint16_t cs,ss,sp;uint32_t limit;
    td2ega_state_registers r;td2ega_small_algorithms_result *out;
} work;
static uint32_t address(uint16_t s,uint16_t o)
{return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(work *w,uint16_t s,uint16_t o)
{uint32_t a=address(s,o);return (uint16_t)(w->m[a]|((uint16_t)w->m[(a+1)&UINT32_C(0xfffff)]<<8));}
static void put(work *w,uint16_t s,uint16_t o,uint16_t v,unsigned size)
{uint32_t a=address(s,o);w->m[a]=(uint8_t)v;if(size==2)w->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++w->out->bus_writes;}
static void push(work *w,uint16_t v)
{w->sp=(uint16_t)(w->sp-2);put(w,w->ss,w->sp,v,2);}
static uint16_t pop(work *w)
{uint16_t v=word(w,w->ss,w->sp);w->sp=(uint16_t)(w->sp+2);return v;}
static int32_t signedword(uint16_t v)
{return v&0x8000?(int32_t)v-65536:(int32_t)v;}
static int step(work *w,uint16_t ip)
{if(w->out->iterations==w->limit){w->out->status=3;w->out->next_segment=w->cs;w->out->next_ip=ip;return 0;}++w->out->iterations;return 1;}
void td2ega_small_algorithms(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,
    uint16_t sp,uint16_t entry,const td2ega_state_registers *in,uint32_t limit,
    td2ega_small_algorithms_result *out)
{
    work w;uint16_t bound,old,value;uint32_t wide;int32_t difference;uint8_t flag,character,divisor;
    if(out==NULL)return;
    *out=(td2ega_small_algorithms_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || entry>2 || sp<32 || sp>UINT16_C(0xffe0) || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1)return;
    w=(work){m,(uint16_t)(load+(entry==2?0x432:0x6c9)),ss,sp,limit,*in,out};
    if(entry==0){
        flag=m[address(w.r.registers.ds,0x133c)];w.r.carry=0;
        if(flag&0x88){
            if(signedword(w.r.registers.ax)<0)w.r.registers.ax=0;
            else if(signedword(w.r.registers.si)>signedword(word(&w,w.r.registers.ds,0x1310))){bound=word(&w,w.r.registers.ds,0x12d0);if(signedword(w.r.registers.ax)>signedword(bound))w.r.registers.ax=word(&w,w.r.registers.ds,0x12d0);}
            else if(signedword(w.r.registers.ax)>320)w.r.registers.ax=320;
        }
        flag=m[address(w.r.registers.ds,0x133c)];w.r.carry=0;
        if(flag&0xc0){
            w.r.carry=(uint16_t)(w.r.registers.ax<320);
            if(signedword(w.r.registers.ax)>320)w.r.registers.ax=320;
            else if(signedword(w.r.registers.si)<signedword(word(&w,w.r.registers.ds,0x130e)))w.r.carry=0;
            else{bound=word(&w,w.r.registers.ds,0x130a);w.r.carry=(uint16_t)(w.r.registers.ax<bound);if(signedword(w.r.registers.ax)<signedword(bound))w.r.registers.ax=word(&w,w.r.registers.ds,0x130a);}
        }
    }else if(entry==1){
        old=w.r.registers.cx;difference=signedword(old)-signedword(w.r.registers.dx);w.r.registers.cx=(uint16_t)(old-w.r.registers.dx);
        if(difference<=0){w.r.carry=(uint16_t)(w.r.registers.cx<0xfffe);w.r.registers.ax=signedword(w.r.registers.cx)<-2?100:90;goto returned;}
        w.r.carry=(uint16_t)(w.r.registers.cx<60);if(w.r.registers.cx>60){w.r.registers.ax=100;goto returned;}
        w.r.carry=(uint16_t)(w.r.registers.cx<3);if(w.r.registers.cx<3){w.r.registers.ax=1;goto returned;}
        old=w.r.registers.ax;difference=signedword(old)-signedword(w.r.registers.bx);w.r.registers.ax=(uint16_t)(old-w.r.registers.bx);w.r.carry=(uint16_t)(old<w.r.registers.bx);if(difference<0){w.r.registers.ax=100;goto returned;}
        w.r.registers.cx=(uint16_t)((w.r.registers.cx<<8)|(w.r.registers.cx>>8));w.r.registers.cx>>=1;wide=(uint32_t)w.r.registers.ax+5;w.r.registers.ax=(uint16_t)wide;w.r.carry=0;if(w.r.registers.ax&0xff00)w.r.registers.ax=(uint16_t)((w.r.registers.ax&0xff00)|0xff);w.r.carry=(uint16_t)((w.r.registers.cx>>8)<(uint8_t)w.r.registers.ax);
        if((w.r.registers.cx>>8)>=(uint8_t)w.r.registers.ax){w.r.registers.ax=100;goto returned;}
        old=w.r.registers.ax;w.r.registers.ax=w.r.registers.cx;w.r.registers.cx=old;divisor=(uint8_t)w.r.registers.cx;w.r.registers.ax=(uint16_t)(w.r.registers.ax/divisor);w.r.carry=0;
    }else{
        push(&w,w.r.bp);w.r.bp=w.sp;w.sp=(uint16_t)(w.sp-2);w.r.carry=0;push(&w,w.r.registers.si);put(&w,ss,(uint16_t)(w.r.bp-2),0,2);
        for(;;){
            if(!step(&w,0x72))goto finish;
            w.r.registers.si=word(&w,ss,(uint16_t)(w.r.bp-2));w.r.registers.si=(uint16_t)(w.r.registers.si+word(&w,ss,(uint16_t)(w.r.bp+6)));character=m[address(w.r.registers.ds,w.r.registers.si)];w.r.carry=0;if(character==0)break;w.r.carry=(uint16_t)(character<0x5f);if(character==0x5f)put(&w,w.r.registers.ds,w.r.registers.si,0x20,1);value=(uint16_t)(word(&w,ss,(uint16_t)(w.r.bp-2))+1);put(&w,ss,(uint16_t)(w.r.bp-2),value,2);
        }
        for(;;){
            value=word(&w,ss,(uint16_t)(w.r.bp-2));w.r.carry=(uint16_t)(value<18);if(signedword(value)>=18)break;if(!step(&w,0x90))goto finish;w.r.registers.bx=word(&w,ss,(uint16_t)(w.r.bp-2));w.r.registers.si=word(&w,ss,(uint16_t)(w.r.bp+6));put(&w,w.r.registers.ds,(uint16_t)(w.r.registers.bx+w.r.registers.si),0x20,1);value=(uint16_t)(word(&w,ss,(uint16_t)(w.r.bp-2))+1);put(&w,ss,(uint16_t)(w.r.bp-2),value,2);
        }
        if(!step(&w,0x9b))goto finish;
        w.r.registers.bx=word(&w,ss,(uint16_t)(w.r.bp-2));w.r.registers.si=word(&w,ss,(uint16_t)(w.r.bp+6));put(&w,w.r.registers.ds,(uint16_t)(w.r.registers.bx+w.r.registers.si),0,1);w.r.registers.si=pop(&w);w.sp=w.r.bp;w.r.bp=pop(&w);
    }
returned:
    out->next_ip=pop(&w);out->next_segment=w.cs;if(entry==2)out->next_segment=pop(&w);out->status=0;
finish:
    out->current_sp=w.sp;out->returned=w.r;
}
