#include "td2ega_small_state.h"
#include <stddef.h>

typedef struct context {
    uint8_t *m;uint16_t load,ss,sp,cs;td2ega_state_registers r;
    td2ega_small_state_result *out;
} context;
static uint32_t address(uint16_t s,uint16_t o)
{return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint8_t byte(context *c,uint16_t s,uint16_t o)
{++c->out->reads;return c->m[address(s,o)];}
static uint16_t word(context *c,uint16_t s,uint16_t o)
{uint32_t at=address(s,o);++c->out->reads;return (uint16_t)(c->m[at]|((uint16_t)c->m[(at+1)&UINT32_C(0xfffff)]<<8));}
static void put(context *c,uint16_t s,uint16_t o,uint16_t v)
{uint32_t at=address(s,o);c->m[at]=(uint8_t)v;c->m[(at+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++c->out->writes;}
static void push(context *c,uint16_t v)
{c->sp=(uint16_t)(c->sp-2);put(c,c->ss,c->sp,v);}
static uint16_t pop(context *c)
{uint16_t v=word(c,c->ss,c->sp);c->sp=(uint16_t)(c->sp+2);return v;}
static void frame(context *c)
{push(c,c->r.bp);c->r.bp=c->sp;}
static void counter(context *c)
{c->r.registers.interrupts_enabled=0;c->r.registers.ax=word(c,c->r.registers.ds,0x5e90);c->r.registers.dx=word(c,c->r.registers.ds,0x5e92);c->r.registers.interrupts_enabled=1;}
void td2ega_small_state(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,
    uint16_t sp,uint16_t entry,const td2ega_state_registers *in,
    td2ega_small_state_result *out)
{
    context c;uint16_t v,old;uint32_t sum;unsigned i;int near_return;
    if(out==NULL)return;
    *out=(td2ega_small_state_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || entry>13 || sp<16 || sp>UINT16_C(0xffe0) || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1)return;
    c=(context){m,load,ss,sp,(uint16_t)(load+(entry==6 || entry==8 || entry==9 || entry==11?0x13a8:entry==10?0x0267:0x06c9)),*in,out};near_return=entry==1 || entry==8;
#define R c.r.registers
#define ARG(n) word(&c,c.ss,(uint16_t)(c.r.bp+(n)))
    switch(entry){
    case 0:case 1:break; /* 5D00far and4A18near no-op entries. */
    case 2:case 3:
        if(entry==3)frame(&c);
        R.ax=0x40;R.es=R.ax;R.ax=word(&c,R.es,0x046c);
        if(entry==3){v=ARG(6);c.r.carry=(uint16_t)(R.ax<v);R.ax=(uint16_t)(R.ax-v);c.r.bp=pop(&c);}break;
    case 4:counter(&c);break;
    case 5:
        frame(&c);push(&c,c.cs);push(&c,0xc6a4);counter(&c);v=pop(&c);v=pop(&c);(void)v;
        sum=(uint32_t)R.ax+ARG(6);R.ax=(uint16_t)sum;c.r.carry=(uint16_t)(sum>>16);sum=(uint32_t)R.dx+ARG(8)+c.r.carry;R.dx=(uint16_t)sum;c.r.carry=(uint16_t)(sum>>16);put(&c,R.ds,0x68d6,R.ax);put(&c,R.ds,0x68d8,R.dx);c.r.bp=pop(&c);break;
    case 6:
        R.cx=(uint8_t)R.cx;c.r.carry=0;
        while(R.cx!=0){c.r.carry=(uint16_t)(R.ax>>15);R.ax=(uint16_t)(R.ax<<1);old=R.dx;R.dx=(uint16_t)((R.dx<<1)|c.r.carry);c.r.carry=(uint16_t)(old>>15);--R.cx;}break;
    case 7:
        frame(&c);R.ax=ARG(8);put(&c,R.ds,0x6822,R.ax);R.ax=ARG(6);put(&c,R.ds,0x6820,R.ax);c.r.bp=pop(&c);break;
    case 8:
        R.ax=word(&c,R.ds,0x6d97);R.ax=(uint16_t)~R.ax;R.ax&=R.cx;R.cx=0;c.r.carry=0;if((R.ax&0x80)==0)R.cx=1;break;
    case 9:
        frame(&c);R.bx=ARG(6);c.r.carry=0;if(R.bx!=0){uint32_t at=address(R.ds,(uint16_t)(R.bx-2));v=byte(&c,R.ds,(uint16_t)(R.bx-2));c.m[at]=(uint8_t)(v|1);++out->writes;}c.sp=c.r.bp;c.r.bp=pop(&c);break;
    case 10:
        frame(&c);v=ARG(6);c.r.carry=(uint16_t)(v<1);R.ax=(uint16_t)(v==1?0x7738:0x7739);c.r.bp=pop(&c);break;
    case 11:
        R.cx=pop(&c);R.dx=pop(&c);R.ax=word(&c,R.ds,0x6dd4);c.r.carry=(uint16_t)(R.ax<c.sp);
        if(R.ax<c.sp){R.ax=(uint16_t)(R.ax-c.sp);c.r.carry=(uint16_t)(R.ax!=0);R.ax=(uint16_t)(0-R.ax);}else{R.ax=0;c.r.carry=0;}push(&c,R.dx);push(&c,R.cx);break;
    case 12:case 13:
        frame(&c);push(&c,R.di);push(&c,R.si);
        if(entry==12){R.si=0x6820;R.di=ARG(6);R.ax=R.ds;R.es=R.ax;}else{R.si=ARG(6);R.ax=R.ds;R.es=R.ax;R.di=0x6820;}
        R.direction=0;R.cx=11;
        for(i=0;i<11;++i){v=word(&c,R.ds,R.si);put(&c,R.es,R.di,v);R.si=(uint16_t)(R.si+2);R.di=(uint16_t)(R.di+2);--R.cx;}
        R.si=pop(&c);R.di=pop(&c);c.r.bp=pop(&c);break;
    }
    out->next_ip=pop(&c);out->next_segment=near_return?c.cs:pop(&c);out->status=0;out->current_sp=c.sp;out->returned=c.r;
#undef R
#undef ARG
}
