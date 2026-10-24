#include "td2ega_copy_config.h"
#include <stddef.h>
typedef struct context {
    uint8_t *m;uint16_t ss,sp,cs;td2ega_state_registers r;
    td2ega_copy_config_result *out;
} context;
static uint32_t address(uint16_t s,uint16_t o)
{return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(context *c,uint16_t s,uint16_t o)
{uint32_t at=address(s,o);return (uint16_t)(c->m[at]|((uint16_t)c->m[(at+1)&UINT32_C(0xfffff)]<<8));}
static void put(context *c,uint16_t s,uint16_t o,uint16_t v)
{uint32_t at=address(s,o);c->m[at]=(uint8_t)v;c->m[(at+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++c->out->writes;}
static void push(context *c,uint16_t v)
{c->sp=(uint16_t)(c->sp-2);put(c,c->ss,c->sp,v);}
static uint16_t pop(context *c)
{uint16_t v=word(c,c->ss,c->sp);c->sp=(uint16_t)(c->sp+2);return v;}
void td2ega_copy_config(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,
    uint16_t sp,uint16_t entry,const td2ega_state_registers *in,
    uint32_t limit,td2ega_copy_config_result *out)
{
    context c;uint16_t v;
    if(out==NULL)return;
    *out=(td2ega_copy_config_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || entry>2 || sp<16 || sp>UINT16_C(0xffe0) || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1)return;
    c=(context){m,ss,sp,(uint16_t)(load+0x6c9),*in,out};
#define R c.r.registers
#define ARG(n) word(&c,c.ss,(uint16_t)(c.r.bp+(n)))
    push(&c,c.r.bp);c.r.bp=c.sp;push(&c,R.ds);
    if(entry==2){push(&c,R.di);push(&c,R.si);}else{push(&c,R.si);push(&c,R.di);}
    R.direction=0;
    if(entry!=2)R.ds=ARG(8);
    R.si=ARG(6);
    if(entry==0){R.es=ARG(12);R.di=ARG(10);R.cx=ARG(14);}
    else{R.cx=(uint16_t)(entry==1?13:26);R.ax=c.cs;R.es=R.ax;R.di=0xaf3a;}
    while(R.cx!=0){
        if(out->work==limit){out->status=3;goto finish;}
        ++out->work;
        if(entry==0){v=c.m[address(R.ds,R.si)];c.m[address(R.es,R.di)]=(uint8_t)v;++out->writes;R.si=(uint16_t)(R.si+1);R.di=(uint16_t)(R.di+1);}
        else{v=word(&c,R.ds,R.si);put(&c,R.es,R.di,v);R.si=(uint16_t)(R.si+2);R.di=(uint16_t)(R.di+2);}
        --R.cx;
    }
    if(entry==2){R.si=pop(&c);R.di=pop(&c);}else{R.di=pop(&c);R.si=pop(&c);}
    R.ds=pop(&c);c.r.bp=pop(&c);out->next_ip=pop(&c);out->next_segment=pop(&c);out->status=0;
finish:
    out->current_sp=c.sp;out->returned=c.r;
#undef R
#undef ARG
}
