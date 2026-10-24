#include "td2ega_small_platform.h"
#include <stddef.h>
typedef struct context {
    uint8_t *m;uint16_t load,ss,sp,cs;uint32_t limit;
    td2ega_state_registers r;td2ega_small_platform_service service;
    void *user;td2ega_small_platform_result *out;
} context;
static uint32_t address(uint16_t s,uint16_t o)
{return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(context *c,uint16_t s,uint16_t o)
{uint32_t a=address(s,o);return (uint16_t)(c->m[a]|((uint16_t)c->m[(a+1)&UINT32_C(0xfffff)]<<8));}
static void put(context *c,uint16_t s,uint16_t o,uint16_t v)
{uint32_t a=address(s,o);c->m[a]=(uint8_t)v;c->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);}
static void push(context *c,uint16_t v)
{c->sp=(uint16_t)(c->sp-2);put(c,c->ss,c->sp,v);}
static uint16_t pop(context *c)
{uint16_t v=word(c,c->ss,c->sp);c->sp=(uint16_t)(c->sp+2);return v;}
static void ah(context *c,uint16_t v)
{c->r.registers.ax=(uint16_t)((c->r.registers.ax&255)|((v&255)<<8));}
static int interrupt(context *c,uint16_t vector,uint16_t site)
{
    td2ega_small_platform_request q={0};td2ega_state_registers returned;
    if(c->out->calls==c->limit){c->out->status=3;return 0;}
    q.vector=vector;q.site=site;q.segment=c->cs;q.stack_segment=c->ss;q.stack_sp=c->sp;q.incoming=c->r;returned=c->r;++c->out->calls;
    if(!c->service(c->user,c->m,&q,&returned)){c->out->status=4;return 0;}
    if(returned.carry>1 || returned.registers.interrupts_enabled>1 || returned.registers.direction>1){c->out->status=2;return 0;}
    c->r=returned;return 1;
}
void td2ega_small_platform(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,
    uint16_t sp,uint16_t entry,const td2ega_state_registers *incoming,
    td2ega_small_platform_service service,void *user,uint32_t limit,
    td2ega_small_platform_result *out)
{
    context c;
    if(out==NULL)return;
    *out=(td2ega_small_platform_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || incoming==NULL || service==NULL || entry>4 || sp<16 || sp>UINT16_C(0xffe0) || incoming->carry>1 || incoming->registers.interrupts_enabled>1 || incoming->registers.direction>1)return;
    c=(context){m,load,ss,sp,(uint16_t)(load+(entry==2?0x13a8:0x06c9)),limit,*incoming,service,user,out};
#define R c.r.registers
#define INT(vector,site) do{if(!interrupt(&c,vector,site))goto finish;}while(0)
    if(entry==2 || entry==3){push(&c,c.r.bp);c.r.bp=c.sp;}
    switch(entry){
    case 0:
        ah(&c,0x19);INT(0x21,0x5d50);R.dx=(uint16_t)((R.dx&UINT16_C(0xff00))|(R.ax&255));ah(&c,0x0e);INT(0x21,0x5d56);ah(&c,0);c.r.carry=0;break;
    case 1:
        INT(0x11,0x5d74);R.cx=(uint16_t)((R.cx&UINT16_C(0xff00))|6);R.ax=(uint16_t)((R.ax&UINT16_C(0xff00))|((R.ax&255)>>6));ah(&c,0);c.r.carry=0;if(R.ax==0)R.ax=(uint16_t)(R.ax+1);R.ax=(uint16_t)(R.ax+1);break;
    case 2:
        ah(&c,0x19);INT(0x21,0x2e33);R.ax=(uint16_t)(R.ax+1);ah(&c,0);R.bx=word(&c,c.ss,(uint16_t)(c.r.bp+6));put(&c,R.ds,R.bx,R.ax);R.ax=0;c.r.carry=0;break;
    case 3:
        R.dx=word(&c,c.ss,(uint16_t)(c.r.bp+6));R.ax=0x4301;R.cx=2;INT(0x21,0x5d67);if(c.r.carry)R.ax=1;else{R.ax=0;c.r.carry=0;}break;
    case 4:
        ah(&c,0);INT(0x1a,0x5d30);R.cx&=0x3f3f;R.dx&=0x3f3f;R.cx|=0x8080;R.dx|=0x8080;c.r.carry=0;put(&c,R.ds,0x52c2,R.cx);put(&c,R.ds,0x52c4,R.dx);R.ax=0x52c2;break;
    }
    if(entry==2 || entry==3)c.r.bp=pop(&c);
    out->next_ip=pop(&c);out->next_segment=pop(&c);out->status=0;
finish:
    out->current_sp=c.sp;out->returned=c.r;
#undef R
#undef INT
}
