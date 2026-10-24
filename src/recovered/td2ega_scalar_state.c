#include "td2ega_scalar_state.h"
#include <stddef.h>
typedef struct context {
    uint8_t *m;uint16_t ss,sp;td2ega_state_registers r;
    td2ega_scalar_state_result *out;
} context;
static uint32_t address(uint16_t s,uint16_t o)
{return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(context *c,uint16_t s,uint16_t o)
{uint32_t a=address(s,o);return (uint16_t)(c->m[a]|((uint16_t)c->m[(a+1)&UINT32_C(0xfffff)]<<8));}
static void put(context *c,uint16_t s,uint16_t o,uint16_t v)
{uint32_t a=address(s,o);c->m[a]=(uint8_t)v;c->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++c->out->bus_writes;}
static void push(context *c,uint16_t v)
{c->sp=(uint16_t)(c->sp-2);put(c,c->ss,c->sp,v);}
static uint16_t pop(context *c)
{uint16_t v=word(c,c->ss,c->sp);c->sp=(uint16_t)(c->sp+2);return v;}
static int32_t sw(uint16_t v)
{return v<0x8000?v:(int32_t)v-65536;}
void td2ega_scalar_state(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,
    uint16_t sp,uint16_t entry,const td2ega_state_registers *in,
    td2ega_scalar_state_result *out)
{
    context c;uint16_t v,old;uint32_t at;uint8_t ch;(void)load;
    if(out==NULL)return;
    *out=(td2ega_scalar_state_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || entry>3 || sp<16 || sp>UINT16_C(0xffe0) || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1)return;
    c=(context){m,ss,sp,*in,out};
#define R c.r.registers
#define W(offset) word(&c,R.ds,offset)
    if(entry<2){push(&c,c.r.bp);c.r.bp=c.sp;}
    switch(entry){
    case 0:
        at=address(c.ss,(uint16_t)(c.r.bp+6));ch=c.m[at];c.r.carry=(uint16_t)(ch<0x61);
        if(ch>=0x61 && ch<=0x7a){ch=(uint8_t)(ch-0x20);c.m[at]=ch;++out->bus_writes;c.r.carry=0;}
        R.ax=(uint16_t)(ch<128?ch:(0xff00|ch));break;
    case 1:
        R.bx=word(&c,c.ss,(uint16_t)(c.r.bp+6));v=W(0x6da2);c.r.carry=0;
        if(sw(R.bx)<sw(v) && sw(R.bx)>=0 && (c.m[address(R.ds,(uint16_t)(R.bx+0x6da4))]&0x40)!=0)R.ax=1;else R.ax=0;break;
    case 2:
        c.r.carry=0;
        if(W(0x83e4)==0)R.ax=1;
        else{v=W(0x83da);if(sw(v)>0){put(&c,R.ds,0x83da,(uint16_t)(v-1));R.ax=1;}else R.ax=0;}break;
    case 3:
        R.bx=W(0x8a22);old=R.bx;R.bx=(uint16_t)(R.bx<<1);c.r.carry=(uint16_t)(old>>15);put(&c,R.ds,(uint16_t)(R.bx+0x40),0);put(&c,R.ds,0x8a22,0);put(&c,R.ds,0x8a8c,0);R.ax=W(0x8c9e);put(&c,R.ds,0x8a1c,R.ax);break;
    }
    if(entry<2){c.sp=c.r.bp;c.r.bp=pop(&c);}
    out->next_ip=pop(&c);out->next_segment=pop(&c);out->status=0;out->current_sp=c.sp;out->returned=c.r;
#undef R
#undef W
}
