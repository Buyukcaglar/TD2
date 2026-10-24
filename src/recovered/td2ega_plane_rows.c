#include "td2ega_plane_rows.h"
#include <stddef.h>
typedef struct row_context {
    uint8_t *m;uint16_t load,ss,sp;uint32_t limit;
    td2ega_state_registers r;td2ega_plane_rows_result *out;
} row_context;
static uint32_t address(uint16_t s,uint16_t o)
{ return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff); }
static uint16_t word(const uint8_t *m,uint16_t s,uint16_t o)
{ uint32_t a=address(s,o);return (uint16_t)(m[a]|((uint16_t)m[(a+1)&UINT32_C(0xfffff)]<<8)); }
static uint16_t read(row_context *c,uint16_t o)
{ return word(c->m,c->r.registers.ds,o); }
static void put(row_context *c,uint16_t o,uint16_t v)
{ uint32_t a=address(c->r.registers.ds,o);c->m[a]=(uint8_t)v;c->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8); }
static int32_t sw(uint16_t v)
{ return v<UINT16_C(0x8000)?v:(int32_t)v-INT32_C(65536); }
static int span(row_context *c)
{
    td2ega_plane_span_result r;
    if (c->out->calls==c->limit) { c->out->status=3;return -1; }
    ++c->out->calls;
    td2ega_plane_span(c->m,UINT32_C(0x100000),c->load,c->ss,(uint16_t)(c->sp-2),0,&c->r,NULL,NULL,&r);
    c->r=r.returned;c->out->writes+=r.writes;
    if (r.status==0)return 0;
    if (r.status==1) {
        ++c->out->continuations;
        if (r.next_ip==UINT16_C(0x28bd))return 1;
        c->out->status=1;c->out->next_ip=r.next_ip;return -1;
    }
    c->out->status=r.status;return -1;
}
void td2ega_plane_rows(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,
    uint16_t sp,const td2ega_state_registers *in,uint32_t limit,
    td2ega_plane_rows_result *out)
{
    row_context c;uint16_t v,old;int disposition;
    if (out==NULL)return;
    *out=(td2ega_plane_rows_result){0};out->status=2;
    if (m==NULL || bytes<UINT32_C(0x100000) || in==NULL || sp<258 || sp>UINT16_C(0xfff0) || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1)return;
    c=(row_context){m,load,ss,sp,limit,*in,out};out->current_sp=sp;
#define R c.r.registers
#define W(o) read(&c,(uint16_t)(o))
#define CALL() do { disposition=span(&c);if(disposition<0)goto finish;if(disposition>0)goto advance; } while(0)
    R.es=W(0x2a26);R.si=W(0x2c2a);c.r.carry=(uint16_t)(R.si>>15);R.si=(uint16_t)(R.si<<1);R.direction=0;R.bx=R.si;v=W(0x2a28);old=R.bx;R.bx=(uint16_t)(R.bx+v);c.r.carry=(uint16_t)(R.bx<old);R.di=word(m,(uint16_t)(load+0x6c9),R.bx);
    do {
        ++out->iterations;R.dx=0;c.r.carry=0;put(&c,0x9be,0);put(&c,0x9c0,0);c.r.carry=0;
        if (W(R.si+0xd5c)&0x20) {
            R.bx=W(0x5350);v=W(0x2c86);c.r.carry=(uint16_t)(R.si<v);
            if (sw(R.si)<sw(v))goto first_value;
            R.ax=W(0x2c2e);v=W(R.si+0x9c4);c.r.carry=(uint16_t)(R.ax<v);
            if (sw(R.ax)>=sw(v))goto first_value;
            CALL();
        }
        R.bx=W(0x534a);
first_value:
        R.ax=W(R.si+0x9c4);CALL();R.bx=W(0x534e);R.ax=W(R.si+0xa7c);CALL();R.bx=7;R.ax=W(R.si+0xb34);CALL();R.bx=W(0x534e);R.ax=W(R.si+0xbec);CALL();c.r.carry=0;
        if (W(R.si+0xd5c)&4) {
            R.bx=W(0x534c);v=W(0x2c88);c.r.carry=(uint16_t)(R.si<v);
            if (sw(R.si)>=sw(v)) { R.ax=W(0x2c68);v=W(R.si+0xbec);c.r.carry=(uint16_t)(R.ax<v);if(sw(R.ax)>=sw(v)) { CALL(); } }
            R.bx=W(0x5350);
        } else { R.bx=W(0x534c);R.ax=W(R.si+0xca4);CALL();R.bx=W(0x5352); }
        R.ax=80;CALL();
advance:
        R.si=(uint16_t)(R.si+2);c.r.carry=(uint16_t)(R.si<34);
    } while (R.si!=34);
    out->status=0;out->current_sp=(uint16_t)(sp+2);
finish:
    out->returned=c.r;
#undef R
#undef W
#undef CALL
}
