#include "td2ega_loop_prepare.h"
#include <stddef.h>
static uint32_t address(uint16_t s,uint16_t o)
{ return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff); }
static uint16_t word(const uint8_t *m,uint16_t s,uint16_t o)
{ uint32_t a=address(s,o);return (uint16_t)(m[a]|((uint16_t)m[(a+1)&UINT32_C(0xfffff)]<<8)); }
static void put(uint8_t *m,uint16_t s,uint16_t o,uint16_t v)
{ uint32_t a=address(s,o);m[a]=(uint8_t)v;m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8); }
static void delta(uint8_t *m,td2ega_state_registers *r)
{
    uint16_t low=r->registers.ax,high=r->registers.dx;
    uint32_t borrow=(uint32_t)r->registers.cx+(low<r->registers.bx?1U:0U);
    r->registers.ax=(uint16_t)(low-r->registers.bx);
    high=(uint16_t)(high-borrow);r->registers.dx=(uint16_t)(0-high);r->carry=(uint16_t)(high!=0);
    /* NEG8000 has SF=OF=1, so JGE skips adjustment despite a negative result. */
    if (high>0 && high<UINT16_C(0x8000)) {
        uint32_t sum=(uint32_t)r->registers.dx+word(m,r->registers.ds,UINT16_C(0x380d));
        r->registers.dx=(uint16_t)sum;r->carry=(uint16_t)(sum>>16);
    }
}
void td2ega_loop_prepare(uint8_t *m,uint32_t bytes,
    const td2ega_state_registers *in,uint32_t limit,
    td2ega_loop_prepare_result *out)
{
    td2ega_state_registers r;unsigned i,pass;uint16_t value,base,extent;
    if (out==NULL) return;
    *out=(td2ega_loop_prepare_result){0};out->status=2;
    if (m==NULL || bytes<UINT32_C(0x100000) || in==NULL || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1) return;
    r=*in;r.registers.ax=0;r.carry=0;r.registers.bx=r.registers.ds;r.registers.es=r.registers.bx;r.registers.di=UINT16_C(0x2c64);r.registers.cx=17;r.registers.direction=0;
    for (i=0;i<17;++i) { put(m,r.registers.es,r.registers.di,r.registers.ax);r.registers.di=(uint16_t)(r.registers.di+2);--r.registers.cx; }
    r.registers.ax=80;put(m,r.registers.ds,0x2c2e,80);put(m,r.registers.ds,0x2c2c,80);put(m,r.registers.ds,0x2c32,80);
    r.registers.ax=17;put(m,r.registers.ds,0x2c2a,17);put(m,r.registers.ds,0x2c30,17);
    r.registers.ax=m[address(r.registers.ds,0x5491)];
    m[address(r.registers.ds,0x2c97)]=(uint8_t)r.registers.ax;m[address(r.registers.ds,0x2c98)]=(uint8_t)r.registers.ax;m[address(r.registers.ds,0x2c9a)]=(uint8_t)r.registers.ax;m[address(r.registers.ds,0x2c9b)]=(uint8_t)r.registers.ax;
    r.registers.ax=word(m,r.registers.ds,0x533e);put(m,r.registers.ds,0x2c62,r.registers.ax);put(m,r.registers.ds,0x2c62,(uint16_t)(word(m,r.registers.ds,0x2c62)-1));
    r.registers.ax=(uint16_t)(0-word(m,r.registers.ds,0x2f48));put(m,r.registers.ds,0x2c24,r.registers.ax);
    r.registers.ax=word(m,r.registers.ds,0x52ca);put(m,r.registers.ds,0x2c26,r.registers.ax);
    r.registers.ax=word(m,r.registers.ds,0x52c8);put(m,r.registers.ds,0x2c28,r.registers.ax);
    value=word(m,r.registers.ds,0x52cc);value=(uint16_t)((value>>1)|(value&UINT16_C(0x8000)));r.registers.ax=(uint16_t)(0-value);put(m,r.registers.ds,0x2c20,r.registers.ax);
    r.registers.ax=(uint16_t)((r.registers.ax&UINT16_C(0xff00))|m[address(r.registers.ds,0x3375)]);m[address(r.registers.ds,0x2a1c)]=(uint8_t)r.registers.ax;
    r.registers.ax=word(m,r.registers.ds,0x2a1e);put(m,r.registers.ds,0x2c22,r.registers.ax);
    r.registers.bx=word(m,r.registers.ds,0x2c28);r.registers.cx=word(m,r.registers.ds,0x2c26);r.registers.si=0;r.registers.di=0;r.carry=0;
    for (pass=0;pass<2;++pass) {
        base=pass==0?UINT16_C(0x3813):UINT16_C(0x39a3);
        do {
            if (out->records==limit) { out->status=3;goto finish; }
            ++out->records;r.bp=word(m,r.registers.ds,(uint16_t)(r.registers.si+base));r.registers.ax=word(m,r.registers.ds,(uint16_t)(r.registers.si+base+4));r.registers.dx=word(m,r.registers.ds,(uint16_t)(r.registers.si+base+2));delta(m,&r);
            r.carry=(uint16_t)(r.registers.dx<25);
            if (r.registers.dx<=25) {
                r.carry=(uint16_t)(r.registers.dx>>15);r.registers.dx=(uint16_t)(r.registers.dx<<1);
                put(m,r.registers.ds,(uint16_t)(r.registers.di+0x27f6),r.registers.dx);put(m,r.registers.ds,(uint16_t)(r.registers.di+0x27f8),r.bp);
                r.registers.ax=word(m,r.registers.ds,(uint16_t)(r.registers.si+base+6));put(m,r.registers.ds,(uint16_t)(r.registers.di+0x27fa),r.registers.ax);
                r.registers.di=(uint16_t)(r.registers.di+8);
            }
            r.registers.si=(uint16_t)(r.registers.si+8);extent=word(m,r.registers.ds,pass==0?UINT16_C(0x5354):UINT16_C(0x5356));r.carry=(uint16_t)(r.registers.si<extent);
        } while (r.carry);
        if (pass==0) { r.registers.si=0;r.carry=0; }
    }
    put(m,r.registers.ds,0x28be,r.registers.di);
    r.registers.ax=word(m,r.registers.ds,0x52d0);r.registers.dx=word(m,r.registers.ds,0x52d2);delta(m,&r);
    r.carry=(uint16_t)(r.registers.dx>>15);r.registers.dx=(uint16_t)(r.registers.dx<<1);put(m,r.registers.ds,0x28c0,r.registers.dx);
    r.registers.ax=word(m,r.registers.ds,0x52d4);put(m,r.registers.ds,0x28c2,r.registers.ax);
    r.registers.ax=word(m,r.registers.ds,0x52d8);r.registers.dx=word(m,r.registers.ds,0x52da);delta(m,&r);
    r.carry=(uint16_t)(r.registers.dx>>15);r.registers.dx=(uint16_t)(r.registers.dx<<1);put(m,r.registers.ds,0x28c4,r.registers.dx);
    r.registers.ax=word(m,r.registers.ds,0x52dc);put(m,r.registers.ds,0x28c6,r.registers.ax);
    r.registers.ax=(uint16_t)((r.registers.ax&UINT16_C(0xff00))|m[address(r.registers.ds,0x33b8)]);m[address(r.registers.ds,0x2c9c)]=(uint8_t)r.registers.ax;
    r.registers.ax=(uint16_t)((r.registers.ax&UINT16_C(0xff00))|m[address(r.registers.ds,0x33b7)]);m[address(r.registers.ds,0x2c9d)]=(uint8_t)r.registers.ax;out->status=0;
finish:
    out->returned=r;
}
