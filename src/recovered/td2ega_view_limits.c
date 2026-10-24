#include "td2ega_view_limits.h"
#include <stddef.h>
static uint32_t address(uint16_t s,uint16_t o)
{ return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff); }
static uint16_t word(const uint8_t *m,uint16_t s,uint16_t o)
{ uint32_t a=address(s,o);return (uint16_t)(m[a]|((uint16_t)m[(a+1)&UINT32_C(0xfffff)]<<8)); }
static void put(uint8_t *m,uint16_t s,uint16_t o,uint16_t v)
{ uint32_t a=address(s,o);m[a]=(uint8_t)v;m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8); }
static int32_t signed_word(uint16_t v)
{ return v<UINT16_C(0x8000)?(int32_t)v:(int32_t)v-INT32_C(65536); }
static void limit_raw(const uint8_t *m,td2ega_state_registers *r)
{
    uint16_t v;uint8_t flags=m[address(r->registers.ds,UINT16_C(0x2c98))];
    r->carry=0;
    if (flags&UINT8_C(0x88)) {
        if (signed_word(r->registers.ax)<0) r->registers.ax=0;
        else {
            v=word(m,r->registers.ds,UINT16_C(0x2c6c));r->carry=(uint16_t)(r->registers.si<v);
            if (signed_word(r->registers.si)>signed_word(v)) {
                v=word(m,r->registers.ds,UINT16_C(0x2c2c));r->carry=(uint16_t)(r->registers.ax<v);
                if (signed_word(r->registers.ax)>signed_word(v)) r->registers.ax=v;
            } else {
                r->carry=(uint16_t)(r->registers.ax<80);if (signed_word(r->registers.ax)>80) r->registers.ax=80;
            }
        }
    }
    r->carry=0;
    if ((flags&UINT8_C(0xc0))==0) return;
    r->carry=(uint16_t)(r->registers.ax<80);
    if (signed_word(r->registers.ax)>80) { r->registers.ax=80;return; }
    v=word(m,r->registers.ds,UINT16_C(0x2c6a));r->carry=(uint16_t)(r->registers.si<v);
    if (signed_word(r->registers.si)<signed_word(v)) { r->carry=0;return; }
    v=word(m,r->registers.ds,UINT16_C(0x2c66));r->carry=(uint16_t)(r->registers.ax<v);
    if (signed_word(r->registers.ax)<signed_word(v)) r->registers.ax=v;
}
uint16_t td2ega_limit_value(const uint8_t *m,uint32_t bytes,
    const td2ega_state_registers *in,td2ega_state_registers *out)
{
    if (out==NULL) return 2;
    *out=(td2ega_state_registers){0};
    if (m==NULL || bytes<UINT32_C(0x100000) || in==NULL || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1) return 2;
    *out=*in;limit_raw(m,out);return 0;
}
static void clip_memory(uint8_t *m,td2ega_state_registers *r,uint16_t field)
{
    r->registers.dx=word(m,r->registers.ds,field);r->carry=0;
    if (signed_word(r->registers.dx)<0) put(m,r->registers.ds,field,0);
    else { r->carry=(uint16_t)(r->registers.dx<80);if (signed_word(r->registers.dx)>80) put(m,r->registers.ds,field,80); }
}
void td2ega_finish_limits(uint8_t *m,uint32_t bytes,
    const td2ega_state_registers *in,td2ega_view_limits_result *out)
{
    td2ega_state_registers r;uint8_t flags;uint16_t v;int relation;
    if (out==NULL) return;
    *out=(td2ega_view_limits_result){0};out->status=2;
    if (m==NULL || bytes<UINT32_C(0x100000) || in==NULL || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1) return;
    r=*in;flags=m[address(r.registers.ds,UINT16_C(0x2c98))];r.registers.bx=(uint16_t)((r.registers.bx&UINT16_C(0xff00))|flags);r.carry=0;
    if (flags==0) goto normal;
    r.registers.ax=0;r.registers.cx=80;
    if (flags&0x20) {
        r.registers.di=word(m,r.registers.ds,UINT16_C(0x2c6e));r.registers.dx=word(m,r.registers.ds,(uint16_t)(r.registers.di+0x2b26));r.carry=(uint16_t)(r.registers.dx>>15);r.registers.dx=(uint16_t)(r.registers.dx<<1);put(m,r.registers.ds,UINT16_C(0x2c86),r.registers.dx);clip_memory(m,&r,UINT16_C(0x2c2e));
    }
    r.carry=0;
    if (flags&4) {
        r.registers.di=word(m,r.registers.ds,UINT16_C(0x2c70));r.registers.dx=word(m,r.registers.ds,(uint16_t)(r.registers.di+0x2b26));r.carry=(uint16_t)(r.registers.dx>>15);r.registers.dx=(uint16_t)(r.registers.dx<<1);put(m,r.registers.ds,UINT16_C(0x2c88),r.registers.dx);clip_memory(m,&r,UINT16_C(0x2c68));
    }
    r.registers.dx=word(m,r.registers.ds,UINT16_C(0x2c66));r.carry=0;
    if ((flags&0x40) && (m[address(r.registers.ds,UINT16_C(0x2c9a))]&128)==0) r.registers.dx=(uint16_t)(r.registers.dx-6);
    r.carry=0;
    if (signed_word(r.registers.dx)<=0) put(m,r.registers.ds,UINT16_C(0x2c66),0);
    else {
        r.carry=(uint16_t)(r.registers.dx<80);if (signed_word(r.registers.dx)>=80) r.registers.dx=80;put(m,r.registers.ds,UINT16_C(0x2c66),r.registers.dx);
    }
    r.registers.dx=word(m,r.registers.ds,UINT16_C(0x2c2c));r.carry=0;
    if ((flags&8) && (m[address(r.registers.ds,UINT16_C(0x2c9b))]&128)==0) r.registers.dx=(uint16_t)(r.registers.dx+6);
    r.carry=0;
    if (signed_word(r.registers.dx)<=0) put(m,r.registers.ds,UINT16_C(0x2c2c),0);
    else {
        r.carry=(uint16_t)(r.registers.dx<80);if (signed_word(r.registers.dx)>=80) r.registers.dx=80;put(m,r.registers.ds,UINT16_C(0x2c2c),r.registers.dx);
    }
    r.carry=0;if ((flags&128)==0) goto normal;
    r.carry=0;
    if (word(m,r.registers.ds,UINT16_C(0x2c78))==0) {
        r.registers.dx=word(m,r.registers.ds,UINT16_C(0x2c2a));put(m,r.registers.ds,UINT16_C(0x2c78),r.registers.dx);put(m,r.registers.ds,UINT16_C(0x2c7c),r.registers.dx);put(m,r.registers.ds,UINT16_C(0x2c76),48);
    }
    r.registers.di=word(m,r.registers.ds,UINT16_C(0x2c80));r.bp=word(m,r.registers.ds,UINT16_C(0x2c72));r.carry=(uint16_t)(r.registers.di<r.bp);relation=signed_word(r.registers.di)<signed_word(r.bp)?-1:1;
    if (r.registers.di!=r.bp) {
        r.registers.dx=word(m,r.registers.ds,UINT16_C(0x2c7e));r.registers.bx=word(m,r.registers.ds,UINT16_C(0x2c2a));
        if (relation<0) { r.carry=(uint16_t)(r.registers.dx<r.registers.bx);if (signed_word(r.registers.dx)>signed_word(r.registers.bx)) put(m,r.registers.ds,UINT16_C(0x2c2a),r.registers.dx); }
        else { r.carry=(uint16_t)(r.registers.bx<r.registers.dx);if (signed_word(r.registers.bx)<signed_word(r.registers.dx)) put(m,r.registers.ds,UINT16_C(0x2c7e),r.registers.dx); }
    }
    r.registers.di=word(m,r.registers.ds,UINT16_C(0x2c6a));r.bp=word(m,r.registers.ds,UINT16_C(0x2c6c));r.carry=(uint16_t)(r.registers.di<r.bp);relation=signed_word(r.registers.di)<signed_word(r.bp)?-1:1;
    if (r.registers.di!=r.bp) {
        r.registers.dx=word(m,r.registers.ds,UINT16_C(0x2c66));r.registers.bx=word(m,r.registers.ds,UINT16_C(0x2c2c));
        if (relation<0) { r.carry=(uint16_t)(r.registers.bx<r.registers.dx);if (signed_word(r.registers.bx)<=signed_word(r.registers.dx)) put(m,r.registers.ds,UINT16_C(0x2c2c),r.registers.dx); }
        else { r.carry=(uint16_t)(r.registers.dx<r.registers.bx);if (signed_word(r.registers.dx)>=signed_word(r.registers.bx)) put(m,r.registers.ds,UINT16_C(0x2c66),r.registers.bx); }
    }
    r.registers.si=word(m,r.registers.ds,UINT16_C(0x2c74));r.registers.ax=word(m,r.registers.ds,(uint16_t)(r.registers.si+0x2a5e));limit_raw(m,&r);++out->calls;put(m,r.registers.ds,UINT16_C(0x2c82),r.registers.ax);
    r.registers.ax=word(m,r.registers.ds,(uint16_t)(r.registers.si+0x2ac2));limit_raw(m,&r);++out->calls;put(m,r.registers.ds,UINT16_C(0x2c32),r.registers.ax);
    r.registers.si=word(m,r.registers.ds,UINT16_C(0x2c76));r.registers.ax=word(m,r.registers.ds,(uint16_t)(r.registers.si+0x2a5e));limit_raw(m,&r);++out->calls;put(m,r.registers.ds,UINT16_C(0x2c34),r.registers.ax);
    v=word(m,r.registers.ds,(uint16_t)(r.registers.si+0x2ac2));r.registers.ax=v;limit_raw(m,&r);++out->calls;put(m,r.registers.ds,UINT16_C(0x2c84),r.registers.ax);
normal:
    out->status=0;out->returned=r;
}
