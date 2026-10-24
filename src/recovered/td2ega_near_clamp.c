#include "td2ega_near_clamp.h"
#include <stddef.h>
static uint32_t address(uint16_t s,uint16_t o)
{ return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff); }
static uint16_t word(const uint8_t *m,uint16_t s,uint16_t o)
{ uint32_t a=address(s,o);return (uint16_t)(m[a]|((uint16_t)m[(a+1)&UINT32_C(0xfffff)]<<8)); }
static void put(uint8_t *m,uint16_t s,uint16_t o,uint16_t v)
{ uint32_t a=address(s,o);m[a]=(uint8_t)v;m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8); }
static int32_t signed_word(uint16_t v)
{ return v<UINT16_C(0x8000)?(int32_t)v:(int32_t)v-INT32_C(65536); }
static void add_si(td2ega_state_registers *r,uint16_t value)
{ uint32_t sum=(uint32_t)r->registers.si+value;r->registers.si=(uint16_t)sum;r->carry=(uint16_t)(sum>>16); }
void td2ega_near_clamp(uint8_t *m,uint32_t bytes,
    const td2ega_state_registers *in,uint32_t limit,
    td2ega_near_clamp_result *out)
{
    td2ega_state_registers r;uint16_t saved_ax;
    if (out==NULL) return;
    *out=(td2ega_near_clamp_result){0};out->status=2;
    if (m==NULL || bytes<UINT32_C(0x100000) || in==NULL || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1) return;
    r=*in;r.registers.si=UINT16_C(0x9c4);r.registers.direction=0;r.registers.dx=0;r.carry=0;r.registers.di=5;r.registers.bx=word(m,r.registers.ds,UINT16_C(0x5348));
    do {
        r.registers.cx=r.bp;saved_ax=r.registers.ax;r.carry=(uint16_t)(r.registers.cx<r.registers.ax);r.registers.cx=(uint16_t)(r.registers.cx-r.registers.ax);add_si(&r,r.registers.ax);add_si(&r,r.registers.ax);
        do {
            if (out->words==limit) { out->status=3;goto finish; }
            ++out->words;r.registers.ax=word(m,r.registers.ds,r.registers.si);r.registers.si=(uint16_t)(r.registers.si+2);r.carry=0;
            if (signed_word(r.registers.ax)<0) put(m,r.registers.ds,(uint16_t)(r.registers.si-2),0);
            else {
                r.carry=(uint16_t)(r.registers.ax<r.registers.bx);
                if (signed_word(r.registers.ax)>signed_word(r.registers.bx)) put(m,r.registers.ds,(uint16_t)(r.registers.si-2),r.registers.bx);
            }
            r.registers.cx=(uint16_t)(r.registers.cx-1);
        } while (r.registers.cx!=0);
        r.registers.ax=(uint16_t)(92-r.bp);r.carry=(uint16_t)(92<r.bp);add_si(&r,r.registers.ax);add_si(&r,r.registers.ax);r.registers.ax=saved_ax;r.registers.di=(uint16_t)(r.registers.di-1);
    } while (r.registers.di!=0);
    out->status=0;
finish:
    out->returned=r;
}
