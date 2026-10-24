#include "td2ega_prepare_records.h"
#include "td2ega_byte_ring.h"
#include <stddef.h>

static uint32_t address(uint16_t s, uint16_t o)
{
    return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);
}
static uint8_t byte(const uint8_t *m, uint16_t s, uint16_t o)
{
    return m[address(s,o)];
}
static uint16_t word(const uint8_t *m, uint16_t s, uint16_t o)
{
    uint32_t at=address(s,o);
    return (uint16_t)((uint16_t)m[at]|((uint16_t)m[(at+1)&UINT32_C(0xfffff)]<<8));
}
static void put_byte(uint8_t *m, uint16_t s, uint16_t o, uint8_t v)
{
    m[address(s,o)]=v;
}
static void put_word(uint8_t *m, uint16_t s, uint16_t o, uint16_t v)
{
    uint32_t at=address(s,o);m[at]=(uint8_t)v;m[(at+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);
}
static uint16_t sample(uint8_t *m, uint16_t ds)
{
    TD2EgaByteRing state;
    uint16_t i, result;
    state.cursor=word(m,ds,UINT16_C(0x66e6));
    for (i=0;i<256;++i) state.bytes[i]=byte(m,ds,(uint16_t)(UINT16_C(0x66e8)+i));
    result=td2ega_byte_ring_step(&state);
    put_word(m,ds,UINT16_C(0x66e6),state.cursor);
    put_byte(m,ds,(uint16_t)(UINT16_C(0x66e8)+(state.cursor&UINT16_C(0xff))),state.bytes[state.cursor&UINT16_C(0xff)]);
    return result;
}
void td2ega_prepare_records(uint8_t *m, uint32_t bytes, uint16_t ss,
    const td2ega_music_registers *in, uint16_t incoming_bp, uint32_t limit,
    td2ega_prepare_records_result *out)
{
    td2ega_music_registers r;
    uint16_t bp, at;
    uint32_t product, quotient;
    if (out==NULL) return;
    *out=(td2ega_prepare_records_result){0};out->status=2;
    if (m==NULL || bytes<UINT32_C(0x100000) || in==NULL || in->direction>1 || in->interrupts_enabled>1) return;
    r=*in;r.ax=r.ds;r.es=r.ax;r.direction=0;bp=UINT16_C(0x3813);
    r.ax=(uint16_t)((r.ax&UINT16_C(0xff00))|(uint8_t)(0-byte(m,r.ds,UINT16_C(0x920c))));
    put_byte(m,r.ds,UINT16_C(0x1a70),(uint8_t)r.ax);r.cx=1000;r.si=0;
again:
    out->table_offset=bp;out->record_offset=r.si;
    if (out->steps==limit) { out->status=3;goto finish; }
    ++out->steps;
    at=(uint16_t)(bp+r.si);
    if (byte(m,ss,at)==0) goto table_end;
    if (r.si>16) {
        r.ax=sample(m,r.ds);++out->samples;
        if ((uint8_t)r.ax<=byte(m,r.ds,UINT16_C(0x1a70))) {
            uint16_t saved_si=r.si;
            r.di=r.si;r.si=(uint16_t)(r.si+8);r.cx=(uint16_t)(400-r.si);
            r.si=(uint16_t)(r.si+bp);r.di=(uint16_t)(r.di+bp);
            while (r.cx!=0) {
                uint8_t v=byte(m,r.ds,r.si);put_byte(m,r.es,r.di,v);++r.si;++r.di;--r.cx;
            }
            r.si=saved_si;r.cx=1000;++out->deleted;
            if (byte(m,ss,(uint16_t)(bp+r.si))==0) goto table_end;
            goto again;
        }
    }
    r.ax=word(m,ss,(uint16_t)(at+2));product=(uint32_t)r.ax*word(m,r.ds,UINT16_C(0x380d));
    r.ax=(uint16_t)product;r.dx=(uint16_t)(product>>16);
    quotient=r.cx==0?UINT32_C(0x10000):product/r.cx;
    if (quotient>UINT32_C(0xffff)) { out->status=1;goto finish; }
    r.ax=(uint16_t)quotient;r.dx=(uint16_t)(product%r.cx);r.ax=(uint16_t)(r.ax+UINT16_C(0x3b51));
    put_word(m,ss,(uint16_t)(at+2),r.ax);r.ax=UINT16_C(0xff38);
    if (bp!=UINT16_C(0x3813)) { r.ax=UINT16_C(0xc8);put_byte(m,ss,at,(uint8_t)(byte(m,ss,at)+4)); }
    put_word(m,ss,(uint16_t)(at+6),r.ax);r.si=(uint16_t)(r.si+8);
    if (r.si<400) goto again;
table_end:
    if (bp==UINT16_C(0x3813)) { put_word(m,r.ds,UINT16_C(0x5354),r.si);r.si=0;bp=UINT16_C(0x39a3);goto again; }
    put_word(m,r.ds,UINT16_C(0x5356),r.si);bp=incoming_bp;out->status=0;
finish:
    out->registers=r;out->bp=bp;
}
