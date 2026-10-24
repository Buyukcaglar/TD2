#include "td2ega_keyboard.h"
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
static uint16_t low(uint16_t w, uint8_t b)
{
    return (uint16_t)((w&UINT16_C(0xff00))|b);
}
static int valid(uint8_t *m, uint32_t bytes, const td2ega_music_registers *in,
    td2ega_keyboard_result *out)
{
    if (out==NULL) return 0;
    *out=(td2ega_keyboard_result){0};out->status=2;
    return m!=NULL && bytes>=UINT32_C(0x100000) && in!=NULL &&
        in->direction<=1 && in->interrupts_enabled<=1;
}
static void normal(td2ega_keyboard_result *out, const td2ega_music_registers *r)
{
    out->status=0;out->registers=*r;out->flags_mask=UINT16_C(0x600);
    out->return_flags=(uint16_t)((r->interrupts_enabled<<9)|(r->direction<<10));
}
static int io(td2ega_music_port_service service, void *ctx,
    td2ega_music_registers *r, uint16_t op, uint16_t port)
{
    td2ega_music_port_request q={op,port,(uint8_t)r->ax,r->interrupts_enabled};uint8_t v=0;
    if (!service(ctx,&q,&v)) return 0;
    if (op==0) r->ax=low(r->ax,v);
    return 1;
}
void td2ega_keyboard_install(uint8_t *m, uint32_t bytes, uint16_t cs,
    const td2ega_music_registers *in, td2ega_music_port_service port,
    void *ctx, td2ega_keyboard_result *out)
{
    td2ega_music_registers r;
    uint8_t mask;
    uint16_t saved_di;
    if (!valid(m,bytes,in,out) || port==NULL) return;
    r=*in;saved_di=r.di;
    if (!io(port,ctx,&r,0,0x21)) goto failed;
    mask=(uint8_t)r.ax;r.ax=(uint16_t)((uint16_t)mask*UINT16_C(0x101));
    r.ax=low(r.ax,(uint8_t)(mask|3));if (!io(port,ctx,&r,1,0x21)) goto failed;
    r.bx=0;r.es=0;r.bx=word(m,r.es,UINT16_C(0x24));
    if (r.bx!=UINT16_C(0x6907)) {
        put_word(m,r.ds,UINT16_C(0x62ae),r.bx);r.bx=word(m,r.es,UINT16_C(0x26));put_word(m,r.ds,UINT16_C(0x62b0),r.bx);
        put_word(m,r.es,UINT16_C(0x24),UINT16_C(0x6907));put_word(m,r.es,UINT16_C(0x26),cs);
        r.bx=word(m,r.es,UINT16_C(0x58));put_word(m,r.ds,UINT16_C(0x62b2),r.bx);
        r.bx=word(m,r.es,UINT16_C(0x5a));put_word(m,r.ds,UINT16_C(0x62b4),r.bx);
        put_word(m,r.es,UINT16_C(0x58),UINT16_C(0x69b7));put_word(m,r.es,UINT16_C(0x5a),cs);
    }
    r.ax=low(r.ax,mask);if (!io(port,ctx,&r,1,0x21)) goto failed;
    r.ax=r.ds;r.es=r.ax;r.di=UINT16_C(0x62ba);r.cx=UINT16_C(0x5a);r.ax=0;r.direction=0;
    while (r.cx!=0) { put_byte(m,r.es,r.di,0);++r.di;--r.cx; }
    r.di=saved_di;normal(out,&r);return;
failed:out->status=4;out->registers=r;
}
void td2ega_keyboard_restore(uint8_t *m, uint32_t bytes,
    const td2ega_music_registers *in, td2ega_music_port_service port,
    void *ctx, td2ega_keyboard_result *out)
{
    td2ega_music_registers r;
    uint8_t mask;
    if (!valid(m,bytes,in,out) || port==NULL) return;
    r=*in;if (!io(port,ctx,&r,0,0x21)) goto failed;
    mask=(uint8_t)r.ax;r.ax=(uint16_t)((uint16_t)mask*UINT16_C(0x101));
    r.ax=low(r.ax,(uint8_t)(mask|3));if (!io(port,ctx,&r,1,0x21)) goto failed;
    r.bx=0;r.es=0;r.bx=word(m,r.ds,UINT16_C(0x62ae));
    if (r.bx!=0) {
        put_word(m,r.es,UINT16_C(0x24),r.bx);r.bx=word(m,r.ds,UINT16_C(0x62b0));put_word(m,r.es,UINT16_C(0x26),r.bx);
        r.bx=word(m,r.ds,UINT16_C(0x62b2));put_word(m,r.es,UINT16_C(0x58),r.bx);
        r.bx=word(m,r.ds,UINT16_C(0x62b4));put_word(m,r.es,UINT16_C(0x5a),r.bx);
        r.ax=low(r.ax,byte(m,r.es,UINT16_C(0x417)));r.ax=low(r.ax,(uint8_t)(r.ax&UINT16_C(0xf0)));put_byte(m,r.es,UINT16_C(0x417),(uint8_t)r.ax);
    }
    r.ax=low(r.ax,mask);if (!io(port,ctx,&r,1,0x21)) goto failed;
    normal(out,&r);return;
failed:out->status=4;out->registers=r;
}
void td2ega_keyboard_irq(uint8_t *m, uint32_t bytes, uint16_t load,
    const td2ega_music_registers *in, uint16_t irq_flags,
    td2ega_music_port_service port, void *ctx, td2ega_keyboard_result *out)
{
    td2ega_music_registers r;
    uint16_t scan, table;
    uint8_t saved, translated;
    if (!valid(m,bytes,in,out) || port==NULL) return;
    r=*in;r.interrupts_enabled=1;r.ax=(uint16_t)(load+UINT16_C(0x178f));r.ds=r.ax;
    if (!io(port,ctx,&r,0,0x60)) goto failed;
    saved=(uint8_t)r.ax;
    if (!io(port,ctx,&r,0,0x61)) goto failed;
    r.ax=(uint16_t)((uint16_t)(uint8_t)r.ax*UINT16_C(0x101));r.ax=low(r.ax,(uint8_t)(r.ax|UINT16_C(0x80)));
    if (!io(port,ctx,&r,1,0x61)) goto failed;
    r.ax=(uint16_t)((r.ax<<8)|(r.ax>>8));if (!io(port,ctx,&r,1,0x61)) goto failed;
    scan=(uint16_t)(saved&UINT8_C(0x7f));if (scan>=UINT16_C(0x5a)) scan=0;
    if ((saved&UINT8_C(0x80))!=0) put_byte(m,r.ds,(uint16_t)(UINT16_C(0x62ba)+scan),0);
    else {
        put_word(m,r.ds,UINT16_C(0x62b8),scan);put_byte(m,r.ds,(uint16_t)(UINT16_C(0x62ba)+scan),1);
        if ((byte(m,r.ds,UINT16_C(0x62f2))&1)!=0) table=UINT16_C(0x6480);
        else if ((byte(m,r.ds,UINT16_C(0x62d7))&1)!=0) table=UINT16_C(0x6425);
        else if (((byte(m,r.ds,UINT16_C(0x62e4))|byte(m,r.ds,UINT16_C(0x62f0)))&1)!=0) table=UINT16_C(0x636f);
        else if ((byte(m,r.ds,UINT16_C(0x62f4))&1)!=0) table=UINT16_C(0x63ca);
        else table=UINT16_C(0x6314);
        translated=byte(m,r.ds,(uint16_t)(table+scan));
        if ((translated&UINT8_C(0x80))!=0) {
            if (translated>=UINT8_C(0x85)) translated&=UINT8_C(0x7f);
            put_word(m,r.ds,UINT16_C(0x62b6),(uint16_t)((uint16_t)translated<<8));
        } else put_word(m,r.ds,UINT16_C(0x62b6),translated);
    }
    r.ax=low(r.ax,UINT8_C(0x20));if (!io(port,ctx,&r,1,0x20)) goto failed;
    r=*in;r.interrupts_enabled=(uint16_t)((irq_flags>>9)&1);r.direction=(uint16_t)((irq_flags>>10)&1);
    normal(out,&r);out->return_flags=irq_flags;out->flags_mask=UINT16_C(0xffff);return;
failed:out->status=4;out->registers=r;
}
void td2ega_keyboard_bios(uint8_t *m, uint32_t bytes, uint16_t load,
    const td2ega_music_registers *in, uint16_t entry_flags, uint16_t irq_flags,
    td2ega_keyboard_result *out)
{
    td2ega_music_registers r;
    uint16_t ds=(uint16_t)(load+UINT16_C(0x178f));
    unsigned ah;
    if (!valid(m,bytes,in,out)) return;
    if (((entry_flags>>9)&1)!=in->interrupts_enabled || ((entry_flags>>10)&1)!=in->direction) return;
    r=*in;ah=r.ax>>8;
    if (ah==0) { r.ax=word(m,ds,UINT16_C(0x62b6));put_word(m,ds,UINT16_C(0x62b6),0); }
    else if (ah==1) {
        unsigned b;
        uint16_t logical=0;
        r.ax=word(m,ds,UINT16_C(0x62b6));r.interrupts_enabled=1;
        for (b=0;b<8;++b) logical^=(uint16_t)((r.ax>>b)&1);
        logical=(uint16_t)(logical==0?4:0);
        if (r.ax==0) logical|=UINT16_C(0x40);
        if ((r.ax&UINT16_C(0x8000))!=0) logical|=UINT16_C(0x80);
        normal(out,&r);out->return_flags=(uint16_t)((entry_flags&~UINT16_C(0x8c5))|logical|UINT16_C(0x200));
        out->flags_mask=UINT16_C(0xffef);return;
    } else if (ah==2) r.ax=low(r.ax,(uint8_t)(byte(m,ds,UINT16_C(0x62e4))|byte(m,ds,UINT16_C(0x62f0))));
    else r.ax=0;
    r.interrupts_enabled=(uint16_t)((irq_flags>>9)&1);r.direction=(uint16_t)((irq_flags>>10)&1);
    normal(out,&r);out->return_flags=irq_flags;out->flags_mask=UINT16_C(0xffff);
}
