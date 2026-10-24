#include "td2ega_state_messages.h"
#include <stddef.h>

typedef struct message_context {
    uint8_t *memory;
    uint16_t load, ss, sp;
    uint32_t limit;
    td2ega_state_registers r;
    td2ega_state_message_service service;
    void *context;
    td2ega_state_message_result *out;
} message_context;

static uint32_t address(uint16_t s, uint16_t o)
{
    return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);
}
static uint16_t word(const uint8_t *m, uint16_t s, uint16_t o)
{
    uint32_t at=address(s,o);
    return (uint16_t)((uint16_t)m[at]|((uint16_t)m[(at+1)&UINT32_C(0xfffff)]<<8));
}
static void put_word(uint8_t *m, uint16_t s, uint16_t o, uint16_t v)
{
    uint32_t at=address(s,o);m[at]=(uint8_t)v;m[(at+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);
}
static void cleanup(message_context *c, uint16_t bytes)
{
    c->sp=(uint16_t)(c->sp+bytes);c->r.carry=0;
}
static int call(message_context *c, uint16_t site, uint16_t segment,
    uint16_t offset, uint16_t argc, uint16_t live, const uint16_t *args)
{
    td2ega_state_message_request q={0};td2ega_state_registers returned;
    unsigned i;
    if (c->out->calls==c->limit) { c->out->status=3;return 0; }
    c->sp=(uint16_t)(c->sp-4);q.site=site;q.segment=(uint16_t)(c->load+segment);q.offset=offset;
    q.argument_count=argc;q.live_argument_count=live;q.stack_segment=c->ss;q.stack_sp=c->sp;
    for (i=0;i<live;++i) q.arguments[i]=args[i];
    q.incoming=c->r;returned=c->r;++c->out->calls;
    if (!c->service(c->context,c->memory,&q,&returned)) { c->out->status=4;return 0; }
    if (returned.carry>1 || returned.registers.interrupts_enabled>1 || returned.registers.direction>1) { c->out->status=2;return 0; }
    c->r=returned;c->sp=(uint16_t)(c->sp+4);return 1;
}
static int surface(message_context *c)
{
    uint16_t args[10]={0};
    c->r.registers.ax=UINT16_C(0xaf54);args[0]=c->r.registers.ax;args[1]=(uint16_t)(c->load+UINT16_C(0x6c9));
    c->sp=(uint16_t)(c->sp-4);
    if (!call(c,0x5c9d,0x6c9,0x7d5e,2,2,args)) return 0;
    cleanup(c,4);return 1;
}
static int panel(message_context *c)
{
    uint16_t args[10]={0}, first[5];
    unsigned i;
    c->sp=(uint16_t)(c->sp-4);
    if (!surface(c)) return 0;
    c->sp=(uint16_t)(c->sp+4);
    c->r.registers.ax=15;c->r.registers.di=0;c->r.carry=0;
    args[0]=15;args[1]=0;c->sp=(uint16_t)(c->sp-4);
    if (!call(c,0x3794,0x6c9,0x7a82,2,2,args)) return 0;
    cleanup(c,4);
    c->r.registers.ax=30;c->r.registers.bx=UINT16_C(0x105);c->r.registers.cx=30;c->r.registers.dx=UINT16_C(0x33);
    args[0]=30;args[1]=30;args[2]=UINT16_C(0x105);args[3]=UINT16_C(0x33);args[4]=c->r.registers.di;
    for (i=0;i<5;++i) first[i]=args[i];
    c->sp=(uint16_t)(c->sp-10);
    if (!call(c,0x37ad,0x6c9,0x8a0c,5,5,args)) return 0;
    c->r.registers.di=UINT16_C(0xffff);c->r.registers.ax=33;c->r.registers.bx=UINT16_C(0x11f);c->r.registers.cx=33;c->r.registers.dx=UINT16_C(0x4d);
    args[0]=33;args[1]=33;args[2]=UINT16_C(0x11f);args[3]=UINT16_C(0x4d);args[4]=UINT16_C(0xffff);
    for (i=0;i<5;++i) args[5+i]=first[i];
    c->sp=(uint16_t)(c->sp-10);
    if (!call(c,0x37c6,0x16af,6,5,10,args)) return 0;
    cleanup(c,20);return 1;
}
static int clear_input(message_context *c)
{
    uint16_t args[10]={0};
    do {
        if (!call(c,0x3f0d,0x6c9,0x69fe,0,0,args)) return 0;
        c->r.carry=0;
    } while (c->r.registers.ax!=0);
    c->r.registers.ax=40;c->r.registers.dx=0;args[0]=40;args[1]=0;c->sp=(uint16_t)(c->sp-4);
    if (!call(c,0x3f1c,0x6c9,0x7a55,2,2,args)) return 0;
    cleanup(c,4);c->r.carry=0;
    if (word(c->memory,c->r.registers.ds,UINT16_C(0x8a9a))!=0) return 1;
    if (!call(c,0x3f2b,0x6c9,0x6a3b,0,0,args)) return 0;
    c->r.registers.ax=UINT16_C(0x708);c->r.registers.dx=0;c->r.carry=0;
    args[0]=UINT16_C(0x708);args[1]=0;c->sp=(uint16_t)(c->sp-4);
    if (!call(c,0x3f37,0x6c9,0x6a6a,2,2,args)) return 0;
    cleanup(c,4);return 1;
}
void td2ega_state_message(uint8_t *m, uint32_t bytes, uint16_t load,
    uint16_t ss, uint16_t entry_sp, enum td2ega_state_message_entry entry,
    const td2ega_state_registers *in, td2ega_state_message_service service,
    void *context, uint32_t limit, td2ega_state_message_result *out)
{
    message_context c;
    uint16_t args[10]={0}, text=0, counter;
    if (out==NULL) return;
    *out=(td2ega_state_message_result){0};out->status=2;
    if (m==NULL || bytes<UINT32_C(0x100000) || in==NULL || service==NULL ||
        entry<TD2EGA_MESSAGE_36E0 || entry>TD2EGA_MESSAGE_5C98 || entry_sp<256 || entry_sp>UINT16_C(0xfff0) ||
        in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1) return;
    c=(message_context){m,load,ss,entry_sp,limit,*in,service,context,out};
    out->return_bytes=entry==TD2EGA_MESSAGE_3788?2:4;
    if (entry==TD2EGA_MESSAGE_5C98) { if (!surface(&c)) goto finish;goto normal; }
    if (entry==TD2EGA_MESSAGE_3F0D) { if (!clear_input(&c)) goto finish;goto normal; }
    if (entry==TD2EGA_MESSAGE_3788) { if (!panel(&c)) goto finish;goto normal; }
    if (entry==TD2EGA_MESSAGE_374F) {
        c.r.carry=0;
        if (word(m,c.r.registers.ds,UINT16_C(0x9410))!=0) goto normal;
    }
    c.sp=(uint16_t)(c.sp-2);
    if (!panel(&c)) goto finish;
    c.sp=(uint16_t)(c.sp+2);
    if (entry==TD2EGA_MESSAGE_36E0) {
        c.r.registers.bx=UINT16_C(0x2a);c.r.registers.ax=UINT16_C(0x2e2a);args[0]=c.r.registers.ax;args[1]=c.r.registers.bx;c.sp=(uint16_t)(c.sp-4);
        if (!call(&c,0x36eb,0x16ab,0xc,2,2,args)) goto finish;
        args[2]=args[0];args[3]=args[1];c.r.registers.bx=UINT16_C(0x3a);c.r.registers.ax=UINT16_C(0x2e5c);args[0]=c.r.registers.ax;args[1]=c.r.registers.bx;c.sp=(uint16_t)(c.sp-4);
        if (!call(&c,0x36f8,0x16ab,0xc,2,4,args)) goto finish;
        cleanup(&c,8);text=UINT16_C(0x2e45);
    } else if (entry==TD2EGA_MESSAGE_375F) {
        counter=word(m,c.r.registers.ds,UINT16_C(0x8424));c.r.carry=(uint16_t)(counter<1);
        if (counter==1) text=UINT16_C(0x2f27);
        else {
            c.r.registers.bx=UINT16_C(0x2f24);c.r.registers.cx=UINT16_C(0x2f20);
            args[0]=c.r.registers.cx;args[1]=c.r.registers.bx;args[2]=counter;c.sp=(uint16_t)(c.sp-6);
            if (!call(&c,0x3775,0x13a8,0x2a3c,3,3,args)) goto finish;
            cleanup(&c,6);text=UINT16_C(0x2f13);
        }
    } else {
        static const uint16_t texts[6]={0,UINT16_C(0x2e75),UINT16_C(0x2e91),UINT16_C(0x2eae),UINT16_C(0x2ecc),UINT16_C(0x2ee8)};
        if (entry==TD2EGA_MESSAGE_374F) text=UINT16_C(0x2f04);
        else {
            text=texts[entry];
            if (entry==TD2EGA_MESSAGE_3713) counter=UINT16_C(0x8658);else counter=UINT16_C(0x536c);
            put_word(m,c.r.registers.ds,counter,(uint16_t)(word(m,c.r.registers.ds,counter)+1));
        }
    }
    c.r.registers.ax=text;c.r.registers.bx=UINT16_C(0x32);args[0]=text;args[1]=c.r.registers.bx;c.sp=(uint16_t)(c.sp-4);
    if (!call(&c,0x3708,0x16ab,0xc,2,2,args)) goto finish;
    cleanup(&c,4);c.r.registers.ax=30;c.r.registers.dx=0;args[0]=30;args[1]=0;c.sp=(uint16_t)(c.sp-4);
    if (!call(&c,0x3635,0x6c9,0x7a55,2,2,args)) goto finish;
    cleanup(&c,4);c.sp=(uint16_t)(c.sp-4);
    if (!clear_input(&c)) goto finish;
    c.sp=(uint16_t)(c.sp+4);
normal:
    c.sp=(uint16_t)(c.sp+out->return_bytes);out->status=0;
finish:
    out->current_sp=c.sp;out->returned=c.r;
}
