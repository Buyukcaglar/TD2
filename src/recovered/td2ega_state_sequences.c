#include "td2ega_state_sequences.h"
#include <stddef.h>
typedef struct sequence_context {
    uint8_t *m;uint16_t load,ss,sp;uint32_t limit;
    td2ega_state_registers r;td2ega_state_message_service service;void *context;
    td2ega_state_message_result *out;
} sequence_context;
static uint32_t address(uint16_t s,uint16_t o)
{ return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff); }
static uint16_t word(const uint8_t *m,uint16_t s,uint16_t o)
{ uint32_t a=address(s,o);return (uint16_t)(m[a]|((uint16_t)m[(a+1)&UINT32_C(0xfffff)]<<8)); }
static void put(sequence_context *c,uint16_t o,uint16_t v)
{ uint32_t a=address(c->r.registers.ds,o);c->m[a]=(uint8_t)v;c->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8); }
static int call(sequence_context *c,uint16_t site,uint16_t offset,uint16_t argc,uint16_t live,const uint16_t *args)
{
    td2ega_state_message_request q={0};td2ega_state_registers returned;unsigned i;
    if (c->out->calls==c->limit) { c->out->status=3;return 0; }
    c->sp=(uint16_t)(c->sp-4);q.site=site;q.segment=(uint16_t)(c->load+0x6c9);q.offset=offset;q.argument_count=argc;q.live_argument_count=live;q.stack_segment=c->ss;q.stack_sp=c->sp;q.incoming=c->r;
    for (i=0;i<live;++i) q.arguments[i]=args[i];
    returned=c->r;++c->out->calls;
    if (!c->service(c->context,c->m,&q,&returned)) { c->out->status=4;return 0; }
    if (returned.carry>1 || returned.registers.interrupts_enabled>1 || returned.registers.direction>1) { c->out->status=2;return 0; }
    c->r=returned;c->sp=(uint16_t)(c->sp+4);return 1;
}
static void cleanup(sequence_context *c,uint16_t bytes)
{ c->sp=(uint16_t)(c->sp+bytes);c->r.carry=0; }
static void shift_bx(sequence_context *c)
{ c->r.carry=(uint16_t)(c->r.registers.bx>>15);c->r.registers.bx=(uint16_t)(c->r.registers.bx<<1); }
void td2ega_state_sequence(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,
    uint16_t entry_sp,enum td2ega_state_sequence_entry entry,
    const td2ega_state_registers *in,td2ega_state_message_service service,
    void *context,uint32_t limit,td2ega_state_message_result *out)
{
    sequence_context c;uint16_t args[10]={0},saved_di,saved_si,value,first[2];uint32_t at;
    if (out==NULL) return;
    *out=(td2ega_state_message_result){0};out->status=2;
    if (m==NULL || bytes<UINT32_C(0x100000) || in==NULL || service==NULL || entry<TD2EGA_SEQUENCE_3532 || entry>TD2EGA_SEQUENCE_3643 || entry_sp<256 || entry_sp>UINT16_C(0xfff0) || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1) return;
    c=(sequence_context){m,load,ss,entry_sp,limit,*in,service,context,out};out->return_bytes=4;
    c.r.registers.ax=UINT16_C(0x549f);args[0]=c.r.registers.ax;args[1]=c.r.registers.ds;c.sp=(uint16_t)(c.sp-4);
    if (!call(&c,entry==TD2EGA_SEQUENCE_3532?0x3537:0x3648,0x7977,2,2,args)) goto finish;
    cleanup(&c,4);
    if (entry==TD2EGA_SEQUENCE_3532) {
        static const uint16_t targets[7]={0x201,0x2089,0xaa,0xe7,0x1f71,0x1f99,0x3efc};unsigned i;
        for (i=0;i<7;++i) if (!call(&c,(uint16_t)(0x353f+5*i),targets[i],0,0,args)) goto finish;
        args[0]=word(m,c.r.registers.ds,0x300c);args[1]=word(m,c.r.registers.ds,0x300e);first[0]=args[0];first[1]=args[1];c.sp=(uint16_t)(c.sp-4);
        if (!call(&c,0x356a,0x7dbc,2,2,args)) goto finish;
        args[0]=word(m,c.r.registers.ds,0x3008);args[1]=word(m,c.r.registers.ds,0x300a);args[2]=first[0];args[3]=first[1];c.sp=(uint16_t)(c.sp-4);
        if (!call(&c,0x3577,0xa718,2,4,args)) goto finish;
        cleanup(&c,8);c.r.registers.di=0;c.r.carry=0;
        do {
            c.r.registers.ax=10;c.r.registers.dx=0;args[0]=10;args[1]=0;c.sp=(uint16_t)(c.sp-4);
            if (!call(&c,0x3587,0x7a10,2,2,args)) goto finish;
            cleanup(&c,4);
            if (!call(&c,0x358f,0x3efc,0,0,args)) goto finish;
            c.r.bp=c.r.registers.di;
            c.r.registers.dx=(uint16_t)((c.r.registers.dx&UINT16_C(0xff00))|m[address(ss,(uint16_t)(c.r.bp+0x2e22))]);
            m[address(c.r.registers.ds,0x2e29)]=(uint8_t)c.r.registers.dx;
            c.r.bp=(uint16_t)(c.r.bp<<1);c.r.bp=word(m,ss,(uint16_t)(c.r.bp+0x2c9e));c.r.registers.si=0;c.r.carry=0;
            do {
                c.r.registers.dx=UINT16_C(0xffff);
                c.r.registers.bx=word(m,ss,(uint16_t)(c.r.bp+c.r.registers.si+2));
                value=(uint16_t)(((c.r.registers.bx>>8)-0x13)&255);
                c.r.registers.ax=(uint16_t)(value|(value>=128?UINT16_C(0xff00):0));
                c.r.registers.bx=(uint16_t)((c.r.registers.bx&255)|(c.r.registers.ax&UINT16_C(0xff00)));shift_bx(&c);
                args[2]=c.r.registers.bx;args[3]=c.r.registers.ax;args[4]=c.r.registers.dx;
                c.r.registers.bx=word(m,ss,(uint16_t)(c.r.bp+c.r.registers.si));
                value=(uint16_t)(((c.r.registers.bx>>8)-0x13)&255);
                c.r.registers.ax=(uint16_t)((c.r.registers.ax&UINT16_C(0xff00))|value);
                c.r.registers.bx=(uint16_t)((c.r.registers.bx&255)|(c.r.registers.ax&UINT16_C(0xff00)));shift_bx(&c);
                args[0]=c.r.registers.bx;args[1]=c.r.registers.ax;c.sp=(uint16_t)(c.sp-10);
                if (!call(&c,0x35c4,0x8582,5,5,args)) goto finish;
                cleanup(&c,10);c.r.carry=(uint16_t)(c.r.registers.si>UINT16_C(0xfffb));c.r.registers.si=(uint16_t)(c.r.registers.si+4);
                at=address(c.r.registers.ds,0x2e29);m[at]=(uint8_t)(m[at]-1);
            } while (m[at]!=0);
            c.r.carry=0;c.r.registers.ax=(c.r.registers.di&1)?UINT16_C(0x2e08):UINT16_C(0x2e10);args[0]=c.r.registers.ax;c.sp=(uint16_t)(c.sp-2);
            if (!call(&c,0x35e4,0xabfa,1,1,args)) goto finish;
            cleanup(&c,2);saved_di=c.r.registers.di;c.sp=(uint16_t)(c.sp-2);
            if (!call(&c,0x35ed,0x7a27,0,0,args) || !call(&c,0x35f2,0x1f99,0,0,args) || !call(&c,0x35f7,0x391f,0,0,args) || !call(&c,0x35fc,0x94,0,0,args)) goto finish;
            c.r.registers.di=saved_di;c.sp=(uint16_t)(c.sp+2);c.r.registers.di=(uint16_t)(c.r.registers.di+1);c.r.carry=(uint16_t)(c.r.registers.di<7);
        } while (c.r.registers.di!=7);
        c.r.registers.ax=UINT16_C(0x2e08);args[0]=c.r.registers.ax;c.sp=(uint16_t)(c.sp-2);
        if (!call(&c,0x360f,0xabfa,1,1,args)) goto finish;
        cleanup(&c,2);
        if (!call(&c,0x3617,0x5d00,0,0,args)) goto finish;
        put(&c,0x536c,(uint16_t)(word(m,c.r.registers.ds,0x536c)+1));
        c.r.registers.ax=60;c.r.registers.dx=0;args[0]=60;args[1]=0;c.sp=(uint16_t)(c.sp-4);
        if (!call(&c,0x3626,0x7a55,2,2,args)) goto finish;
        cleanup(&c,4);
    } else {
        td2ega_state_message_result nested;
        m[address(c.r.registers.ds,0x2e29)]=10;saved_si=c.r.registers.si;c.sp=(uint16_t)(c.sp-6);
        td2ega_state_message(m,bytes,load,ss,c.sp,TD2EGA_MESSAGE_5C98,&c.r,service,context,limit-out->calls,&nested);
        out->calls+=nested.calls;c.sp=nested.current_sp;c.r=nested.returned;
        if (nested.status!=0) { out->status=nested.status;goto finish; }
        c.r.registers.di=0;c.r.registers.si=0;c.r.carry=0;
        do {
            if (!call(&c,0x365f,0x6a3b,0,0,args)) goto finish;
            c.r.registers.ax=40;c.r.registers.dx=0;args[0]=40;args[1]=0;c.sp=(uint16_t)(c.sp-4);
            if (!call(&c,0x366a,0x7a10,2,2,args)) goto finish;
            cleanup(&c,4);c.r.carry=(uint16_t)(c.r.registers.di<12);
            if (c.r.registers.di<12) {
                args[0]=word(m,c.r.registers.ds,(uint16_t)(c.r.registers.di+0x22da));args[1]=word(m,c.r.registers.ds,(uint16_t)(c.r.registers.di+0x22dc));first[0]=args[0];first[1]=args[1];c.sp=(uint16_t)(c.sp-4);
                if (!call(&c,0x367f,0x80ca,2,2,args)) goto finish;
                args[0]=word(m,c.r.registers.ds,(uint16_t)(c.r.registers.di+0x22e6));args[1]=word(m,c.r.registers.ds,(uint16_t)(c.r.registers.di+0x22e8));args[2]=first[0];args[3]=first[1];c.sp=(uint16_t)(c.sp-4);
                if (!call(&c,0x368c,0xaa12,2,4,args)) goto finish;
                cleanup(&c,8);
            } else {
                args[0]=word(m,c.r.registers.ds,(uint16_t)(c.r.registers.di+0x22e6));args[1]=word(m,c.r.registers.ds,(uint16_t)(c.r.registers.di+0x22e8));c.sp=(uint16_t)(c.sp-4);
                if (!call(&c,0x369f,0x9cc2,2,2,args)) goto finish;
                cleanup(&c,4);
            }
            c.r.registers.ax=240;c.r.registers.bx=27;args[0]=word(m,c.r.registers.ds,0x2fd8);args[1]=word(m,c.r.registers.ds,0x2fda);args[2]=240;args[3]=27;c.sp=(uint16_t)(c.sp-8);
            if (!call(&c,0x36b7,0x808a,4,4,args)) goto finish;
            cleanup(&c,8);c.r.registers.di=(uint16_t)(c.r.registers.di+4);c.r.carry=(uint16_t)(c.r.registers.di<24);
            if (c.r.registers.di>=24) { c.r.registers.di=12;c.r.registers.si=1; }
            if (!call(&c,0x36cd,0x7a27,0,0,args)) goto finish;
            at=address(c.r.registers.ds,0x2e29);m[at]=(uint8_t)(m[at]-1);
        } while (m[at]!=0);
        put(&c,0x536e,(uint16_t)(word(m,c.r.registers.ds,0x536e)+1));c.r.registers.si=saved_si;c.sp=(uint16_t)(c.sp+2);
    }
    c.sp=(uint16_t)(c.sp+4);out->status=0;
finish:
    out->current_sp=c.sp;out->returned=c.r;
}
