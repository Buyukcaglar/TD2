#include "td2ega_state_loop.h"
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
static uint16_t sign_byte(uint8_t b)
{
    return b<UINT8_C(0x80)?(uint16_t)b:(uint16_t)(UINT16_C(0xff00)|b);
}
static int call(uint8_t *m, uint16_t load, uint16_t site, uint16_t target,
    uint16_t argc, uint16_t live_argc, const uint16_t *args,
    td2ega_state_registers *r, td2ega_state_call_service service, void *ctx,
    uint32_t limit, td2ega_state_loop_result *out)
{
    td2ega_state_call_request q={0};td2ega_state_registers returned;
    unsigned i;
    if (out->calls==limit) { out->status=3;return 0; }
    q.site=site;q.segment=(uint16_t)(load+UINT16_C(0x6c9));q.offset=target;
    q.argument_count=argc;q.live_argument_count=live_argc;
    for (i=0;i<live_argc;++i) q.arguments[i]=args[i];
    q.incoming=*r;returned=*r;++out->calls;
    if (!service(ctx,m,&q,&returned)) { out->status=4;return 0; }
    if (returned.carry>1 || returned.registers.direction>1 || returned.registers.interrupts_enabled>1) { out->status=2;return 0; }
    *r=returned;return 1;
}
void td2ega_state_loop(uint8_t *m, uint32_t bytes, uint16_t load,
    const td2ega_mutable_control *code, const td2ega_state_registers *in,
    td2ega_state_call_service service, void *ctx, uint32_t limit,
    td2ega_state_loop_result *out)
{
    td2ega_state_registers r;
    uint16_t args[4]={0}, old_args[2], value;
    uint8_t state;
    if (out==NULL) return;
    *out=(td2ega_state_loop_result){0};out->status=2;
    if (m==NULL || bytes<UINT32_C(0x100000) || code==NULL || code->returns_state>1 ||
        in==NULL || service==NULL || in->carry>1 || in->registers.direction>1 || in->registers.interrupts_enabled>1) return;
    r=*in;r.registers.direction=0;
#define R r.registers
#define B(o) byte(m,R.ds,UINT16_C(o))
#define W(o) word(m,R.ds,UINT16_C(o))
#define PB(o,v) put_byte(m,R.ds,UINT16_C(o),(uint8_t)(v))
#define PW(o,v) put_word(m,R.ds,UINT16_C(o),(uint16_t)(v))
#define CALL(s,t) do { if (!call(m,load,(s),(t),0,0,args,&r,service,ctx,limit,out)) goto finish; } while (0)
    CALL(0x1b30,0x1e59);CALL(0x1b35,0x1c8f);CALL(0x1b3a,0x5d00);
initialize:
    CALL(0x1b3f,0x1e31);CALL(0x1b44,0x5ada);R.ax=UINT16_C(0x1352);
    args[0]=R.ax;args[1]=R.ds;
    if (!call(m,load,0x1b4e,0x7946,2,2,args,&r,service,ctx,limit,out)) goto finish;
    r.carry=0; /* Balanced, nonwrapping ADDSP4. */
loop:
    CALL(0x1b56,0x0201);CALL(0x1b5b,0x2089);CALL(0x1b60,0x00aa);CALL(0x1b65,0x00e7);
    CALL(0x1b6a,0x1f71);CALL(0x1b6f,0x1f99);CALL(0x1b74,0x391f);CALL(0x1b79,0x0094);
    CALL(0x1b7e,0x3b95);CALL(0x1b83,0x3cef);CALL(0x1b88,0x3c3a);
    state=B(0x5490);R.ax=low(R.ax,state);r.carry=0;
    if (state==0) goto loop;
    PB(0x336b,0);
    if (state>=UINT8_C(0x80)) goto exit_work;
    CALL(0x1b9b,0x7971);R.ax=sign_byte(B(0x5490));r.carry=(uint16_t)(R.ax>>15);
    R.ax=(uint16_t)(R.ax*2);R.bx=R.ax;
    out->dispatch_target=word(m,R.ds,(uint16_t)(UINT16_C(0x2302)+R.bx));
    switch (out->dispatch_target) {
    case 0x1bac:goto exit_work;
    case 0x1c51:CALL(0x1c51,0x374f);goto exit_work;
    case 0x1c02:CALL(0x1c02,0x3532);goto decrement;
    case 0x1c23:CALL(0x1c23,0x3643);goto decrement;
    case 0x1c2a:PW(0x8658,W(0x8658)+1);CALL(0x1c2e,0x36e0);goto decrement;
    case 0x1c35:CALL(0x1c35,0x371f);goto decrement;
    case 0x1c3c:CALL(0x1c3c,0x372b);goto decrement;
    case 0x1c43:CALL(0x1c43,0x3737);goto decrement;
    case 0x1c4a:CALL(0x1c4a,0x3743);goto decrement;
    case 0x1c59:CALL(0x1c59,0x3713);goto decrement;
    default:out->status=2;goto finish;
    }
decrement:
    value=(uint16_t)(W(0x8424)-1);PW(0x8424,value);
    if (value==0) goto reset;
    CALL(0x1c0d,0x375f);state=B(0x5490);r.carry=(uint16_t)(state<4);
    if (state==4) goto exit_work;
    r.carry=(uint16_t)(state<9);
    if (state==9) goto exit_work;
    goto initialize;
reset:
    CALL(0x1c60,0x5c98);args[0]=W(0x2286);args[1]=W(0x2288);old_args[0]=args[0];old_args[1]=args[1];
    if (!call(m,load,0x1c6d,0x80ca,2,2,args,&r,service,ctx,limit,out)) goto finish;
    args[0]=W(0x2282);args[1]=W(0x2284);args[2]=old_args[0];args[3]=old_args[1];
    if (!call(m,load,0x1c7a,0xaa12,2,4,args,&r,service,ctx,limit,out)) goto finish;
    r.carry=0;CALL(0x1c82,0x3f0d);PB(0x5490,0);
exit_work:
    R.ax=W(0x52ca);r.carry=(uint16_t)(R.ax<UINT16_C(0x3b51));R.ax=(uint16_t)(R.ax-UINT16_C(0x3b51));
    R.bx=W(0x380f);r.carry=(uint16_t)(R.bx<11);R.bx=(uint16_t)(R.bx-11);
    r.carry=(uint16_t)(R.ax<R.bx);if (r.carry==0) R.ax=R.bx;PW(0x5374,R.ax);
    R.ax=W(0x52d2);r.carry=(uint16_t)(R.ax<UINT16_C(0x3b51));R.ax=(uint16_t)(R.ax-UINT16_C(0x3b51));
    r.carry=(uint16_t)(R.ax<R.bx);if (r.carry==0) R.ax=R.bx;PW(0x5376,R.ax);
    R.ax=W(0x331e);PW(0x942e,R.ax);
    CALL(0x1bd7,0x7971);CALL(0x1bdc,0x1f60);CALL(0x1be1,0x0083);CALL(0x1be6,0x38d4);CALL(0x1beb,0x601c);
    R.ax=sign_byte(B(0x5490));R.si=in->registers.si;R.ds=in->registers.ds;r.bp=in->bp;
    if (code->returns_state==0) { r.carry=0;R.ax=2;R.es=2;put_word(m,R.es,UINT16_C(0x66),R.ax); }
    out->status=0;
finish:
    out->returned=r;
#undef R
#undef B
#undef W
#undef PB
#undef PW
#undef CALL
}
