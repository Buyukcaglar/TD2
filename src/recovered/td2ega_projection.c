#include "td2ega_projection.h"
#include <stddef.h>
typedef struct projection_context {
    uint8_t *m;td2ega_state_registers r;uint32_t limit;
    td2ega_projection_result *out;
} projection_context;
static uint32_t address(uint16_t s,uint16_t o)
{ return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff); }
static uint16_t word(const uint8_t *m,uint16_t s,uint16_t o)
{ uint32_t a=address(s,o);return (uint16_t)(m[a]|((uint16_t)m[(a+1)&UINT32_C(0xfffff)]<<8)); }
static void put(projection_context *c,uint16_t o,uint16_t v)
{ uint32_t a=address(c->r.registers.ds,o);c->m[a]=(uint8_t)v;c->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8); }
static int32_t signed_word(uint16_t v)
{ return v<UINT16_C(0x8000)?(int32_t)v:(int32_t)v-INT32_C(65536); }
static uint16_t signed_byte(uint8_t v)
{ return v<128?v:(uint16_t)(UINT16_C(0xff00)|v); }
static void lookup_raw(const uint8_t *m,td2ega_state_registers *r)
{
    uint8_t b=(uint8_t)r->registers.ax;uint16_t n=signed_byte(b),value;
    if (b>=128) n=(uint16_t)(0-n);
    value=word(m,r->registers.ds,(uint16_t)(UINT16_C(0x5560)+2*n));
    r->registers.ax=b>=128?(uint16_t)(0-value):value;r->carry=(uint16_t)(b>=128 && value!=0);
}
uint16_t td2ega_signed_byte_lookup(const uint8_t *m,uint32_t bytes,
    const td2ega_state_registers *in,td2ega_state_registers *out)
{
    if (out==NULL) return 2;
    *out=(td2ega_state_registers){0};
    if (m==NULL || bytes<UINT32_C(0x100000) || in==NULL || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1) return 2;
    *out=*in;lookup_raw(m,out);return 0;
}
static int32_t add(projection_context *c,uint16_t *r,uint16_t v)
{
    int32_t signed_sum=signed_word(*r)+signed_word(v);uint32_t sum=(uint32_t)*r+v;
    *r=(uint16_t)sum;c->r.carry=(uint16_t)(sum>>16);return signed_sum;
}
static void sub(projection_context *c,uint16_t *r,uint16_t v)
{ c->r.carry=(uint16_t)(*r<v);*r=(uint16_t)(*r-v); }
static void negate(projection_context *c,uint16_t *r)
{ c->r.carry=(uint16_t)(*r!=0);*r=(uint16_t)(0-*r); }
static void shl(projection_context *c,uint16_t *r)
{ c->r.carry=(uint16_t)(*r>>15);*r=(uint16_t)(*r<<1); }
static void shr(projection_context *c,uint16_t *r,unsigned count)
{ c->r.carry=(uint16_t)((*r>>(count-1))&1);*r=(uint16_t)(*r>>count); }
static void multiply(projection_context *c,uint16_t v)
{ uint32_t product=(uint32_t)c->r.registers.ax*v;c->r.registers.ax=(uint16_t)product;c->r.registers.dx=(uint16_t)(product>>16);c->r.carry=(uint16_t)(c->r.registers.dx!=0); }
static int step(projection_context *c)
{ if (c->out->work==c->limit) { c->out->status=3;return 0; }++c->out->work;return 1; }
void td2ega_projection_step(uint8_t *m,uint32_t bytes,
    const td2ega_state_registers *in,uint32_t limit,td2ega_projection_result *out)
{
    projection_context c;uint8_t b,flags;uint16_t v,saved,node,start,oldax;int32_t signed_sum,product;int64_t quotient,remainder;
    if (out==NULL) return;
    *out=(td2ega_projection_result){0};out->status=2;
    if (m==NULL || bytes<UINT32_C(0x100000) || in==NULL || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1) return;
    c=(projection_context){m,*in,limit,out};c.r.registers.si=0;c.r.carry=0;
#define R c.r.registers
#define W(o) word(m,R.ds,(uint16_t)(o))
#define B(o) m[address(R.ds,(uint16_t)(o))]
#define PW(o,vv) put(&c,(uint16_t)(o),(uint16_t)(vv))
#define PB(o,vv) (B(o)=(uint8_t)(vv))
    do {
        if (!step(&c)) goto finish;
        ++out->iterations;R.bx=W(0x2c26);b=B(R.bx);R.ax=(uint16_t)(b|((uint16_t)(b>>7)<<8));PB(R.si+0x2b8a,b>>7);
        R.cx=(uint16_t)((R.cx&UINT16_C(0xff00))|B(0x2c96));PB(0x2c96,b);R.ax=(uint16_t)(b&127);R.bx=(uint16_t)(R.bx-1);PW(0x2c26,R.bx);R.bx=R.ax;shl(&c,&R.bx);shl(&c,&R.bx);
        R.ax=W(R.bx+0x347e);PW(0x2c92,R.ax);PB(0x2c97,B(0x2c97)^(uint8_t)R.ax);PB(0x2c98,B(0x2c98)|(uint8_t)R.ax);PB(R.si+0x2b8a,B(R.si+0x2b8a)|(uint8_t)R.ax);
        R.ax=(uint16_t)((R.ax&UINT16_C(0xff00))|B(0x2c97));PB(R.si+0x2bbc,(uint8_t)R.ax);R.ax=W(R.bx+0x3480);PW(0x2c94,R.ax);PB(R.si+0x2b8b,R.ax>>8);
        R.ax=signed_byte((uint8_t)R.ax);negate(&c,&R.ax);c.r.carry=(uint16_t)(R.ax&1);R.ax=(uint16_t)((R.ax>>1)|(R.ax&UINT16_C(0x8000)));add(&c,&R.ax,W(0x2c64));PW(0x2c64,R.ax);
        R.ax=(uint16_t)((R.ax&UINT16_C(0xff00))|(R.ax>>8));lookup_raw(m,&c.r);++out->lookups;signed_sum=add(&c,&R.ax,W(0x2c22));PW(0x2c22,R.ax);
        if (signed_sum<0) { negate(&c,&R.ax);multiply(&c,W(R.si+0x2728));negate(&c,&R.dx); }
        else multiply(&c,W(R.si+0x2728));
        add(&c,&R.dx,8);PW(R.si+0x2b26,R.dx);R.ax=W(0x2c2a);c.r.carry=(uint16_t)(R.dx<R.ax);
        if (signed_word(R.dx)<signed_word(R.ax)) { PW(0x2c2a,R.dx);R.ax=R.dx;PW(0x2c72,R.si); }
        PW(R.si+0x2b58,R.ax);R.ax=signed_byte(B(0x2c93));shl(&c,&R.ax);shl(&c,&R.ax);shl(&c,&R.ax);shl(&c,&R.ax);add(&c,&R.ax,W(0x2c24));
        c.r.carry=(uint16_t)(R.ax<UINT16_C(0xba00));
        if (signed_word(R.ax)<signed_word(UINT16_C(0xba00))) R.ax=UINT16_C(0xba00);
        else { c.r.carry=(uint16_t)(R.ax<UINT16_C(0x4600));if (signed_word(R.ax)>signed_word(UINT16_C(0x4600))) R.ax=UINT16_C(0x4600); }
        PW(0x2c24,R.ax);R.ax=(uint16_t)((R.ax&UINT16_C(0xff00))|(R.ax>>8));lookup_raw(m,&c.r);++out->lookups;signed_sum=add(&c,&R.ax,W(0x2c20));PW(0x2c20,R.ax);
        if (signed_sum<0) { negate(&c,&R.ax);multiply(&c,W(R.si+0x26f6));negate(&c,&R.dx); }
        else multiply(&c,W(R.si+0x26f6));
        add(&c,&R.dx,40);PW(R.si+0x2a90,R.dx);R.cx=W(R.si+0x275a);c.r.bp=R.cx;shr(&c,&c.r.bp,2);R.ax=R.dx;sub(&c,&R.ax,R.cx);
        if (B(0x37f6)!=0) {
            R.dx=(uint16_t)(W(0x2c26)+1);sub(&c,&R.dx,W(0x700));c.r.carry=(uint16_t)(R.dx<8);
            if (R.dx<8) {
                c.r.carry=0;
                if ((B(0x2c96)&128)==0) { negate(&c,&R.dx);add(&c,&R.dx,8); }
                saved=R.ax;R.ax=R.cx;multiply(&c,R.dx);shr(&c,&R.ax,3);R.dx=R.ax;R.ax=saved;sub(&c,&R.ax,R.dx);
            } else { c.r.carry=0;if (B(0x2c96)&128) sub(&c,&R.ax,R.cx); }
        }
        PW(R.si+0x2a5e,R.ax);sub(&c,&R.ax,c.r.bp);PW(R.si+0x2a2c,R.ax);R.bx=(uint16_t)((R.bx&UINT16_C(0xff00))|B(0x2c97));flags=(uint8_t)R.bx;
        c.r.carry=0;
        if ((flags&UINT8_C(0xc0))!=0) {
            if (flags&128) add(&c,&R.ax,c.r.bp);
            v=W(0x2c66);c.r.carry=(uint16_t)(R.ax<v);
            if (signed_word(R.ax)>signed_word(v)) { PW(0x2c66,R.ax);PW(0x2c6a,R.si);PB(0x2c9a,flags);goto left_done; }
        }
        R.ax=W(R.si+0x2a2c);c.r.carry=0;
        if (R.si!=0) {
            v=W(R.si+0x2a2a);c.r.carry=(uint16_t)(R.ax<v);
            if (signed_word(R.ax)<signed_word(v)) {
                R.di=W(R.si+0x2b26);v=W(0x2c2a);c.r.carry=(uint16_t)(R.di<v);
                if (signed_word(R.di)<=signed_word(v)) { v=W(0x2c2e);c.r.carry=(uint16_t)(R.ax<v);if (signed_word(R.ax)<signed_word(v)) { PW(0x2c2e,R.ax);PW(0x2c6e,R.si); } }
            }
        }
left_done:
        R.cx=W(R.si+0x275a);R.ax=W(R.si+0x2a90);add(&c,&R.ax,R.cx);R.dx=(uint16_t)(W(0x2c26)+1);sub(&c,&R.dx,W(0x700));c.r.carry=(uint16_t)(R.dx<8);
        if (R.dx<8) {
            c.r.carry=0;if ((B(0x2c96)&128)==0) { negate(&c,&R.dx);add(&c,&R.dx,8); }
            saved=R.ax;R.ax=R.cx;multiply(&c,R.dx);shr(&c,&R.ax,3);R.dx=saved;add(&c,&R.ax,R.dx);
        } else { c.r.carry=0;if (B(0x2c96)&128) add(&c,&R.ax,R.cx); }
        PW(R.si+0x2ac2,R.ax);add(&c,&R.ax,c.r.bp);PW(R.si+0x2af4,R.ax);R.cx=R.ax;c.r.carry=0;
        if ((flags&UINT8_C(0x88))!=0) {
            if (flags&128) sub(&c,&R.ax,c.r.bp);
            v=W(0x2c2c);c.r.carry=(uint16_t)(R.ax<v);
            if (signed_word(R.ax)<signed_word(v)) { PW(0x2c2c,R.ax);PW(0x2c6c,R.si);PB(0x2c9b,flags);goto right_done; }
        }
        R.ax=W(R.si+0x2af4);c.r.carry=0;
        if (R.si!=0) {
            v=W(R.si+0x2af2);c.r.carry=(uint16_t)(R.ax<v);
            if (signed_word(R.ax)>signed_word(v)) {
                R.di=W(R.si+0x2b26);v=W(0x2c2a);c.r.carry=(uint16_t)(R.di<v);
                if (signed_word(R.di)<=signed_word(v)) { v=W(0x2c68);c.r.carry=(uint16_t)(R.ax<v);if (signed_word(R.ax)>signed_word(v)) { PW(0x2c68,R.ax);PW(0x2c70,R.si); } }
            }
        }
right_done:
        R.bx=0;c.r.carry=0;R.dx=W(0x2c26);sub(&c,&R.dx,UINT16_C(0x3b33));
        for (;;) {
            if (!step(&c)) goto finish;
            ++out->scans;node=R.bx;start=W(node+0x37a6);c.r.carry=0;
            if (start==0) { R.cx=UINT16_C(0x280);break; }
            c.r.bp=W(node+0x37a8);c.r.carry=(uint16_t)(R.dx<c.r.bp);
            if (R.dx>c.r.bp) { add(&c,&R.bx,8);continue; }
            R.ax=start;sub(&c,&R.dx,R.ax);
            if (c.r.carry) { R.cx=UINT16_C(0x280);break; }
            sub(&c,&c.r.bp,R.ax);R.ax=W(node+0x37ac);R.bx=W(node+0x37aa);sub(&c,&R.ax,R.bx);
            product=signed_word(R.ax)*signed_word(R.dx);R.ax=(uint16_t)product;R.dx=(uint16_t)((uint32_t)product>>16);c.r.carry=(uint16_t)(product<-32768 || product>32767);
            if (signed_word(c.r.bp)==0) { out->status=1;out->fault_site=UINT16_C(0x23fa);goto finish; }
            quotient=(int64_t)product/signed_word(c.r.bp);remainder=(int64_t)product%signed_word(c.r.bp);
            if (quotient<-32768 || quotient>32767) { out->status=1;out->fault_site=UINT16_C(0x23fa);goto finish; }
            R.ax=(uint16_t)quotient;R.dx=(uint16_t)remainder;add(&c,&R.ax,R.bx);multiply(&c,W(R.si+0x275a));oldax=R.ax;R.ax=(uint16_t)((oldax>>8)|((R.dx&255)<<8));add(&c,&R.cx,R.ax);break;
        }
        PW(R.si+0x2bee,R.cx);R.ax=W(R.si+0x2b26);R.bx=W(R.si+0x275a);shr(&c,&R.bx,1);negate(&c,&R.bx);signed_sum=add(&c,&R.bx,R.ax);
        if (signed_sum<=0) { R.bx=0;c.r.carry=0; }
        c.r.carry=(uint16_t)(R.ax<17);if (signed_word(R.ax)>=17) R.ax=17;c.r.carry=0;
        if (B(0x2c92)>=128) {
            c.r.carry=0;
            if (B(0x2c97)<128) { PW(0x2c76,R.si);PW(0x2c78,R.ax);PW(0x2c7c,R.bx); }
            else { PW(0x2c74,R.si);PW(0x2c30,R.ax);PW(0x2c7a,R.bx); }
        }
        c.r.carry=0;
        if (B(0x2c97)&128) { v=W(0x2c7e);c.r.carry=(uint16_t)(R.bx<v);if (signed_word(R.bx)>=signed_word(v)) { PW(0x2c7e,R.bx);PW(0x2c80,R.si); } }
        R.si=(uint16_t)(R.si+2);c.r.carry=(uint16_t)(R.si<50);
    } while (R.si!=50);
    PW(0x2b58,17);out->status=0;
finish:
    out->returned=c.r;
#undef R
#undef W
#undef B
#undef PW
#undef PB
}
