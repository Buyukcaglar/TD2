#include "td2ega_line_draw.h"
#include <stddef.h>
typedef struct line_context {
    uint8_t *m;uint16_t cs,ss,sp,locals[12];uint32_t limit;
    td2ega_state_registers r;td2ega_line_draw_service service;void *context;
    td2ega_line_draw_result *out;
} line_context;
static uint32_t address(uint16_t s,uint16_t o)
{ return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff); }
static uint16_t word(const uint8_t *m,uint16_t s,uint16_t o)
{ uint32_t a=address(s,o);return (uint16_t)(m[a]|((uint16_t)m[(a+1)&UINT32_C(0xfffff)]<<8)); }
static uint16_t code_word(line_context *c,uint16_t o)
{ return word(c->m,c->cs,o); }
static uint16_t argument(line_context *c,uint16_t o)
{ return word(c->m,c->ss,(uint16_t)(c->r.bp+o)); }
static int32_t sw(uint16_t v)
{ return v<UINT16_C(0x8000)?v:(int32_t)v-INT32_C(65536); }
static void al(line_context *c,uint16_t v)
{ c->r.registers.ax=(uint16_t)((c->r.registers.ax&UINT16_C(0xff00))|(v&255)); }
static void ah(line_context *c,uint16_t v)
{ c->r.registers.ax=(uint16_t)((c->r.registers.ax&255)|((v&255)<<8)); }
static int32_t compare(line_context *c,uint16_t a,uint16_t b)
{ c->r.carry=(uint16_t)(a<b);return sw(a)-sw(b); }
static void add(line_context *c,uint16_t *a,uint16_t b)
{ uint32_t n=(uint32_t)*a+b;*a=(uint16_t)n;c->r.carry=(uint16_t)(n>>16); }
static void adc(line_context *c,uint16_t *a,uint16_t b)
{ uint32_t n=(uint32_t)*a+b+c->r.carry;*a=(uint16_t)n;c->r.carry=(uint16_t)(n>>16); }
static int32_t sub(line_context *c,uint16_t *a,uint16_t b)
{ int32_t relation=sw(*a)-sw(b);c->r.carry=(uint16_t)(*a<b);*a=(uint16_t)(*a-b);return relation; }
static void negate(line_context *c,uint16_t *a)
{ c->r.carry=(uint16_t)(*a!=0);*a=(uint16_t)(0-*a); }
static void shl(line_context *c,uint16_t *a)
{ c->r.carry=(uint16_t)(*a>>15);*a=(uint16_t)(*a<<1); }
static void shr(line_context *c,uint16_t *a)
{ c->r.carry=(uint16_t)(*a&1);*a=(uint16_t)(*a>>1); }
static int step(line_context *c,int iteration)
{
    if (c->out->work==c->limit) { c->out->status=3;return 0; }
    ++c->out->work;if (iteration)++c->out->iterations;return 1;
}
static int service(line_context *c,uint16_t kind,uint16_t site,
    uint32_t bus_address,uint16_t *value,const uint16_t *args)
{
    td2ega_line_draw_request q={0};td2ega_line_draw_response r={0};unsigned i;
    if (!step(c,0))return 0;
    if (kind==0)c->sp=(uint16_t)(c->sp-4);
    q.kind=kind;q.site=site;q.segment=c->cs;q.offset=kind==0?UINT16_C(0x8a0c):0;q.stack_segment=c->ss;q.stack_sp=c->sp;q.port=c->r.registers.dx;q.value=value?*value:0;q.address=bus_address;q.incoming=c->r;
    if (args!=NULL)for(i=0;i<5;++i)q.arguments[i]=args[i];
    r.returned=c->r;r.value=q.value;++c->out->calls;
    if (!c->service(c->context,c->m,&q,&r)) { c->out->status=4;return 0; }
    if (kind==0) {
        c->r=r.returned;
        if (c->r.carry>1 || c->r.registers.interrupts_enabled>1 || c->r.registers.direction>1) { c->out->status=2;return 0; }
    } else if (kind==2) {
        if (r.value>255) { c->out->status=2;return 0; }
        *value=r.value;
    }
    return 1;
}
static int output(line_context *c,uint16_t site)
{ uint16_t v=(uint8_t)c->r.registers.ax;return service(c,1,site,0,&v,NULL); }
static void mask_and(line_context *c,uint8_t value)
{ c->m[address(c->r.registers.es,c->r.registers.di)]&=value;c->r.carry=0;++c->out->writes; }
static void mask_or(line_context *c,uint8_t value)
{ c->m[address(c->r.registers.es,c->r.registers.di)]|=value;c->r.carry=0;++c->out->writes; }
static int divide(line_context *c,uint16_t site)
{
    uint32_t dividend=((uint32_t)c->r.registers.dx<<16)|c->r.registers.ax;uint16_t d=c->r.registers.cx;
    if (d==0 || dividend/d>65535) { c->out->status=1;c->out->fault_site=site;return 0; }
    c->r.registers.ax=(uint16_t)(dividend/d);c->r.registers.dx=(uint16_t)(dividend%d);return 1;
}
void td2ega_line_draw(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,
    uint16_t sp,const td2ega_state_registers *in,td2ega_line_draw_service adapter,
    void *context,uint32_t limit,td2ega_line_draw_result *out)
{
    line_context c;uint16_t v,args[5];unsigned i;int32_t relation;
    if(out==NULL)return;
    *out=(td2ega_line_draw_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || adapter==NULL || sp<256 || sp>UINT16_C(0xffe0) || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1)return;
    c=(line_context){0};c.m=m;c.cs=(uint16_t)(load+0x6c9);c.ss=ss;c.sp=(uint16_t)(sp-24);c.limit=limit;c.r=*in;c.service=adapter;c.context=context;c.out=out;c.r.bp=(uint16_t)(sp-2);
#define R c.r.registers
#define L(n) c.locals[(n)/2]
#define A(n) argument(&c,n)
#define CW(n) code_word(&c,n)
#define CMP(a,b) compare(&c,a,b)
#define STEP() do { if(!step(&c,1))goto finish; } while(0)
#define OUT(s) do { if(!output(&c,s))goto finish; } while(0)
    R.ax=c.cs;R.ds=R.ax;R.es=CW(0xaf3c);R.ax=CW(0xaf46);for(i=0;i<3;++i)shl(&c,&R.ax);L(0x14)=R.ax;R.ax=CW(0xaf48);for(i=0;i<3;++i)shl(&c,&R.ax);L(0x16)=R.ax;R.ax=A(8);
    if(CMP(R.ax,A(12))!=0)goto vertical;
    if(CMP(R.ax,CW(0xaf4a))<0)goto cleanup;
    if(CMP(R.ax,CW(0xaf4c))>=0)goto cleanup;
    R.cx=A(10);sub(&c,&R.cx,A(6));
    if((R.cx&UINT16_C(0x8000))==0)R.bx=A(6);
    else { negate(&c,&R.cx);R.bx=A(10); }
    R.cx=(uint16_t)(R.cx+1);
    if(CMP(R.bx,L(0x14))<0) {
        add(&c,&R.cx,R.bx);relation=sub(&c,&R.cx,L(0x14));if(relation<=0)goto cleanup;R.bx=L(0x14);
    }
    if(CMP(R.bx,L(0x16))>=0)goto cleanup;
    R.ax=R.cx;add(&c,&R.ax,R.bx);relation=sub(&c,&R.ax,L(0x16));if(relation>0)sub(&c,&R.cx,R.ax);
    R.ds=in->registers.ds;args[4]=A(14);R.ax=1;args[3]=R.ax;args[2]=R.cx;args[1]=A(8);args[0]=R.bx;c.sp=(uint16_t)(c.sp-10);
    if(!service(&c,0,0x8611,0,NULL,args))goto finish;
    c.sp=(uint16_t)(c.sp+14);c.r.carry=0;goto cleanup;
vertical:
    R.ax=A(6);if(CMP(R.ax,A(10))!=0)goto general;
    if(CMP(R.ax,L(0x14))<0)goto cleanup;
    if(CMP(R.ax,L(0x16))>=0)goto cleanup;
    R.cx=A(12);relation=sub(&c,&R.cx,A(8));if(relation>=0)R.si=A(8);else{negate(&c,&R.cx);R.si=A(12);}R.cx=(uint16_t)(R.cx+1);
    if(CMP(R.si,CW(0xaf4a))<0){add(&c,&R.cx,R.si);relation=sub(&c,&R.cx,CW(0xaf4a));if(relation<=0)goto cleanup;R.si=CW(0xaf4a);}
    if(CMP(R.si,CW(0xaf4c))>=0)goto cleanup;
    R.ax=R.cx;add(&c,&R.ax,R.si);relation=sub(&c,&R.ax,CW(0xaf4c));if(relation>0)sub(&c,&R.cx,R.ax);
    R.ds=in->registers.ds;args[4]=A(14);args[3]=R.cx;R.ax=1;args[2]=R.ax;args[1]=R.si;args[0]=A(6);c.sp=(uint16_t)(c.sp-10);
    if(!service(&c,0,0x867b,0,NULL,args))goto finish;
    c.sp=(uint16_t)(c.sp+14);c.r.carry=0;goto cleanup;
general:
    R.ax=0;c.r.carry=0;L(10)=0;L(14)=0;R.bx=A(10);sub(&c,&R.bx,A(6));if(R.bx&UINT16_C(0x8000)){negate(&c,&R.bx);al(&c,1);}R.bx=(uint16_t)(R.bx+1);R.cx=A(12);sub(&c,&R.cx,A(8));if(R.cx&UINT16_C(0x8000)){ah(&c,1);negate(&c,&R.cx);}R.cx=(uint16_t)(R.cx+1);
    if(CMP(R.bx,R.cx)<0)goto ymajor;
    c.r.carry=0;
    if((uint8_t)R.ax!=0){R.si=A(10);L(8)=R.si;R.si=A(12);L(12)=R.si;ah(&c,(R.ax>>8)^1);c.r.carry=0;}
    else{R.si=A(6);L(8)=R.si;R.si=A(8);L(12)=R.si;}
    if(CMP(R.bx,R.cx)==0){R.bx=R.ax;R.ax=0;c.r.carry=0;R.dx=1;c.r.carry=0;if((R.bx>>8)!=0)negate(&c,&R.dx);}
    else{R.dx=R.cx;R.cx=R.bx;R.bx=R.ax;R.ax=0;c.r.carry=0;if(!divide(&c,0x86eb))goto finish;R.dx=0;c.r.carry=0;if((R.bx>>8)!=0){R.dx=UINT16_C(0xffff);L(14)=R.dx;negate(&c,&R.ax);}}
    L(18)=R.ax;L(16)=R.dx;R.dx=L(8);goto clip_x;
ymajor:
    c.r.carry=0;if((R.ax>>8)!=0){R.si=A(10);L(8)=R.si;R.si=A(12);L(12)=R.si;al(&c,(uint8_t)R.ax^1);c.r.carry=0;}else{R.si=A(6);L(8)=R.si;R.si=A(8);L(12)=R.si;}
    R.dx=R.bx;R.bx=R.ax;R.ax=0;c.r.carry=0;if(!divide(&c,0x8730))goto finish;R.dx=0;c.r.carry=0;if((uint8_t)R.bx!=0){R.dx=UINT16_C(0xffff);L(10)=R.dx;negate(&c,&R.ax);}L(18)=R.ax;L(16)=R.dx;R.si=L(12);goto clip_y;
clip_x:
    STEP();R.bx=L(12);if(CMP(R.bx,CW(0xaf4a))<0)goto skip_x;if(CMP(R.bx,CW(0xaf4c))>=0)goto skip_x;if(CMP(R.dx,L(20))<0)goto skip_x;if(CMP(R.dx,L(22))>=0)goto cleanup;goto draw_x;
skip_x:
    R.dx=(uint16_t)(R.dx+1);R.ax=L(18);add(&c,&L(14),R.ax);R.ax=L(16);adc(&c,&L(12),R.ax);R.cx=(uint16_t)(R.cx-1);if(R.cx!=0)goto clip_x;goto cleanup;
clip_y:
    STEP();R.dx=L(8);if(CMP(R.dx,L(20))<0)goto skip_y;if(CMP(R.dx,L(22))>=0)goto skip_y;if(CMP(R.si,CW(0xaf4a))<0)goto skip_y;if(CMP(R.si,CW(0xaf4c))>=0)goto cleanup;goto draw_y;
skip_y:
    R.si=(uint16_t)(R.si+1);R.ax=L(18);add(&c,&L(10),R.ax);R.ax=L(16);adc(&c,&L(8),R.ax);R.cx=(uint16_t)(R.cx-1);if(R.cx!=0)goto clip_y;goto cleanup;
draw_y:
    if(CMP(CW(0xaf3c),UINT16_C(0xa000))==0)goto ega_y;
ram_y:
    STEP();if(CMP(R.si,CW(0xaf4c))>=0)goto cleanup;R.dx=L(8);if(CMP(R.dx,L(20))<0)goto cleanup;if(CMP(R.dx,L(22))>=0)goto cleanup;
    R.bx=R.si;shl(&c,&R.bx);add(&c,&R.bx,CW(0xaf44));R.di=word(m,R.ds,R.bx);R.bx=R.dx;R.bx&=7;c.r.carry=0;al(&c,m[address(c.cs,(uint16_t)(R.bx-0x7a86))]);ah(&c,(uint8_t)R.ax^255);R.bx=R.dx;for(i=0;i<3;++i)shr(&c,&R.bx);add(&c,&R.di,R.bx);R.bx=0;c.r.carry=0;R.dx=A(14);
    do {
        v=CW((uint16_t)(R.bx-0x50c4));c.r.carry=0;
        if(v!=0){R.es=CW((uint16_t)(R.bx-0x50c4));mask_and(&c,(uint8_t)(R.ax>>8));c.r.carry=0;if(R.dx&1)mask_or(&c,(uint8_t)R.ax);}
        shr(&c,&R.dx);add(&c,&R.bx,2);
    }while(CMP(R.bx,8)<0);
    R.si=(uint16_t)(R.si+1);R.ax=L(18);add(&c,&L(10),R.ax);R.ax=L(16);adc(&c,&L(8),R.ax);R.cx=(uint16_t)(R.cx-1);if(R.cx!=0)goto ram_y;goto cleanup;
ega_y:
    R.dx=0x3ce;al(&c,5);OUT(0x882b);R.dx=(uint16_t)(R.dx+1);al(&c,2);OUT(0x882f);R.dx=0x3c4;al(&c,2);OUT(0x8835);R.dx=(uint16_t)(R.dx+1);al(&c,15);OUT(0x8839);
ega_y_loop:
    STEP();if(CMP(R.si,CW(0xaf4c))>=0)goto ega_y_end;R.dx=L(8);if(CMP(R.dx,L(20))<0)goto ega_y_end;if(CMP(R.dx,L(22))>=0)goto ega_y_end;
    R.bx=R.si;shl(&c,&R.bx);add(&c,&R.bx,CW(0xaf44));R.di=word(m,R.ds,R.bx);R.bx=R.dx;for(i=0;i<3;++i)shr(&c,&R.bx);add(&c,&R.di,R.bx);R.bx=R.dx;R.bx&=7;c.r.carry=0;R.bx=(uint16_t)((R.bx&UINT16_C(0xff00))|m[address(c.cs,(uint16_t)(R.bx-0x7a86))]);R.dx=0x3ce;al(&c,8);OUT(0x8872);R.dx=(uint16_t)(R.dx+1);al(&c,(uint8_t)R.bx);OUT(0x8876);R.ax=A(14);v=m[address(R.es,R.di)];if(!service(&c,2,0x887a,address(R.es,R.di),&v,NULL))goto finish;ah(&c,v);v=(uint8_t)R.ax;if(!service(&c,3,0x887d,address(R.es,R.di),&v,NULL))goto finish;++out->writes;
    R.si=(uint16_t)(R.si+1);R.ax=L(18);add(&c,&L(10),R.ax);R.ax=L(16);adc(&c,&L(8),R.ax);R.cx=(uint16_t)(R.cx-1);if(R.cx!=0)goto ega_y_loop;
ega_y_end:
    R.dx=0x3ce;al(&c,5);OUT(0x8894);R.dx=(uint16_t)(R.dx+1);al(&c,0);OUT(0x8898);R.dx=0x3ce;al(&c,8);OUT(0x889e);R.dx=(uint16_t)(R.dx+1);al(&c,0);OUT(0x88a2);goto cleanup;
draw_x:
    if(CMP(CW(0xaf3c),UINT16_C(0xa000))==0)goto ega_x;
ram_x:
    STEP();R.bx=L(12);if(CMP(R.bx,CW(0xaf4a))<0)goto cleanup;if(CMP(R.bx,CW(0xaf4c))>=0)goto cleanup;if(CMP(R.dx,L(22))>=0)goto cleanup;
    shl(&c,&R.bx);add(&c,&R.bx,CW(0xaf44));R.di=word(m,R.ds,R.bx);R.bx=R.dx;R.bx&=7;c.r.carry=0;al(&c,m[address(c.cs,(uint16_t)(R.bx-0x7a86))]);ah(&c,(uint8_t)R.ax^255);R.bx=R.dx;for(i=0;i<3;++i)shr(&c,&R.bx);add(&c,&R.di,R.bx);R.bx=0;c.r.carry=0;R.si=A(14);
    do {
        v=CW((uint16_t)(R.bx-0x50c4));c.r.carry=0;
        if(v!=0){R.es=CW((uint16_t)(R.bx-0x50c4));mask_and(&c,(uint8_t)(R.ax>>8));c.r.carry=0;if(R.si&1)mask_or(&c,(uint8_t)R.ax);}
        shr(&c,&R.si);add(&c,&R.bx,2);
    }while(CMP(R.bx,8)<0);
    R.dx=(uint16_t)(R.dx+1);R.ax=L(18);add(&c,&L(14),R.ax);R.ax=L(16);adc(&c,&L(12),R.ax);R.cx=(uint16_t)(R.cx-1);if(R.cx!=0)goto ram_x;goto cleanup;
ega_x:
    R.si=R.dx;R.dx=0x3ce;al(&c,5);OUT(0x8927);R.dx=(uint16_t)(R.dx+1);al(&c,2);OUT(0x892b);R.dx=0x3c4;al(&c,2);OUT(0x8931);R.dx=(uint16_t)(R.dx+1);al(&c,15);OUT(0x8935);
ega_x_loop:
    STEP();R.bx=L(12);if(CMP(R.bx,CW(0xaf4a))<0)goto ega_x_end;if(CMP(R.bx,CW(0xaf4c))>=0)goto ega_x_end;if(CMP(R.si,L(22))>=0)goto ega_x_end;
    shl(&c,&R.bx);add(&c,&R.bx,CW(0xaf44));R.di=word(m,R.ds,R.bx);R.bx=R.si;for(i=0;i<3;++i)shr(&c,&R.bx);add(&c,&R.di,R.bx);R.bx=R.si;R.bx&=7;c.r.carry=0;R.bx=(uint16_t)((R.bx&UINT16_C(0xff00))|m[address(c.cs,(uint16_t)(R.bx-0x7a86))]);R.dx=0x3ce;al(&c,8);OUT(0x896e);R.dx=(uint16_t)(R.dx+1);al(&c,(uint8_t)R.bx);OUT(0x8972);R.ax=A(14);v=m[address(R.es,R.di)];if(!service(&c,2,0x8976,address(R.es,R.di),&v,NULL))goto finish;ah(&c,v);v=(uint8_t)R.ax;if(!service(&c,3,0x8979,address(R.es,R.di),&v,NULL))goto finish;++out->writes;
    R.si=(uint16_t)(R.si+1);R.ax=L(18);add(&c,&L(14),R.ax);R.ax=L(16);adc(&c,&L(12),R.ax);R.cx=(uint16_t)(R.cx-1);if(R.cx!=0)goto ega_x_loop;
ega_x_end:
    R.dx=0x3ce;al(&c,5);OUT(0x8990);R.dx=(uint16_t)(R.dx+1);al(&c,0);OUT(0x8994);R.dx=0x3ce;al(&c,8);OUT(0x899a);R.dx=(uint16_t)(R.dx+1);al(&c,0);OUT(0x899e);
cleanup:
    c.r.carry=0;R.di=in->registers.di;R.si=in->registers.si;R.ds=in->registers.ds;c.r.bp=in->bp;c.sp=(uint16_t)(sp+4);out->status=0;
finish:
    out->current_sp=c.sp;out->returned=c.r;
#undef R
#undef L
#undef A
#undef CW
#undef CMP
#undef STEP
#undef OUT
}
