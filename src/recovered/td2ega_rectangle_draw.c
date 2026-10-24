#include "td2ega_rectangle_draw.h"
#include <stddef.h>
typedef struct rectangle_context {
    uint8_t *m;uint16_t cs,ss,sp,locals[4];uint32_t limit;
    td2ega_state_registers r;td2ega_line_draw_service service;void *context;
    td2ega_line_draw_result *out;
} rectangle_context;
static uint32_t address(uint16_t s,uint16_t o)
{ return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff); }
static uint16_t word(const uint8_t *m,uint16_t s,uint16_t o)
{ uint32_t a=address(s,o);return (uint16_t)(m[a]|((uint16_t)m[(a+1)&UINT32_C(0xfffff)]<<8)); }
static uint16_t argument(rectangle_context *c,uint16_t o)
{ return word(c->m,c->ss,(uint16_t)(c->r.bp+o)); }
static void put_argument(rectangle_context *c,uint16_t o,uint16_t v)
{ uint32_t a=address(c->ss,(uint16_t)(c->r.bp+o));c->m[a]=(uint8_t)v;c->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8); }
static int32_t sw(uint16_t v)
{ return v<UINT16_C(0x8000)?v:(int32_t)v-INT32_C(65536); }
static int32_t compare(rectangle_context *c,uint16_t a,uint16_t b)
{ c->r.carry=(uint16_t)(a<b);return sw(a)-sw(b); }
static void add(rectangle_context *c,uint16_t *a,uint16_t b)
{ uint32_t n=(uint32_t)*a+b;*a=(uint16_t)n;c->r.carry=(uint16_t)(n>>16); }
static int32_t sub(rectangle_context *c,uint16_t *a,uint16_t b)
{ int32_t relation=sw(*a)-sw(b);c->r.carry=(uint16_t)(*a<b);*a=(uint16_t)(*a-b);return relation; }
static void shl(rectangle_context *c,uint16_t *a)
{ c->r.carry=(uint16_t)(*a>>15);*a=(uint16_t)(*a<<1); }
static void sar(rectangle_context *c,uint16_t *a)
{ c->r.carry=(uint16_t)(*a&1);*a=(uint16_t)((*a>>1)|(*a&UINT16_C(0x8000))); }
static void al(rectangle_context *c,uint16_t v)
{ c->r.registers.ax=(uint16_t)((c->r.registers.ax&UINT16_C(0xff00))|(v&255)); }
static void ah(rectangle_context *c,uint16_t v)
{ c->r.registers.ax=(uint16_t)((c->r.registers.ax&255)|((v&255)<<8)); }
static int step(rectangle_context *c,int iteration)
{ if(c->out->work==c->limit){c->out->status=3;return 0;}++c->out->work;if(iteration)++c->out->iterations;return 1; }
static int device(rectangle_context *c,uint16_t kind,uint16_t site,uint16_t *value)
{
    td2ega_line_draw_request q={0};td2ega_line_draw_response r={0};
    if(!step(c,0))return 0;
    q.kind=kind;q.site=site;q.segment=c->cs;q.stack_segment=c->ss;q.stack_sp=c->sp;q.port=c->r.registers.dx;q.value=*value;q.incoming=c->r;
    if(kind!=1)q.address=address(c->r.registers.es,c->r.registers.di);
    r.returned=c->r;r.value=q.value;++c->out->calls;
    if(!c->service(c->context,c->m,&q,&r)){c->out->status=4;return 0;}
    if(kind==2){if(r.value>255){c->out->status=2;return 0;}*value=r.value;}
    return 1;
}
static int output(rectangle_context *c,uint16_t site)
{ uint16_t value=(uint8_t)c->r.registers.ax;return device(c,1,site,&value); }
static int pixel(rectangle_context *c,uint16_t read_site,uint16_t write_site)
{
    uint16_t value=c->m[address(c->r.registers.es,c->r.registers.di)];
    if(!device(c,2,read_site,&value))return 0;
    ah(c,value);value=(uint8_t)c->r.registers.ax;
    if(!device(c,3,write_site,&value))return 0;
    ++c->out->writes;return 1;
}
static void bits(rectangle_context *c,uint8_t mask,int set)
{ uint32_t a=address(c->r.registers.es,c->r.registers.di);if(set)c->m[a]|=mask;else c->m[a]&=mask;c->r.carry=0;++c->out->writes; }
static int repeat(rectangle_context *c)
{
    while(c->r.registers.cx!=0){if(!step(c,1))return 0;c->m[address(c->r.registers.es,c->r.registers.di)]=(uint8_t)c->r.registers.ax;c->r.registers.di=(uint16_t)(c->r.registers.di+1);--c->r.registers.cx;++c->out->writes;}return 1;
}
void td2ega_rectangle_draw(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,
    uint16_t sp,uint16_t entry,const td2ega_state_registers *in,
    td2ega_line_draw_service adapter,void *context,uint32_t limit,
    td2ega_line_draw_result *out)
{
    rectangle_context c;uint16_t v,old;int32_t relation;int set;unsigned i;
    if(out==NULL)return;
    *out=(td2ega_line_draw_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || adapter==NULL || entry>1 || sp<256 || sp>UINT16_C(0xffe0) || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1)return;
    c=(rectangle_context){0};c.m=m;c.cs=(uint16_t)(load+0x6c9);c.ss=ss;c.sp=(uint16_t)(sp-14);c.limit=limit;c.r=*in;c.r.bp=(uint16_t)(sp-2);c.service=adapter;c.context=context;c.out=out;
#define R c.r.registers
#define A(n) argument(&c,n)
#define PA(n,vv) put_argument(&c,n,vv)
#define CW(n) word(m,c.cs,(uint16_t)(n))
#define L(n) c.locals[((n)-6)/2]
#define CMP(a,b) compare(&c,a,b)
#define STEP() do{if(!step(&c,1))goto finish;}while(0)
#define OUT(site) do{if(!output(&c,site))goto finish;}while(0)
#define PIXEL(rd,wr) do{if(!pixel(&c,rd,wr))goto finish;}while(0)
    if(entry==0){
        R.dx=CW(0xaf46);for(i=0;i<3;++i)shl(&c,&R.dx);R.ax=R.dx;relation=sub(&c,&R.ax,A(6));
        if(relation>0){PA(6,R.dx);v=A(10);relation=sub(&c,&v,R.ax);PA(10,v);if(relation<=0)goto cleanup;}
        R.ax=A(6);add(&c,&R.ax,A(10));R.bx=CW(0xaf48);for(i=0;i<3;++i)shl(&c,&R.bx);relation=sub(&c,&R.ax,R.bx);
        if(relation>0){v=A(10);relation=sub(&c,&v,R.ax);PA(10,v);if(relation<=0)goto cleanup;}
        R.ax=CW(0xaf4a);relation=sub(&c,&R.ax,A(8));
        if(relation>0){R.bx=CW(0xaf4a);PA(8,R.bx);v=A(12);relation=sub(&c,&v,R.ax);PA(12,v);if(relation<=0)goto cleanup;}
        R.ax=A(8);add(&c,&R.ax,A(12));relation=sub(&c,&R.ax,CW(0xaf4c));
        if(relation>0){v=A(12);relation=sub(&c,&v,R.ax);PA(12,v);if(relation<=0)goto cleanup;}
    }
    R.direction=0;if(CMP(A(10),0)<=0)goto cleanup;if(CMP(A(12),0)<=0)goto cleanup;
    R.es=CW(0xaf3c);R.cx=A(6);R.bx=R.cx;for(i=0;i<3;++i)sar(&c,&R.bx);L(12)=R.bx;R.bx=R.cx;R.bx&=7;c.r.carry=0;R.dx=(uint16_t)((R.dx&255)|((uint16_t)m[address(R.ds,(uint16_t)(R.bx+0x6838))]<<8));add(&c,&R.cx,A(10));R.cx=(uint16_t)(R.cx-1);R.bx=R.cx;R.bx&=7;c.r.carry=0;R.dx=(uint16_t)((R.dx&UINT16_C(0xff00))|m[address(R.ds,(uint16_t)(R.bx+0x6840))]);for(i=0;i<3;++i)sar(&c,&R.cx);sub(&c,&R.cx,L(12));R.bx=A(8);shl(&c,&R.bx);add(&c,&R.bx,CW(0xaf44));R.di=CW(R.bx);add(&c,&R.di,L(12));L(6)=R.di;R.ax=CW(0xaf4e);sub(&c,&R.ax,R.cx);L(8)=R.ax;
    if(CMP(CW(0xaf3c),UINT16_C(0xa000))==0)goto hardware;
    R.si=0xaf3c;old=R.cx;R.cx=(uint16_t)(R.cx-1);relation=sw(old)-1;L(10)=R.cx;
    if(relation>0)goto ram_wide;
    if(R.cx==0)goto ram_two;
    R.dx=(uint16_t)((R.dx&255)|((uint16_t)((R.dx>>8)&R.dx&255)<<8));c.r.carry=0;R.dx=(uint16_t)((R.dx&UINT16_C(0xff00))|(R.dx>>8));R.dx=(uint16_t)((R.dx&UINT16_C(0xff00))|((uint8_t)R.dx^255));al(&c,(uint8_t)A(14));ah(&c,4);R.bx=L(8);
ram_one_plane:
    STEP();if(CMP(CW(R.si),0)==0)goto ram_one_next;R.es=CW(R.si);R.di=L(6);R.cx=A(12);c.r.carry=0;set=(R.ax&1)!=0;
ram_one_row:
    STEP();bits(&c,(uint8_t)(set?(R.dx>>8):R.dx),set);add(&c,&R.di,R.bx);R.cx=(uint16_t)(R.cx-1);if(R.cx!=0)goto ram_one_row;
ram_one_next:
    c.r.carry=(uint16_t)(R.ax&1);al(&c,(uint8_t)R.ax>>1);add(&c,&R.si,2);ah(&c,(R.ax>>8)-1);if((int8_t)(R.ax>>8)>0)goto ram_one_plane;goto cleanup;
ram_two:
    al(&c,(uint8_t)A(14));ah(&c,4);R.bx=L(8);
ram_two_plane:
    STEP();if(CMP(CW(R.si),0)==0)goto ram_two_next;R.es=CW(R.si);R.di=L(6);R.cx=A(12);c.r.carry=0;set=(R.ax&1)!=0;if(!set)R.dx=(uint16_t)~R.dx;
ram_two_row:
    STEP();bits(&c,(uint8_t)(R.dx>>8),set);R.di=(uint16_t)(R.di+1);bits(&c,(uint8_t)R.dx,set);add(&c,&R.di,R.bx);R.cx=(uint16_t)(R.cx-1);if(R.cx!=0)goto ram_two_row;if(!set)R.dx=(uint16_t)~R.dx;
ram_two_next:
    c.r.carry=(uint16_t)(R.ax&1);al(&c,(uint8_t)R.ax>>1);add(&c,&R.si,2);ah(&c,(R.ax>>8)-1);if((int8_t)(R.ax>>8)>0)goto ram_two_plane;goto cleanup;
ram_wide:
    ah(&c,4);
ram_wide_plane:
    STEP();if(CMP(CW(R.si),0)==0)goto ram_wide_next;R.es=CW(R.si);R.di=L(6);R.bx=A(12);c.r.carry=0;set=(A(14)&1)!=0;
    if(set)al(&c,255);else{R.dx=(uint16_t)~R.dx;al(&c,0);c.r.carry=0;}
ram_wide_row:
    STEP();bits(&c,(uint8_t)(R.dx>>8),set);R.di=(uint16_t)(R.di+1);R.cx=L(10);if(!repeat(&c))goto finish;bits(&c,(uint8_t)R.dx,set);add(&c,&R.di,L(8));old=R.bx;R.bx=(uint16_t)(R.bx-1);if(sw(old)-1>0)goto ram_wide_row;if(!set)R.dx=(uint16_t)~R.dx;
ram_wide_next:
    v=A(14);c.r.carry=(uint16_t)(v&1);PA(14,(uint16_t)((v&UINT16_C(0xff00))|((uint8_t)v>>1)));add(&c,&R.si,2);ah(&c,(R.ax>>8)-1);if((int8_t)(R.ax>>8)>0)goto ram_wide_plane;goto cleanup;
hardware:
    R.bx=R.dx;R.dx=0x3ce;al(&c,5);OUT(0x8b66);R.dx=(uint16_t)(R.dx+1);al(&c,2);OUT(0x8b6a);R.dx=0x3c4;al(&c,2);OUT(0x8b70);R.dx=(uint16_t)(R.dx+1);al(&c,255);OUT(0x8b74);old=R.cx;R.cx=(uint16_t)(R.cx-1);relation=sw(old)-1;L(10)=R.cx;
    if(relation>0)goto hardware_wide;
    if(R.cx==0)goto hardware_two;
    R.bx=(uint16_t)((R.bx&255)|((uint16_t)((R.bx>>8)&R.bx&255)<<8));c.r.carry=0;R.dx=0x3ce;al(&c,8);OUT(0x8b84);R.dx=(uint16_t)(R.dx+1);al(&c,R.bx>>8);OUT(0x8b88);R.di=L(6);R.cx=A(12);al(&c,(uint8_t)A(14));R.dx=CW(0xaf4e);
hardware_one_row:
    STEP();PIXEL(0x8b97,0x8b9a);add(&c,&R.di,R.dx);R.cx=(uint16_t)(R.cx-1);if(R.cx!=0)goto hardware_one_row;goto hardware_end;
hardware_two:
    R.dx=0x3ce;al(&c,8);OUT(0x8bc4);R.dx=(uint16_t)(R.dx+1);al(&c,R.bx>>8);OUT(0x8bc8);R.di=L(6);R.cx=A(12);al(&c,(uint8_t)A(14));R.dx=CW(0xaf4e);
hardware_two_left:
    STEP();PIXEL(0x8bd7,0x8bda);add(&c,&R.di,R.dx);R.cx=(uint16_t)(R.cx-1);if(R.cx!=0)goto hardware_two_left;
    R.dx=0x3ce;al(&c,8);OUT(0x8be6);R.dx=(uint16_t)(R.dx+1);al(&c,(uint8_t)R.bx);OUT(0x8bea);R.di=L(6);R.di=(uint16_t)(R.di+1);R.cx=A(12);al(&c,(uint8_t)A(14));R.dx=CW(0xaf4e);
hardware_two_right:
    STEP();PIXEL(0x8bfa,0x8bfd);add(&c,&R.di,R.dx);R.cx=(uint16_t)(R.cx-1);if(R.cx!=0)goto hardware_two_right;goto hardware_end;
hardware_wide:
    R.dx=0x3ce;al(&c,8);OUT(0x8c0b);R.dx=(uint16_t)(R.dx+1);al(&c,R.bx>>8);OUT(0x8c0f);R.di=L(6);R.cx=A(12);al(&c,(uint8_t)A(14));R.dx=CW(0xaf4e);
hardware_wide_left:
    STEP();PIXEL(0x8c1e,0x8c21);add(&c,&R.di,R.dx);R.cx=(uint16_t)(R.cx-1);if(R.cx!=0)goto hardware_wide_left;
    R.dx=0x3ce;al(&c,8);OUT(0x8c2d);R.dx=(uint16_t)(R.dx+1);al(&c,(uint8_t)R.bx);OUT(0x8c31);R.di=L(6);add(&c,&R.di,L(10));R.di=(uint16_t)(R.di+1);R.cx=A(12);al(&c,(uint8_t)A(14));R.dx=CW(0xaf4e);
hardware_wide_right:
    STEP();PIXEL(0x8c44,0x8c47);add(&c,&R.di,R.dx);R.cx=(uint16_t)(R.cx-1);if(R.cx!=0)goto hardware_wide_right;
    R.dx=0x3ce;al(&c,8);OUT(0x8c53);R.dx=(uint16_t)(R.dx+1);al(&c,255);OUT(0x8c57);R.di=L(6);R.di=(uint16_t)(R.di+1);R.bx=A(12);al(&c,(uint8_t)A(14));R.dx=L(8);R.dx=(uint16_t)(R.dx+1);
hardware_middle_row:
    STEP();R.cx=L(10);
hardware_middle_byte:
    STEP();PIXEL(0x8c69,0x8c6c);R.di=(uint16_t)(R.di+1);R.cx=(uint16_t)(R.cx-1);if(R.cx!=0)goto hardware_middle_byte;add(&c,&R.di,R.dx);old=R.bx;R.bx=(uint16_t)(R.bx-1);if(sw(old)-1>0)goto hardware_middle_row;
hardware_end:
    R.dx=0x3ce;al(&c,8);OUT(0x8ba6);R.dx=(uint16_t)(R.dx+1);al(&c,255);OUT(0x8baa);R.dx=0x3ce;al(&c,5);OUT(0x8bb0);R.dx=(uint16_t)(R.dx+1);al(&c,0);OUT(0x8bb4);
cleanup:
    c.r.carry=0;R.si=in->registers.si;R.di=in->registers.di;c.r.bp=in->bp;c.sp=(uint16_t)(sp+4);out->status=0;
finish:
    out->current_sp=c.sp;out->returned=c.r;
#undef R
#undef A
#undef PA
#undef CW
#undef L
#undef CMP
#undef STEP
#undef OUT
#undef PIXEL
}
