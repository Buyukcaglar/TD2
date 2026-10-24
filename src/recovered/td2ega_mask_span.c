#include "td2ega_mask_span.h"
#include <stddef.h>
typedef struct mask_context {
    uint8_t *m;uint16_t cs,ss,sp;uint32_t limit;
    td2ega_state_registers r;td2ega_line_draw_service service;void *context;
    td2ega_line_draw_result *out;
} mask_context;
static uint32_t address(uint16_t s,uint16_t o)
{ return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff); }
static int32_t sw(uint16_t v)
{ return v<UINT16_C(0x8000)?v:(int32_t)v-INT32_C(65536); }
static int32_t sb(uint8_t v)
{ return v<128?v:(int32_t)v-256; }
static void al(mask_context *c,uint16_t v)
{ c->r.registers.ax=(uint16_t)((c->r.registers.ax&UINT16_C(0xff00))|(v&255)); }
static void ah(mask_context *c,uint16_t v)
{ c->r.registers.ax=(uint16_t)((c->r.registers.ax&255)|((v&255)<<8)); }
static void dl(mask_context *c,uint16_t v)
{ c->r.registers.dx=(uint16_t)((c->r.registers.dx&UINT16_C(0xff00))|(v&255)); }
static void dh(mask_context *c,uint16_t v)
{ c->r.registers.dx=(uint16_t)((c->r.registers.dx&255)|((v&255)<<8)); }
static void cl(mask_context *c,uint16_t v)
{ c->r.registers.cx=(uint16_t)((c->r.registers.cx&UINT16_C(0xff00))|(v&255)); }
static void add_di(mask_context *c,uint16_t value)
{ uint32_t sum=(uint32_t)c->r.registers.di+value;c->r.registers.di=(uint16_t)sum;c->r.carry=(uint16_t)(sum>>16); }
static int step(mask_context *c,int iteration)
{ if(c->out->work==c->limit){c->out->status=3;return 0;}++c->out->work;if(iteration)++c->out->iterations;return 1; }
static uint8_t operation(mask_context *c,uint8_t a,uint8_t b,uint16_t kind)
{ c->r.carry=0;return kind==0?(uint8_t)(a&b):kind==1?(uint8_t)(a|b):(uint8_t)(a^b); }
static void bits(mask_context *c,uint8_t value,uint16_t kind)
{ uint32_t a=address(c->r.registers.es,c->r.registers.di);c->m[a]=operation(c,c->m[a],value,kind);++c->out->writes; }
static int device(mask_context *c,uint16_t kind,uint16_t site,uint16_t *value)
{
    td2ega_line_draw_request q={0};td2ega_line_draw_response r={0};
    if(!step(c,0))return 0;
    q.kind=kind;q.site=site;q.segment=c->cs;q.stack_segment=c->ss;q.stack_sp=c->sp;q.port=c->r.registers.dx;q.address=address(c->r.registers.es,c->r.registers.di);q.value=*value;q.incoming=c->r;r.returned=c->r;r.value=*value;++c->out->calls;
    if(!c->service(c->context,c->m,&q,&r)){c->out->status=4;return 0;}
    if(kind==2){if(r.value>255){c->out->status=2;return 0;}*value=r.value;}else ++c->out->writes;
    return 1;
}
static int read_device(mask_context *c,uint16_t site,uint16_t *value)
{ *value=c->m[address(c->r.registers.es,c->r.registers.di)];return device(c,2,site,value); }
static int write_device(mask_context *c,uint16_t site,uint16_t value)
{ return device(c,3,site,&value); }
static int repeat(mask_context *c)
{
    while(c->r.registers.cx!=0){if(!step(c,1))return 0;c->m[address(c->r.registers.es,c->r.registers.di)]=(uint8_t)c->r.registers.ax;c->r.registers.di=(uint16_t)(c->r.registers.di+(c->r.registers.direction?-1:1));--c->r.registers.cx;++c->out->writes;}return 1;
}
void td2ega_mask_span(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,
    uint16_t sp,uint16_t entry,const td2ega_state_registers *in,
    td2ega_line_draw_service adapter,void *context,uint32_t limit,
    td2ega_line_draw_result *out)
{
    mask_context c;uint16_t kind,v,old;int32_t relation;
    static const uint16_t aligned_read[3]={0xad2d,0xad96,0xadff};
    static const uint16_t aligned_write[3]={0xad30,0xad99,0xae04};
    static const uint16_t first_read[3]={0xad4f,0xadb8,0xae23};
    static const uint16_t first_write[3]={0xad54,0xadbd,0xae28};
    static const uint16_t middle_read[3]={0xad5a,0xadc3,0xae2e};
    static const uint16_t middle_write[3]={0xad5d,0xadc6,0xae33};
    static const uint16_t last_read[3]={0xad63,0xadcc,0xae39};
    static const uint16_t last_write[3]={0xad68,0xadd1,0xae3e};
    static const uint16_t two_first_read[3]={0xad75,0xadde,0xae4b};
    static const uint16_t two_first_write[3]={0xad7a,0xade3,0xae50};
    static const uint16_t two_last_read[3]={0xad7e,0xade7,0xae54};
    static const uint16_t two_last_write[3]={0xad83,0xadec,0xae59};
    if(out==NULL)return;
    *out=(td2ega_line_draw_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || entry>5 || (entry>=3 && adapter==NULL) || sp<256 || sp>UINT16_C(0xfff0) || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1)return;
    c=(mask_context){m,(uint16_t)(load+0x6c9),ss,sp,limit,*in,adapter,context,out};kind=(uint16_t)(entry%3);
#define R c.r.registers
#define STEP() do{if(!step(&c,1))goto finish;}while(0)
#define READ(site) do{if(!read_device(&c,site,&v))goto finish;}while(0)
#define WRITE(site,val) do{if(!write_device(&c,site,(uint16_t)(val)))goto finish;}while(0)
    c.r.carry=0;
    if(R.bx==0){
        R.bx=R.cx;if(kind==0){R.ax=0;c.r.carry=0;}else al(&c,255);
aligned_row:
        STEP();R.cx=R.dx;
        if(entry<3 && kind<2){if(!repeat(&c))goto finish;}
        else{
aligned_byte:
            STEP();
            if(entry<3){bits(&c,(uint8_t)R.ax,2);R.di=(uint16_t)(R.di+1);}
            else{READ(aligned_read[kind]);ah(&c,v);if(kind==2)ah(&c,operation(&c,(uint8_t)(R.ax>>8),(uint8_t)R.ax,2));WRITE(aligned_write[kind],(uint8_t)R.ax);R.di=(uint16_t)(R.di+(R.direction?-1:1));}
            R.cx=(uint16_t)(R.cx-1);if(R.cx!=0)goto aligned_byte;
        }
        add_di(&c,R.bx);old=R.si;R.si=(uint16_t)(R.si-1);if(sw(old)-1>0)goto aligned_row;goto normal;
    }
    ah(&c,m[address(c.cs,(uint16_t)(R.bx-(entry<3?0x7d38:0x52e6)))]);dh(&c,R.ax>>8);dh(&c,(R.dx>>8)^255);
    if(entry>=3)goto device_edges;
    c.r.carry=0;if((R.ax&2)==0){if(kind==0)ah(&c,0);else if(kind==1)dh(&c,255);else ah(&c,255);}c.r.carry=0;
    if((R.ax&1)==0){if(kind==0)dh(&c,0);else if(kind==1)ah(&c,255);else dh(&c,255);dl(&c,(uint8_t)R.dx-1);R.cx=(uint16_t)(R.cx+1);}
    relation=sb((uint8_t)R.dx)-1;dl(&c,(uint8_t)R.dx-1);R.bx=R.cx;
    if((uint8_t)R.dx==0)goto ram_two;
    if(relation<0)goto ram_one;
    R.cx&=255;c.r.carry=0;if(kind==0){al(&c,0);c.r.carry=0;}else al(&c,255);
ram_wide_row:
    STEP();bits(&c,(uint8_t)(kind==0?(R.ax>>8):(R.dx>>8)),kind);R.di=(uint16_t)(R.di+1);cl(&c,(uint8_t)R.dx);
    if(kind<2){if(!repeat(&c))goto finish;}
    else{
ram_xor_byte:
        STEP();bits(&c,(uint8_t)R.ax,2);R.di=(uint16_t)(R.di+1);R.cx=(uint16_t)(R.cx-1);if(R.cx!=0)goto ram_xor_byte;
    }
    bits(&c,(uint8_t)(kind==0?(R.dx>>8):(R.ax>>8)),kind);add_di(&c,R.bx);old=R.si;R.si=(uint16_t)(R.si-1);if(sw(old)-1>0)goto ram_wide_row;goto normal;
ram_two:
    R.cx=R.si;
ram_two_row:
    STEP();bits(&c,(uint8_t)(kind==0?(R.ax>>8):(R.dx>>8)),kind);R.di=(uint16_t)(R.di+1);bits(&c,(uint8_t)(kind==0?(R.dx>>8):(R.ax>>8)),kind);add_di(&c,R.bx);R.cx=(uint16_t)(R.cx-1);if(R.cx!=0)goto ram_two_row;goto normal;
ram_one:
    R.cx=R.si;ah(&c,operation(&c,(uint8_t)(R.ax>>8),(uint8_t)(R.dx>>8),kind==0?1:0));
ram_one_row:
    STEP();bits(&c,(uint8_t)(R.ax>>8),kind);add_di(&c,R.bx);R.cx=(uint16_t)(R.cx-1);if(R.cx!=0)goto ram_one_row;goto normal;
device_edges:
    c.r.carry=(uint16_t)((uint8_t)R.dx<1);if((uint8_t)R.dx==1){R.bx=R.cx;R.cx=R.si;goto device_two_row;}
    dl(&c,(uint8_t)R.dx-1);R.bx=R.cx;R.cx&=255;c.r.carry=0;if(kind==0){al(&c,0);c.r.carry=0;}else al(&c,255);
device_wide_row:
    STEP();READ(first_read[kind]);cl(&c,v);cl(&c,operation(&c,(uint8_t)R.cx,(uint8_t)(kind==0?(R.ax>>8):(R.dx>>8)),kind));WRITE(first_write[kind],(uint8_t)R.cx);R.di=(uint16_t)(R.di+1);cl(&c,(uint8_t)R.dx);
device_middle_byte:
    STEP();READ(middle_read[kind]);ah(&c,v);if(kind==2)ah(&c,operation(&c,(uint8_t)(R.ax>>8),(uint8_t)R.ax,2));WRITE(middle_write[kind],R.ax>>8);R.di=(uint16_t)(R.di+1);R.cx=(uint16_t)(R.cx-1);if(R.cx!=0)goto device_middle_byte;
    READ(last_read[kind]);cl(&c,v);cl(&c,operation(&c,(uint8_t)R.cx,(uint8_t)(kind==0?(R.dx>>8):(R.ax>>8)),kind));WRITE(last_write[kind],(uint8_t)R.cx);add_di(&c,R.bx);old=R.si;R.si=(uint16_t)(R.si-1);if(sw(old)-1>0)goto device_wide_row;goto normal;
device_two_row:
    STEP();READ(two_first_read[kind]);dl(&c,v);dl(&c,operation(&c,(uint8_t)R.dx,(uint8_t)(kind==0?(R.ax>>8):(R.dx>>8)),kind));WRITE(two_first_write[kind],(uint8_t)R.dx);R.di=(uint16_t)(R.di+1);READ(two_last_read[kind]);dl(&c,v);dl(&c,operation(&c,(uint8_t)R.dx,(uint8_t)(kind==0?(R.dx>>8):(R.ax>>8)),kind));WRITE(two_last_write[kind],(uint8_t)R.dx);add_di(&c,R.bx);R.cx=(uint16_t)(R.cx-1);if(R.cx!=0)goto device_two_row;
normal:
    c.sp=(uint16_t)(sp+2);out->status=0;
finish:
    out->current_sp=c.sp;out->returned=c.r;
#undef R
#undef STEP
#undef READ
#undef WRITE
}
