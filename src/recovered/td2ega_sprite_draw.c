#include "td2ega_sprite_draw.h"
#include <stddef.h>
typedef struct sprite_context {
    uint8_t *m;uint16_t load,cs,ss,sp;uint32_t limit;
    td2ega_state_registers r;td2ega_line_draw_service service;void *context;
    td2ega_sprite_draw_result *out;
} sprite_context;
static uint32_t address(uint16_t s,uint16_t o)
{ return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff); }
static uint8_t byte(const uint8_t *m,uint16_t s,uint16_t o)
{ return m[address(s,o)]; }
static uint16_t word(const uint8_t *m,uint16_t s,uint16_t o)
{ uint32_t a=address(s,o);return (uint16_t)(m[a]|((uint16_t)m[(a+1)&UINT32_C(0xfffff)]<<8)); }
static void put_word(uint8_t *m,uint16_t s,uint16_t o,uint16_t v)
{ uint32_t a=address(s,o);m[a]=(uint8_t)v;m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8); }
static uint16_t local(sprite_context *c,uint16_t offset)
{ return word(c->m,c->ss,(uint16_t)(c->r.bp-offset)); }
static void put_local(sprite_context *c,uint16_t offset,uint16_t v)
{ put_word(c->m,c->ss,(uint16_t)(c->r.bp-offset),v); }
static uint8_t local_byte(sprite_context *c,uint16_t offset)
{ return byte(c->m,c->ss,(uint16_t)(c->r.bp-offset)); }
static void put_local_byte(sprite_context *c,uint16_t offset,uint16_t v)
{ c->m[address(c->ss,(uint16_t)(c->r.bp-offset))]=(uint8_t)v; }
static uint16_t argument(sprite_context *c,uint16_t offset)
{ return word(c->m,c->ss,(uint16_t)(c->r.bp+offset)); }
static int32_t sw(uint16_t v)
{ return v<UINT16_C(0x8000)?v:(int32_t)v-INT32_C(65536); }
static int32_t sb(uint8_t v)
{ return v<128?v:(int32_t)v-256; }
static int32_t compare(sprite_context *c,uint16_t a,uint16_t b)
{ c->r.carry=(uint16_t)(a<b);return sw(a)-sw(b); }
static void add(sprite_context *c,uint16_t *a,uint16_t b)
{ uint32_t sum=(uint32_t)*a+b;*a=(uint16_t)sum;c->r.carry=(uint16_t)(sum>>16); }
static int32_t sub(sprite_context *c,uint16_t *a,uint16_t b)
{ int32_t relation=sw(*a)-sw(b);c->r.carry=(uint16_t)(*a<b);*a=(uint16_t)(*a-b);return relation; }
static void negate(sprite_context *c,uint16_t *a)
{ c->r.carry=(uint16_t)(*a!=0);*a=(uint16_t)(0-*a); }
static void shl(sprite_context *c,uint16_t *a)
{ c->r.carry=(uint16_t)(*a>>15);*a=(uint16_t)(*a<<1); }
static void sar(sprite_context *c,uint16_t *a)
{ c->r.carry=(uint16_t)(*a&1);*a=(uint16_t)((*a>>1)|(*a&UINT16_C(0x8000))); }
static void al(sprite_context *c,uint16_t v)
{ c->r.registers.ax=(uint16_t)((c->r.registers.ax&UINT16_C(0xff00))|(v&255)); }
static void ah(sprite_context *c,uint16_t v)
{ c->r.registers.ax=(uint16_t)((c->r.registers.ax&255)|((v&255)<<8)); }
static void bl(sprite_context *c,uint16_t v)
{ c->r.registers.bx=(uint16_t)((c->r.registers.bx&UINT16_C(0xff00))|(v&255)); }
static void cl(sprite_context *c,uint16_t v)
{ c->r.registers.cx=(uint16_t)((c->r.registers.cx&UINT16_C(0xff00))|(v&255)); }
static void dl(sprite_context *c,uint16_t v)
{ c->r.registers.dx=(uint16_t)((c->r.registers.dx&UINT16_C(0xff00))|(v&255)); }
static void dh(sprite_context *c,uint16_t v)
{ c->r.registers.dx=(uint16_t)((c->r.registers.dx&255)|((v&255)<<8)); }
static void mul_byte(sprite_context *c,uint8_t v)
{ c->r.registers.ax=(uint16_t)((uint8_t)c->r.registers.ax*v);c->r.carry=(uint16_t)(c->r.registers.ax>255); }
static void push(sprite_context *c,uint16_t v)
{ c->sp=(uint16_t)(c->sp-2);put_word(c->m,c->ss,c->sp,v); }
static uint16_t pop(sprite_context *c)
{ uint16_t v=word(c->m,c->ss,c->sp);c->sp=(uint16_t)(c->sp+2);return v; }
static int step(sprite_context *c,int iteration)
{ if(c->out->work==c->limit){c->out->status=3;return 0;}++c->out->work;if(iteration)++c->out->iterations;return 1; }
static int device(sprite_context *c,uint16_t kind,uint16_t site,uint16_t *value)
{
    td2ega_line_draw_request q={0};td2ega_line_draw_response r={0};
    if(!step(c,0))return 0;
    q.kind=kind;q.site=site;q.segment=c->cs;q.stack_segment=c->ss;q.stack_sp=c->sp;q.port=c->r.registers.dx;q.value=*value;q.incoming=c->r;
    if(kind!=1)q.address=address(c->r.registers.es,c->r.registers.di);
    r.returned=c->r;r.value=*value;++c->out->calls;
    if(!c->service(c->context,c->m,&q,&r)){c->out->status=4;return 0;}
    if(kind==2){if(r.value>255){c->out->status=2;return 0;}*value=r.value;}
    else if(kind==3)++c->out->writes;
    return 1;
}
static int output(sprite_context *c,uint16_t site)
{ uint16_t value=(uint8_t)c->r.registers.ax;return device(c,1,site,&value); }
static int mask_call(sprite_context *c,uint16_t site,uint16_t target)
{
    td2ega_line_draw_result result;uint16_t entry;
    if(!step(c,0))return 0;
    push(c,(uint16_t)(site+3));++c->out->mask_calls;
    switch(target){case 0x82d0:entry=0;break;case 0x8336:entry=1;break;case 0x839c:entry=2;break;case 0xad22:entry=3;break;case 0xad8b:entry=4;break;case 0xadf4:entry=5;break;default:c->out->status=1;c->out->next_segment=c->cs;c->out->next_ip=target;return 0;}
    td2ega_mask_span(c->m,UINT32_C(0x100000),c->load,c->ss,c->sp,entry,&c->r,c->service,c->context,c->limit-c->out->work,&result);
    c->r=result.returned;c->sp=result.current_sp;c->out->work+=result.work;c->out->iterations+=result.iterations;c->out->calls+=result.calls;c->out->writes+=result.writes;
    if(result.status!=0){c->out->status=result.status;return 0;}return 1;
}
static void cleanup(sprite_context *c,int hardware)
{
    uint32_t sum=(uint32_t)c->sp+0x44;c->sp=(uint16_t)sum;c->r.carry=(uint16_t)(sum>>16);
    c->r.registers.di=pop(c);c->r.registers.si=pop(c);c->r.registers.ds=pop(c);c->r.bp=pop(c);c->out->next_ip=pop(c);c->out->next_segment=pop(c);c->out->status=0;(void)hardware;
}
static void ram_store(sprite_context *c,uint8_t value)
{ c->m[address(c->r.registers.es,c->r.registers.di)]=value;++c->out->writes; }
static void lodsb(sprite_context *c)
{ al(c,byte(c->m,c->r.registers.ds,c->r.registers.si));c->r.registers.si=(uint16_t)(c->r.registers.si+(c->r.registers.direction?-1:1)); }
static void stosb(sprite_context *c)
{ ram_store(c,(uint8_t)c->r.registers.ax);c->r.registers.di=(uint16_t)(c->r.registers.di+(c->r.registers.direction?-1:1)); }
static void rotate_ax(sprite_context *c,unsigned shift)
{ unsigned i;for(i=0;i<shift;++i){c->r.carry=(uint16_t)(c->r.registers.ax&1);c->r.registers.ax=(uint16_t)((c->r.registers.ax>>1)|(c->r.registers.ax<<15));} }
static void preceding(sprite_context *c,unsigned shift)
{
    uint8_t v=byte(c->m,c->r.registers.ds,(uint16_t)(c->r.registers.si-1));unsigned i;
    for(i=0;i<shift;++i)v=(uint8_t)((v>>1)|(v<<7));
    dh(c,v&(uint8_t)(255u<<(8-shift)));c->r.carry=0;
}
static int read_pixel(sprite_context *c,uint16_t site,uint16_t *value)
{ *value=byte(c->m,c->r.registers.es,c->r.registers.di);return device(c,2,site,value); }
static int write_pixel(sprite_context *c,uint16_t site,uint16_t value)
{ return device(c,3,site,&value); }
static int kernel(sprite_context *c,uint16_t target)
{
    unsigned shift=0;int hardware=0,latched=0;uint16_t v,old;uint8_t high_mask,low_mask,old_index;int32_t relation;
    static const uint16_t hardware_initial_read[8]={0,0x98de,0x9958,0x99d6,0x9a58,0x9adb,0x9b5c,0x9bd9};
    static const uint16_t hardware_data_write[8]={0x9854,0x9901,0x997f,0x9a01,0x9a84,0x9b05,0x9b82,0x9bfb};
    static const uint16_t hardware_extra_read[8]={0,0x9902,0x9980,0x9a02,0x9a85,0x9b06,0x9b83,0x9bfc};
    static const uint16_t hardware_tail_read[8]={0,0x990c,0x998a,0x9a0c,0x9a8f,0x9b10,0x9b8d,0x9c06};
    static const uint16_t hardware_tail_write[8]={0,0x9913,0x9991,0x9a13,0x9a96,0x9b17,0x9b94,0x9c0d};
    static const uint16_t write_mask_index[8]={0x984c,0x98cc,0x9946,0x99c4,0x9a46,0x9ac9,0x9b4a,0x9bc7};
    static const uint16_t write_mask_value[8]={0x9850,0x98d0,0x994a,0x99c8,0x9a4a,0x9acd,0x9b4e,0x9bcb};
    static const uint16_t read_plane_index[8]={0,0x98d6,0x9950,0x99ce,0x9a50,0x9ad3,0x9b54,0x9bd1};
    static const uint16_t read_plane_value[8]={0,0x98da,0x9954,0x99d2,0x9a54,0x9ad7,0x9b58,0x9bd5};
    switch(target){
    case 0x9582:shift=0;break;case 0x95b2:shift=1;break;case 0x9607:shift=2;break;case 0x9661:shift=3;break;case 0x96bf:shift=4;break;case 0x9721:shift=5;break;case 0x9781:shift=6;break;case 0x97dd:shift=7;break;
    case 0x9835:hardware=1;shift=0;break;case 0x98bb:hardware=1;shift=1;break;case 0x9935:hardware=1;shift=2;break;case 0x99b3:hardware=1;shift=3;break;case 0x9a35:hardware=1;shift=4;break;case 0x9ab8:hardware=1;shift=5;break;case 0x9b39:hardware=1;shift=6;break;case 0x9bb6:hardware=1;shift=7;break;
    case 0x9872:hardware=1;goto hardware_cleanup;
    default:c->out->status=1;c->out->next_segment=c->cs;c->out->next_ip=target;return 0;
    }
#define R c->r.registers
#define L(n) local(c,n)
#define LB(n) local_byte(c,n)
#define PL(n,value) put_local(c,n,value)
#define PLB(n,value) put_local_byte(c,n,value)
#define CW(n) word(c->m,c->cs,(uint16_t)(n))
#define STEP() do{if(!step(c,1))return 0;}while(0)
#define OUT(site) do{if(!output(c,site))return 0;}while(0)
#define READ(site) do{if(!read_pixel(c,site,&v))return 0;}while(0)
#define WRITE(site,value) do{v=(uint16_t)(value);if(!write_pixel(c,site,v))return 0;}while(0)
    if(hardware)goto hardware_start;
    if(shift==0)R.dx=L(0x2c);
ram_plane:
    STEP();R.si=L(0x3a);R.es=word(c->m,c->ss,(uint16_t)(c->r.bp+R.si-0x16));R.di=L(0x2a);R.si=word(c->m,c->ss,(uint16_t)(c->r.bp+R.si-0x1e));R.bx=L(14);
ram_row:
    STEP();R.cx=L(12);
    if(shift==0){
ram_copy_byte:
        if(R.cx!=0){STEP();ram_store(c,byte(c->m,R.ds,R.si));R.si=(uint16_t)(R.si+(R.direction?-1:1));R.di=(uint16_t)(R.di+(R.direction?-1:1));--R.cx;goto ram_copy_byte;}
        add(c,&R.di,R.dx);goto ram_row_end;
    }
    high_mask=(uint8_t)(255u<<(8-shift));low_mask=(uint8_t)~high_mask;
    if(shift!=7)dh(c,byte(c->m,R.es,R.di));
    c->r.carry=0;
    if((R.dx&2)==0){preceding(c,shift);c->r.carry=0;if(R.cx==0)goto ram_tail;}
    else if(shift==7)dh(c,byte(c->m,R.es,R.di));
    dh(c,(R.dx>>8)&high_mask);c->r.carry=0;
ram_shift_byte:
    STEP();ah(c,0);c->r.carry=0;lodsb(c);rotate_ax(c,shift);al(c,(uint8_t)R.ax|(uint8_t)(R.dx>>8));c->r.carry=0;dh(c,R.ax>>8);stosb(c);R.cx=(uint16_t)(R.cx-1);if(R.cx!=0)goto ram_shift_byte;c->r.carry=0;
    if((R.dx&1)==0)goto ram_advance;
ram_tail:
    al(c,byte(c->m,R.es,R.di));al(c,(uint8_t)R.ax&low_mask);c->r.carry=0;al(c,(uint8_t)R.ax|(uint8_t)(R.dx>>8));c->r.carry=0;ram_store(c,(uint8_t)R.ax);
ram_advance:
    add(c,&R.di,L(0x2c));
ram_row_end:
    add(c,&R.si,L(0x36));old=R.bx;R.bx=(uint16_t)(R.bx-1);if(sw(old)-1>0)goto ram_row;
    if(shift==0)add(c,&R.si,L(0x38));
    old_index=LB(0x3a);relation=sb(old_index)-2;PLB(0x3a,(uint8_t)(old_index-2));c->r.carry=(uint16_t)(old_index<2);if(relation>=0)goto ram_plane;cleanup(c,0);return 1;
hardware_start:
    R.si=L(0x28);R.di=L(0x2a);
    if(shift!=0)goto hardware_row;
    c->r.carry=0;latched=LB(0x42)!=0;
hardware_row:
    STEP();R.bx=(uint16_t)(c->r.bp-0x26);
hardware_plane:
    STEP();R.cx=word(c->m,c->ss,R.bx);R.dx=0x3c4;al(c,2);OUT(shift==0 && latched?0x988f:write_mask_index[shift]);R.dx=(uint16_t)(R.dx+1);al(c,(uint8_t)R.cx);OUT(shift==0 && latched?0x9893:write_mask_value[shift]);
    if(shift!=0){R.dx=0x3ce;al(c,4);OUT(read_plane_index[shift]);R.dx=(uint16_t)(R.dx+1);al(c,R.cx>>8);OUT(read_plane_value[shift]);}
    R.cx=L(12);
    if(shift==0){
        if(latched)goto hardware_latched_byte;
hardware_copy_byte:
        if(R.cx!=0){STEP();v=byte(c->m,R.ds,R.si);if(!device(c,3,0x9854,&v))return 0;R.si=(uint16_t)(R.si+(R.direction?-1:1));R.di=(uint16_t)(R.di+(R.direction?-1:1));--R.cx;goto hardware_copy_byte;}goto hardware_advance;
hardware_latched_byte:
        STEP();READ(0x9897);ah(c,v);v=byte(c->m,R.ds,R.si);if(!device(c,3,0x989a,&v))return 0;R.si=(uint16_t)(R.si+(R.direction?-1:1));R.di=(uint16_t)(R.di+(R.direction?-1:1));R.cx=(uint16_t)(R.cx-1);if(R.cx!=0)goto hardware_latched_byte;goto hardware_advance;
    }
    high_mask=(uint8_t)(255u<<(8-shift));low_mask=(uint8_t)~high_mask;READ(hardware_initial_read[shift]);dh(c,v);dl(c,LB(0x3e));c->r.carry=0;
    if((R.dx&2)==0){preceding(c,shift);c->r.carry=0;if(R.cx==0)goto hardware_tail;}
    dh(c,(R.dx>>8)&high_mask);c->r.carry=0;
hardware_shift_byte:
    STEP();ah(c,0);c->r.carry=0;lodsb(c);rotate_ax(c,shift);al(c,(uint8_t)R.ax|(uint8_t)(R.dx>>8));c->r.carry=0;dh(c,R.ax>>8);WRITE(hardware_data_write[shift],(uint8_t)R.ax);R.di=(uint16_t)(R.di+(R.direction?-1:1));READ(hardware_extra_read[shift]);ah(c,v);R.cx=(uint16_t)(R.cx-1);if(R.cx!=0)goto hardware_shift_byte;c->r.carry=0;if((R.dx&1)==0)goto hardware_advance;
hardware_tail:
    READ(hardware_tail_read[shift]);al(c,v);al(c,(uint8_t)R.ax&low_mask);c->r.carry=0;al(c,(uint8_t)R.ax|(uint8_t)(R.dx>>8));c->r.carry=0;WRITE(hardware_tail_write[shift],(uint8_t)R.ax);
hardware_advance:
    sub(c,&R.di,L(12));add(c,&R.si,word(c->m,c->ss,(uint16_t)(R.bx+8)));add(c,&R.bx,2);compare(c,R.bx,L(0x3c));if(R.bx<L(0x3c))goto hardware_plane;add(c,&R.di,CW(0xaf4e));sub(c,&R.si,L(0x32));v=L(14);relation=sw(v)-1;PL(14,(uint16_t)(v-1));if(relation>0)goto hardware_row;
hardware_cleanup:
    R.dx=0x3ce;al(c,3);OUT(0x9877);R.dx=(uint16_t)(R.dx+1);al(c,0);OUT(0x987b);cleanup(c,1);return 1;
#undef R
#undef L
#undef LB
#undef PL
#undef PLB
#undef CW
#undef STEP
#undef OUT
#undef READ
#undef WRITE
}
static void add_local(sprite_context *c,uint16_t offset,uint16_t value)
{ uint16_t v=local(c,offset);add(c,&v,value);put_local(c,offset,v); }
static int32_t sub_local(sprite_context *c,uint16_t offset,uint16_t value)
{ uint16_t v=local(c,offset);int32_t relation=sub(c,&v,value);put_local(c,offset,v);return relation; }
static int high_masks(sprite_context *c,int hardware,int which)
{
    uint16_t v,target;uint8_t bits;
#define R c->r.registers
#define L(n) local(c,n)
#define LB(n) local_byte(c,n)
#define PL(n,value) put_local(c,n,value)
#define PLB(n,value) put_local_byte(c,n,value)
#define A(n) argument(c,n)
#define CW(n) word(c->m,c->cs,(uint16_t)(n))
#define B(n) byte(c->m,R.ds,(uint16_t)(n))
#define OUT(site) do{if(!output(c,site))return 0;}while(0)
    c->r.carry=0;if((B(R.si+12+which)&0xf0)==0)return 1;c->r.carry=0;if((LB(0x41)&(which?6:1))==0)return 1;
    if(which){R.ax=hardware?0xad8b:0x8336;c->r.carry=0;if(LB(0x41)&4)R.ax=hardware?0xadf4:0x839c;PL(0x48,R.ax);}
    PLB(0x44,0x10);PL(0x46,0);
scan:
    if(!step(c,1))return 0;
    al(c,LB(0x44));c->r.carry=0;
    if((B(R.si+12+which)&(uint8_t)R.ax)==0)goto next;
    R.bx=L(0x46);
    if(hardware){
        R.dx=0x3ce;al(c,4);OUT(which?0x9512:0x94ac);R.dx=(uint16_t)(R.dx+1);al(c,(uint8_t)R.bx);OUT(which?0x9516:0x94b0);R.dx=0x3c4;al(c,2);OUT(which?0x951c:0x94b6);R.dx=(uint16_t)(R.dx+1);al(c,byte(c->m,c->cs,(uint16_t)(R.bx-0x6e98)));OUT(which?0x9523:0x94bd);
    }else{
        R.ax=CW((uint16_t)(R.bx-0x50c4));c->r.carry=0;if(R.ax==0)goto next;R.es=R.ax;
    }
    R.di=L(0x2a);R.dx=L(12);R.si=L(14);R.cx=L(0x2c);R.bx=L(0x34);al(c,LB(0x3e));target=which?L(0x48):(hardware?0xad22:0x82d0);
    if(!mask_call(c,hardware?(which?0x9536:0x94d0):(which?0x93ef:0x9394),target))return 0;
    R.si=A(6);
next:
    if(hardware && !which){v=L(0x46);PL(0x46,(uint16_t)(v+1));}else add_local(c,0x46,(uint16_t)(hardware?1:2));
    bits=LB(0x44);PLB(0x44,(uint8_t)(bits<<1));c->r.carry=(uint16_t)(bits>>7);if(!c->r.carry)goto scan;return 1;
#undef R
#undef L
#undef LB
#undef PL
#undef PLB
#undef A
#undef CW
#undef B
#undef OUT
}
static int setup(sprite_context *c,uint16_t entry)
{
    uint16_t v;int32_t relation;unsigned i;
#define R c->r.registers
#define L(n) local(c,n)
#define LB(n) local_byte(c,n)
#define PL(n,value) put_local(c,n,value)
#define PLB(n,value) put_local_byte(c,n,value)
#define A(n) argument(c,n)
#define CW(n) word(c->m,c->cs,(uint16_t)(n))
#define W(n) word(c->m,R.ds,(uint16_t)(n))
#define B(n) byte(c->m,R.ds,(uint16_t)(n))
#define STEP() do{if(!step(c,1))return 0;}while(0)
#define OUT(site) do{if(!output(c,site))return 0;}while(0)
    push(c,c->r.bp);c->r.bp=c->sp;push(c,R.ds);push(c,R.si);push(c,R.di);c->r.carry=(uint16_t)(c->sp<0x44);c->sp=(uint16_t)(c->sp-0x44);R.ax=0x9562;PL(0x40,R.ax);R.ax=0x9572;PL(0x4a,R.ax);PLB(0x42,0);PLB(0x41,3);R.ds=A(8);R.si=A(6);
    R.ax=entry==2?W(R.si+8):A(10);if(entry==0)sub(c,&R.ax,W(R.si+4));PL(8,R.ax);R.ax=entry==2?W(R.si+10):A(12);if(entry==0)sub(c,&R.ax,W(R.si+6));PL(10,R.ax);
    R.direction=0;R.bx=L(10);R.cx=W(R.si+2);R.dx=(uint16_t)(R.si+16);R.ax=R.bx;
    if(compare(c,R.ax,CW(0xaf4a))<0)goto clip_top;
    add(c,&R.ax,R.cx);relation=sub(c,&R.ax,CW(0xaf4c));if(relation<=0)goto vertical_done;relation=sub(c,&R.cx,R.ax);if(relation>0)goto vertical_done;goto done;
clip_top:
    R.bx=CW(0xaf4a);add(c,&R.ax,R.cx);relation=sub(c,&R.ax,R.bx);if(relation<=0)goto done;v=R.cx;R.cx=R.ax;R.ax=v;sub(c,&R.ax,R.cx);mul_byte(c,B(R.si));add(c,&R.dx,R.ax);R.ax=R.bx;add(c,&R.ax,R.cx);relation=sub(c,&R.ax,CW(0xaf4c));if(relation<=0)goto vertical_done;relation=sub(c,&R.cx,R.ax);if(relation<=0)goto done;
vertical_done:
    PL(0x28,R.dx);PL(14,R.cx);PL(10,R.bx);PLB(0x3e,3);R.cx=W(R.si);PL(0x2e,R.cx);R.dx=0;c->r.carry=0;R.bx=L(8);R.ax=R.bx;R.ax&=7;c->r.carry=0;PL(0x34,R.ax);for(i=0;i<3;++i)sar(c,&R.bx);R.ax=R.bx;
    if(compare(c,R.ax,CW(0xaf46))<0)goto clip_left;
    add(c,&R.ax,R.cx);relation=sub(c,&R.ax,CW(0xaf48));if(relation<0)goto horizontal_done;PLB(0x3e,2);relation=sub(c,&R.cx,R.ax);if(relation<=0)goto done;R.dx=R.ax;goto horizontal_done;
clip_left:
    R.bx=CW(0xaf46);add(c,&R.ax,R.cx);relation=sub(c,&R.ax,R.bx);if(relation<0)goto done;R.si=R.cx;sub(c,&R.si,R.ax);add_local(c,0x28,R.si);PLB(0x3e,1);R.si=CW(0xaf48);sub(c,&R.si,R.bx);if(compare(c,R.ax,R.si)>=0){R.ax=R.si;PLB(0x3e,0);}v=R.dx;R.dx=R.cx;R.cx=v;sub(c,&R.dx,R.ax);add(c,&R.cx,R.ax);
horizontal_done:
    PL(12,R.cx);PL(0x36,R.dx);PL(8,R.bx);R.si=A(6);R.bx=L(10);shl(c,&R.bx);add(c,&R.bx,CW(0xaf44));R.ax=L(8);add(c,&R.ax,CW(R.bx));PL(0x2a,R.ax);R.ax=W(R.si+2);mul_byte(c,B(R.si));c->r.carry=0;
    if(B(R.si+15)&0xf0){dl(c,B(R.si+15));for(i=0;i<4;++i){c->r.carry=(uint16_t)(R.dx&1);dl(c,(uint8_t)R.dx>>1);}dh(c,0);c->r.carry=0;add(c,&R.ax,R.dx);}
    PL(0x38,R.ax);R.ax=CW(0xaf4e);sub(c,&R.ax,L(12));PL(0x2c,R.ax);if(compare(c,CW(0xaf3c),UINT16_C(0xa000))==0)goto hardware;
    R.si=(uint16_t)(R.si+12);R.di=0;c->r.carry=0;R.dx=L(0x28);
ram_map:
    STEP();bl(c,B(R.si));R.bx&=15;c->r.carry=0;if(R.bx==0)goto ram_map_end;
ram_select:
    STEP();c->r.carry=0;if(R.bx==0)goto ram_next_plane;R.cx=R.bx;bl(c,byte(c->m,c->cs,(uint16_t)(R.bx-0x6ebc)));cl(c,(uint8_t)R.cx&byte(c->m,c->cs,(uint16_t)(R.bx-0x6e9c)));c->r.carry=0;shl(c,&R.bx);R.ax=CW((uint16_t)(R.bx-0x50c4));R.bx=R.cx;c->r.carry=0;if(R.ax==0)goto ram_select;put_word(c->m,c->ss,(uint16_t)(c->r.bp+R.di-0x16),R.ax);put_word(c->m,c->ss,(uint16_t)(c->r.bp+R.di-0x1e),R.dx);add(c,&R.di,2);goto ram_select;
ram_next_plane:
    if(compare(c,R.di,8)>=0)goto ram_map_end;R.si=(uint16_t)(R.si+1);add(c,&R.dx,L(0x38));goto ram_map;
ram_map_end:
    sub(c,&R.di,2);PL(0x3a,R.di);R.si=A(6);if(!high_masks(c,0,0) || !high_masks(c,0,1))return 0;if(compare(c,L(0x3a),0)<0)goto done;dl(c,LB(0x3e));R.bx=L(0x34);shl(c,&R.bx);R.ax=L(12);add(c,&R.ax,R.bx);if(R.ax==0)goto done;add(c,&R.bx,L(0x40));if(!step(c,0))return 0;++c->out->dispatches;return kernel(c,CW(R.bx));
hardware:
    R.dx=0x3ce;al(c,3);OUT(0x9421);R.dx=(uint16_t)(R.dx+1);al(c,LB(0x42));OUT(0x9426);R.es=CW(0xaf3c);R.ax=L(0x38);sub(c,&R.ax,L(12));PL(0x30,R.ax);R.si=(uint16_t)(R.si+12);R.di=0;c->r.carry=0;R.cx=4;R.bx=0;c->r.carry=0;PL(0x32,0);
hardware_map:
    STEP();bl(c,B(R.si));R.bx&=15;c->r.carry=0;if(R.bx==0)goto hardware_map_end;R.dx=L(12);negate(c,&R.dx);
hardware_select:
    STEP();ah(c,byte(c->m,c->cs,(uint16_t)(R.bx-0x6ebc)));al(c,byte(c->m,c->cs,(uint16_t)(R.bx-0x6eac)));put_word(c->m,c->ss,(uint16_t)(c->r.bp+R.di-0x26),R.ax);put_word(c->m,c->ss,(uint16_t)(c->r.bp+R.di-0x1e),R.dx);add(c,&R.di,2);R.ax=(uint16_t)~R.ax;R.bx&=R.ax;c->r.carry=0;if(R.bx!=0)goto hardware_select;R.dx=L(0x30);put_word(c->m,c->ss,(uint16_t)(c->r.bp+R.di-0x20),R.dx);R.dx=L(0x38);add_local(c,0x32,R.dx);R.si=(uint16_t)(R.si+1);R.cx=(uint16_t)(R.cx-1);if(R.cx!=0)goto hardware_map;
hardware_map_end:
    R.ax=(uint16_t)(c->r.bp+R.di-0x26);PL(0x3c,R.ax);R.dx=L(0x2e);sub_local(c,0x32,R.dx);R.si=A(6);if(!high_masks(c,1,0) || !high_masks(c,1,1))return 0;R.ax=(uint16_t)(c->r.bp-0x26);if(compare(c,R.ax,L(0x3c))==0)goto done;R.bx=L(0x34);shl(c,&R.bx);R.ax=L(12);add(c,&R.ax,R.bx);if(R.ax==0){if(!step(c,0))return 0;++c->out->dispatches;return kernel(c,0x9872);}add(c,&R.bx,L(0x4a));if(!step(c,0))return 0;++c->out->dispatches;return kernel(c,CW(R.bx));
done:
    cleanup(c,0);return 1;
#undef R
#undef L
#undef LB
#undef PL
#undef PLB
#undef A
#undef CW
#undef W
#undef B
#undef STEP
#undef OUT
}
static int initialize(sprite_context *c,uint8_t *m,uint32_t bytes,
    uint16_t load,uint16_t ss,uint16_t sp,const td2ega_state_registers *in,
    td2ega_line_draw_service adapter,void *context,uint32_t limit,
    td2ega_sprite_draw_result *out)
{
    if(out==NULL)return 0;
    *out=(td2ega_sprite_draw_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || adapter==NULL || sp<256 || sp>UINT16_C(0xfff0) || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1)return 0;
    *c=(sprite_context){m,load,(uint16_t)(load+0x6c9),ss,sp,limit,*in,adapter,context,out};return 1;
}
void td2ega_sprite_draw(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,
    uint16_t sp,uint16_t entry,const td2ega_state_registers *in,
    td2ega_line_draw_service adapter,void *context,uint32_t limit,
    td2ega_sprite_draw_result *out)
{
    sprite_context c;
    if(!initialize(&c,m,bytes,load,ss,sp,in,adapter,context,limit,out))return;
    if(entry>2 || sp<512)return;
    setup(&c,entry);out->current_sp=c.sp;out->returned=c.r;
}
void td2ega_sprite_kernel(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,
    uint16_t sp,uint16_t target,const td2ega_state_registers *in,
    td2ega_line_draw_service adapter,void *context,uint32_t limit,
    td2ega_sprite_draw_result *out)
{
    sprite_context c;
    if(!initialize(&c,m,bytes,load,ss,sp,in,adapter,context,limit,out))return;
    if(sp>UINT16_C(0xffa0))return;
    kernel(&c,target);out->current_sp=c.sp;out->returned=c.r;
}
