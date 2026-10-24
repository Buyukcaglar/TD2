#include "td2ega_mode_controller.h"
#include <stddef.h>
typedef struct work {uint8_t *m;uint32_t bytes;uint16_t load,cs,ss,sp;td2ega_state_registers r;uint32_t limit,leaf_limit,iteration_limit;td2ega_mode_controller_result *o;} work;
static uint32_t address(uint16_t s,uint16_t o){return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(work *w,uint16_t s,uint16_t o){uint32_t a=address(s,o);return (uint16_t)(w->m[a]|((uint16_t)w->m[(a+1)&UINT32_C(0xfffff)]<<8));}
static uint16_t rd(work *w,uint16_t o){return word(w,w->r.registers.ds,o);}
static uint8_t byte(work *w,uint16_t o){return w->m[address(w->r.registers.ds,o)];}
static void put(work *w,uint16_t s,uint16_t o,uint16_t v,unsigned n){uint32_t a=address(s,o);w->m[a]=(uint8_t)v;if(n==2)w->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++w->o->bus_writes;}
static void wr(work *w,uint16_t o,uint16_t v){put(w,w->r.registers.ds,o,v,2);}
static void wb(work *w,uint16_t o,uint16_t v){put(w,w->r.registers.ds,o,v,1);}
static void push(work *w,uint16_t v){w->sp=(uint16_t)(w->sp-2);put(w,w->ss,w->sp,v,2);}
static uint16_t pop(work *w){uint16_t v=word(w,w->ss,w->sp);w->sp=(uint16_t)(w->sp+2);return v;}
static int32_t sw(uint16_t v){return v&0x8000?(int32_t)v-65536:(int32_t)v;}
static uint16_t add(work *w,uint16_t a,uint16_t b){uint32_t v=(uint32_t)a+b;w->r.carry=(uint16_t)(v>65535);return (uint16_t)v;}
static uint16_t sub(work *w,uint16_t a,uint16_t b){w->r.carry=(uint16_t)(a<b);return (uint16_t)(a-b);}
static uint16_t sbb(work *w,uint16_t a,uint16_t b){uint32_t v=(uint32_t)b+w->r.carry;w->r.carry=(uint16_t)((uint32_t)a<v);return (uint16_t)((uint32_t)a-v);}
static int32_t sbbwide(work *w,uint16_t a,uint16_t b,uint16_t *result){uint16_t borrow=w->r.carry;int32_t d=sw(a)-sw(b)-borrow;*result=sbb(w,a,b);return d;}
static void cmp(work *w,uint16_t a,uint16_t b){w->r.carry=(uint16_t)(a<b);}
static int begin(work *w,uint16_t site,uint16_t *expected){if(w->o->calls==w->limit){w->o->status=3;w->o->next_segment=w->cs;w->o->next_ip=site;return 0;}++w->o->calls;*expected=w->sp;push(w,(uint16_t)(site+3));return 1;}
static int leaf(work *w,uint16_t site)
{
    td2ega_record_dispatch_result r;uint16_t expected;
    if(!begin(w,site,&expected))return 0;
    td2ega_record_dispatch(w->m,w->bytes,w->load,w->ss,w->sp,&w->r,w->leaf_limit,w->iteration_limit,&r);w->r=r.returned;w->sp=r.current_sp;w->o->nested_calls+=r.calls;w->o->iterations+=r.child_iterations;w->o->bus_writes+=r.bus_writes;w->o->next_segment=r.next_segment;w->o->next_ip=r.next_ip;if(r.dispatch_offset!=0){w->o->raw_target=r.raw_target;w->o->dispatch_site=0x57a7;w->o->dispatch_offset=r.dispatch_offset;}if(r.status!=0){w->o->status=r.status;return 0;}if(r.return_kind==1){w->o->exit_kind=1;w->o->status=0;return 0;}if(r.next_segment!=w->cs || r.next_ip!=(uint16_t)(site+3) || w->sp!=expected){w->o->status=1;return 0;}return 1;
}
static int product(work *w)
{
    td2ega_control_bus_result r;uint16_t expected;
    if(!begin(w,0x5650,&expected))return 0;
    td2ega_control_bus(w->m,w->bytes,w->load,w->ss,w->sp,3,&w->r,0,&r);w->r=r.returned;w->sp=r.current_sp;w->o->nested_calls+=r.calls;w->o->bus_writes+=r.bus_writes;w->o->next_segment=r.next_segment;w->o->next_ip=r.next_ip;if(r.status!=0){w->o->status=r.status;return 0;}if(r.next_segment!=w->cs || r.next_ip!=0x5653 || w->sp!=expected){w->o->status=1;return 0;}return 1;
}
static void initialize_tail(work *w){td2ega_record_math_result r;td2ega_record_math(w->m,w->bytes,w->load,w->ss,w->sp,2,&w->r,w->iteration_limit,&r);w->r=r.returned;w->sp=r.current_sp;w->o->iterations+=r.iterations;w->o->bus_writes+=r.bus_writes;w->o->next_segment=r.next_segment;w->o->next_ip=r.next_ip;w->o->status=r.status;}
static uint16_t target(work *w,uint16_t base,uint16_t site){uint16_t index=(uint16_t)((uint16_t)(w->r.registers.bx-1)<<1);w->r.carry=(uint16_t)(w->r.registers.bx==0);w->r.registers.bx=index;w->o->dispatch_site=site;w->o->dispatch_offset=(uint16_t)(base+index);w->o->raw_target=rd(w,w->o->dispatch_offset);return w->o->raw_target;}
#define AX w.r.registers.ax
#define BX w.r.registers.bx
#define DX w.r.registers.dx
#define SI w.r.registers.si
#define CF w.r.carry
void td2ega_mode_controller(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,uint16_t sp,const td2ega_state_registers *in,uint32_t limit,uint32_t leaf_limit,uint32_t iteration_limit,td2ega_mode_controller_result *out)
{
    work w;uint16_t v,jump;uint8_t b;int32_t d;unsigned shift;
    if(out==NULL)return;
    *out=(td2ega_mode_controller_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || sp<36 || sp>UINT16_C(0xffe0) || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1)return;
    w=(work){m,bytes,load,(uint16_t)(load+0x6c9),ss,sp,*in,limit,leaf_limit,iteration_limit,out};AX=0;CF=0;wb(&w,0x33bc,0);wb(&w,0x3374,0);wr(&w,0x3348,AX);AX=byte(&w,0x33b6);AX=(uint16_t)(AX|byte(&w,0x33b7));CF=0;wb(&w,0x33b8,(uint8_t)AX);AX=rd(&w,0x52da);CF=0;if(AX==0)goto returned;CF=0;if(byte(&w,0x33b6)!=0)goto first_mode;CF=0;if(byte(&w,0x33b7)!=0)goto second_mode;BX=rd(&w,0x52d8);BX=sub(&w,BX,rd(&w,0x52c8));AX=sbb(&w,AX,rd(&w,0x52ca));CF=0;if(AX&0x8000)goto clear;CF=0;if(rd(&w,0x3346)&4){wb(&w,0x33bc,1);BX=AX;for(shift=0;shift<4;++shift){CF=(uint16_t)(BX&1);BX>>=1;}BX=(uint16_t)(BX+1);cmp(&w,BX,5);if(sw(BX)>=5)BX=5;wr(&w,0x3348,BX);}cmp(&w,AX,16);if(sw(AX)>16)goto returned;AX=rd(&w,0x52ce);v=rd(&w,0x52d6);cmp(&w,AX,v);if(AX<v){b=byte(&w,0x52d7);cmp(&w,b,50);if(b<=50)goto returned;wb(&w,0x33b6,1);goto tail;}b=(uint8_t)(AX>>8);cmp(&w,b,50);if(b<=50)goto returned;wr(&w,0x3354,AX);wb(&w,0x33b7,1);goto tail;
first_mode:
    if(!leaf(&w,0x54f4))goto finish;AX=rd(&w,0x52d8);AX=sub(&w,AX,rd(&w,0x52d0));AX=rd(&w,0x52da);d=sbbwide(&w,AX,rd(&w,0x52d2),&v);AX=v;if(d<0)AX=add(&w,AX,rd(&w,0x380d));BX=byte(&w,0x33b6);CF=0;jump=target(&w,0x3456,0x5514);goto dispatch;
second_mode:
    b=byte(&w,0x33b7);cmp(&w,b,6);if(b<6){if(!leaf(&w,0x5581))goto finish;}AX=rd(&w,0x52d8);AX=sub(&w,AX,rd(&w,0x52c8));AX=rd(&w,0x52da);d=sbbwide(&w,AX,rd(&w,0x52ca),&v);AX=v;if(d<0)AX=add(&w,AX,rd(&w,0x380d));BX=byte(&w,0x33b7);CF=0;jump=target(&w,0x3446,0x55a1);
dispatch:
    switch(jump){
    case 0x5518:cmp(&w,AX,300);if(sw(AX)<=300){b=(uint8_t)(byte(&w,0x33b6)+1);wb(&w,0x33b6,b);wb(&w,0x33ba,1);}goto returned;
    case 0x5527:cmp(&w,AX,10);if(sw(AX)>=10){b=(uint8_t)(byte(&w,0x33b6)+1);wb(&w,0x33b6,b);}goto returned;
    case 0x5531:cmp(&w,AX,10);if(sw(AX)>=10){AX=rd(&w,0x52d0);DX=rd(&w,0x52d2);DX=add(&w,DX,10);SI=add(&w,SI,8);cmp(&w,SI,DX);if(SI==DX){SI=0;CF=0;}wr(&w,0x52d8,AX);wr(&w,0x52da,DX);}CF=0;if(rd(&w,0x52de)==0){b=(uint8_t)(byte(&w,0x33b6)+1);wb(&w,0x33b6,b);wb(&w,0x33bb,20);}goto returned;
    case 0x5561:b=(uint8_t)(byte(&w,0x33bb)-1);wb(&w,0x33bb,b);if(b==0){b=(uint8_t)(byte(&w,0x33b6)+1);wb(&w,0x33b6,b);}goto returned;
    case 0x556c:v=rd(&w,0x52de);v=add(&w,v,0x400);wr(&w,0x52de,v);cmp(&w,AX,60);if(sw(AX)>=60)goto clear;goto returned;
    case 0x55a5:cmp(&w,AX,300);if(sw(AX)<=300){b=(uint8_t)(byte(&w,0x33b7)+1);wb(&w,0x33b7,b);wb(&w,0x33ba,1);}goto returned;
    case 0x55b4:cmp(&w,AX,10);if(sw(AX)>=10){b=(uint8_t)(byte(&w,0x33b7)+1);wb(&w,0x33b7,b);}goto returned;
    case 0x55be:cmp(&w,AX,10);if(sw(AX)>=10){AX=rd(&w,0x52c8);DX=rd(&w,0x52ca);DX=add(&w,DX,10);SI=add(&w,SI,8);cmp(&w,SI,DX);if(SI==DX){SI=0;CF=0;}wr(&w,0x52d8,AX);wr(&w,0x52da,DX);CF=0;if(rd(&w,0x52ce)==0){wr(&w,0x52de,0);goto advance_second;}}CF=0;if(rd(&w,0x52de)!=0)goto returned;
advance_second:
        wr(&w,0x52ce,0);b=(uint8_t)(byte(&w,0x33b7)+1);wb(&w,0x33b7,b);wb(&w,0x33bb,20);goto returned;
    case 0x5603:b=(uint8_t)(byte(&w,0x33bb)-1);wb(&w,0x33bb,b);if(b==0){b=(uint8_t)(byte(&w,0x33b7)+1);wb(&w,0x33b7,b);}goto returned;
    case 0x560e:v=rd(&w,0x52de);v=add(&w,v,0x400);wr(&w,0x52de,v);cmp(&w,AX,60);if(sw(AX)<60)goto returned;v=(uint16_t)(rd(&w,0x5370)+1);wr(&w,0x5370,v);goto clear;
    case 0x5620:b=(uint8_t)(byte(&w,0x33bb)-1);wb(&w,0x33bb,b);if(b==0){b=(uint8_t)(byte(&w,0x33b7)-1);wb(&w,0x33b7,b);AX=rd(&w,0x330e);wr(&w,0x3316,AX);AX=rd(&w,0x330c);wr(&w,0x3314,AX);}goto returned;
    case 0x5637:CF=0;if(rd(&w,0x3346)&4){wb(&w,0x33bc,1);wr(&w,0x3348,1);}wb(&w,0x52cf,30);push(&w,AX);if(!product(&w))goto finish;wb(&w,0x2f5b,1);AX=pop(&w);cmp(&w,AX,2);if(sw(AX)>2)goto returned;wb(&w,0x33bb,30);b=(uint8_t)(byte(&w,0x33b7)-1);wb(&w,0x33b7,b);wr(&w,0x52ce,0);wr(&w,0x332c,800);wb(&w,0x2f5b,1);goto returned;
    case 0x5679:CF=0;if(rd(&w,0x3346)&4){wb(&w,0x33bc,1);wr(&w,0x3348,1);}cmp(&w,AX,300);if(sw(AX)>300)goto align;cmp(&w,AX,2);if(sw(AX)<=2)goto align;v=rd(&w,0x52ce);cmp(&w,v,0x1e00);if(v<0x1e00){b=(uint8_t)(byte(&w,0x33b7)-1);wb(&w,0x33b7,b);}goto returned;
    default:out->status=6;out->next_segment=w.cs;out->next_ip=out->dispatch_site;goto finish;
    }
align:
    AX=rd(&w,0x3332);AX=add(&w,AX,180);v=rd(&w,0x52dc);cmp(&w,AX,v);if(sw(AX)<sw(v))goto restart;AX=sub(&w,AX,360);v=rd(&w,0x52dc);cmp(&w,AX,v);if(sw(AX)>sw(v))goto restart;AX=rd(&w,0x52c8);DX=rd(&w,0x52ca);wr(&w,0x52d8,AX);DX=add(&w,DX,2);v=rd(&w,0x3811);cmp(&w,DX,v);if(DX>=v)DX=sub(&w,DX,rd(&w,0x380d));wr(&w,0x52da,DX);wr(&w,0x8424,1);wb(&w,0x5490,2);goto returned;
restart:
    wb(&w,0x33b7,1);AX=rd(&w,0x52ce);wr(&w,0x3354,AX);
tail:
    initialize_tail(&w);goto finish;
clear:
    AX=0;CF=0;wr(&w,0x52da,AX);wb(&w,0x33b6,0);wb(&w,0x33b7,0);wb(&w,0x33b8,0);wb(&w,0x33ba,0);
returned:
    out->next_ip=pop(&w);out->next_segment=w.cs;out->status=0;
finish:
    out->current_sp=w.sp;out->returned=w.r;
}
