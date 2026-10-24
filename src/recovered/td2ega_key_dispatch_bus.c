#include "td2ega_key_dispatch_bus.h"
#include <stddef.h>
typedef struct work {uint8_t *m;uint16_t cs,ss,sp,zf;td2ega_state_registers r;td2ega_key_dispatch_bus_result *o;} work;
static uint32_t address(uint16_t s,uint16_t o){return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(work *w,uint16_t s,uint16_t o){uint32_t a=address(s,o);return (uint16_t)(w->m[a]|((uint16_t)w->m[(a+1)&UINT32_C(0xfffff)]<<8));}
static uint8_t byte(work *w,uint16_t o){return w->m[address(w->r.registers.ds,o)];}
static void put(work *w,uint16_t s,uint16_t o,uint16_t v){uint32_t a=address(s,o);w->m[a]=(uint8_t)v;w->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++w->o->bus_writes;}
static void wb(work *w,uint16_t o,uint8_t v){w->m[address(w->r.registers.ds,o)]=v;++w->o->bus_writes;}
static void push(work *w,uint16_t v){w->sp=(uint16_t)(w->sp-2);put(w,w->ss,w->sp,v);}
static uint16_t pop(work *w){uint16_t v=word(w,w->ss,w->sp);w->sp=(uint16_t)(w->sp+2);return v;}
static uint16_t logic(work *w,uint16_t v){w->r.carry=0;w->zf=(uint16_t)(v==0);return v;}
static uint16_t shl(work *w,uint16_t v){w->r.carry=(uint16_t)(v>>15);v=(uint16_t)(v<<1);w->zf=(uint16_t)(v==0);return v;}
static int valid(const td2ega_state_registers *r){return r->carry<=1 && r->registers.interrupts_enabled<=1 && r->registers.direction<=1;}
#define AX w.r.registers.ax
#define BX w.r.registers.bx
#define SI w.r.registers.si
#define DI w.r.registers.di
#define BP w.r.bp
#define CF w.r.carry
void td2ega_key_dispatch_bus(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,uint16_t sp,const td2ega_state_registers *in,uint32_t max_calls,td2ega_key_dispatch_bus_service service,void *context,td2ega_key_dispatch_bus_result *out)
{
    work w;uint16_t v,target,expected_sp,site;td2ega_key_dispatch_bus_request request;td2ega_key_dispatch_bus_response response;
    if(out==NULL)return;
    *out=(td2ega_key_dispatch_bus_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || !valid(in))return;
    w=(work){m,(uint16_t)(load+0x6c9),ss,sp,0,*in,out};push(&w,BP);BP=w.sp;w.r.registers.interrupts_enabled=0;v=byte(&w,0x6252);CF=0;w.zf=(uint16_t)(v==0);
    if(v!=0){w.r.registers.interrupts_enabled=1;BP=pop(&w);site=0x6535;goto root;}
    wb(&w,0x6252,1);w.r.registers.interrupts_enabled=1;BX=word(&w,ss,(uint16_t)(BP+6));logic(&w,(uint8_t)BX);
    if(!w.zf){BX=logic(&w,(uint16_t)(BX&0x7f));put(&w,ss,(uint16_t)(BP+6),BX);BX=shl(&w,BX);BX=word(&w,w.r.registers.ds,(uint16_t)(BX+0x6048));}
    else{BX=(uint16_t)(BX>>8);CF=0;w.zf=1;CF=(uint16_t)(BX<0x84);w.zf=(uint16_t)(BX==0x84);if(BX>=0x84)BX=0x84;BX=shl(&w,BX);BX=word(&w,w.r.registers.ds,(uint16_t)(BX+0x6148));}
    logic(&w,BX);if(w.zf){AX=word(&w,ss,(uint16_t)(BP+6));wb(&w,0x6252,0);BP=pop(&w);site=0x6584;goto root;}
    target=BX;out->callback_target=target;push(&w,DI);push(&w,SI);expected_sp=w.sp;AX=w.cs;push(&w,AX);
    if(out->calls==max_calls){out->status=3;out->next_segment=w.cs;out->next_ip=0x6559;goto done;}
    ++out->calls;push(&w,0x655b);request=(td2ega_key_dispatch_bus_request){0x6559,w.cs,target,ss,w.sp,w.r};out->next_segment=w.cs;out->next_ip=target;
    response=(td2ega_key_dispatch_bus_response){0};
    if(service==NULL || !service(context,m,&request,&response) || response.status>5 || response.status==2 || !valid(&response.returned)){out->status=4;goto done;}
    w.sp=response.current_sp;w.r=response.returned;out->bus_writes+=response.bus_writes;out->next_segment=response.next_segment;out->next_ip=response.next_ip;
    if(response.status!=0){out->status=response.status;goto done;}
    if(out->next_segment!=w.cs || out->next_ip!=0x655b || w.sp!=expected_sp){out->status=1;goto done;}
    SI=pop(&w);DI=pop(&w);AX=logic(&w,0);wb(&w,0x6252,0);BP=pop(&w);site=0x6565;
root:
    if(w.sp>UINT16_C(0xfffc)){out->status=5;out->next_segment=w.cs;out->next_ip=site;goto done;}
    out->next_ip=pop(&w);out->next_segment=pop(&w);out->status=0;out->zero_flag=w.zf;out->flags_valid=1;
done:
    out->current_sp=w.sp;out->returned=w.r;
}
