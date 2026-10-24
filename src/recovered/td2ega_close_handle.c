#include "td2ega_close_handle.h"
#include "td2ega_table_scalar.h"
#include <stddef.h>
static uint32_t address(uint16_t s,uint16_t o){return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(const uint8_t *m,uint16_t s,uint16_t o){uint32_t a=address(s,o);return (uint16_t)(m[a]|((uint16_t)m[(a+1)&UINT32_C(0xfffff)]<<8));}
static void put(uint8_t *m,uint16_t s,uint16_t o,uint16_t v){uint32_t a=address(s,o);m[a]=(uint8_t)v;m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);}
static int valid(const td2ega_state_registers *r){return r->carry<=1 && r->registers.interrupts_enabled<=1 && r->registers.direction<=1;}
void td2ega_close_handle(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,uint16_t sp,const td2ega_state_registers *in,td2ega_small_platform_service service,void *context,uint32_t limit,td2ega_close_handle_result *out)
{
    td2ega_state_registers r,returned;td2ega_small_platform_request request;td2ega_table_scalar_result mapped;uint16_t cs=(uint16_t)(load+0x13a8),expected;
    if(out==NULL)return;
    *out=(td2ega_close_handle_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || sp<20 || sp>UINT16_C(0xffe0) || !valid(in))return;
    r=*in;sp=(uint16_t)(sp-2);put(m,ss,sp,r.bp);r.bp=sp;out->bus_writes=1;r.registers.bx=word(m,ss,(uint16_t)(r.bp+6));r.carry=(uint16_t)(r.registers.bx<word(m,r.registers.ds,0x6da2));
    if(!r.carry){r.registers.ax=0x900;r.carry=1;}
    else{
        r.registers.ax=(uint16_t)((r.registers.ax&0xff)|0x3e00);out->next_segment=cs;out->next_ip=0x2252;
        if(limit==0){out->status=3;goto finish;}
        request=(td2ega_small_platform_request){0x21,0x2252,cs,ss,sp,r};returned=r;
        if(service==NULL || !service(context,m,&request,&returned) || !valid(&returned)){out->status=4;goto finish;}++out->services;r=returned;
        if(!r.carry){m[address(r.registers.ds,(uint16_t)(r.registers.bx+0x6da4))]=0;++out->bus_writes;}
    }
    if(r.carry){expected=sp;sp=(uint16_t)(sp-2);put(m,ss,sp,0x93c);++out->bus_writes;++out->error_calls;td2ega_table_scalar(m,bytes,load,ss,sp,0,&r,&mapped);out->bus_writes+=mapped.bus_writes;r=mapped.returned;sp=mapped.current_sp;if(mapped.status!=0 || mapped.next_segment!=cs || mapped.next_ip!=0x93c || sp!=expected){out->status=1;out->next_segment=mapped.next_segment;out->next_ip=mapped.next_ip;goto finish;}r.registers.ax=0xffff;r.registers.dx=0xffff;}
    else{r.registers.ax=0;r.carry=0;}
    sp=r.bp;r.bp=word(m,ss,sp);sp=(uint16_t)(sp+2);out->next_ip=word(m,ss,sp);sp=(uint16_t)(sp+2);out->next_segment=word(m,ss,sp);sp=(uint16_t)(sp+2);out->status=0;
finish:
    out->current_sp=sp;out->returned=r;
}
