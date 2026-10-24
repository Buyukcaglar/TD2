#include "td2ega_finalizer_list.h"
#include <stddef.h>
static uint32_t address(uint16_t s,uint16_t o)
{return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t physicalword(const uint8_t *m,uint32_t a)
{return (uint16_t)(m[a]|((uint16_t)m[(a+1)&UINT32_C(0xfffff)]<<8));}
static uint16_t word(const uint8_t *m,uint16_t s,uint16_t o)
{return physicalword(m,address(s,o));}
static void put(uint8_t *m,uint16_t s,uint16_t o,uint16_t v)
{uint32_t a=address(s,o);m[a]=(uint8_t)v;m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);}
static int valid(const td2ega_state_registers *r)
{return r->carry<=1 && r->registers.interrupts_enabled<=1 && r->registers.direction<=1;}
void td2ega_finalizer_list(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,
    uint16_t sp,const td2ega_state_registers *in,td2ega_finalizer_service service,
    void *context,uint32_t limit,td2ega_finalizer_result *out)
{
    td2ega_state_registers r,returned;td2ega_finalizer_request request;uint16_t cs=(uint16_t)(load+0x13a8),segment,ip;uint32_t a;
    if(out==NULL)return;
    *out=(td2ega_finalizer_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || sp<16 || sp>UINT16_C(0xffe0) || !valid(in))return;
    r=*in;
    for(;;){
        r.carry=(uint16_t)(r.registers.si<r.registers.di);if(!r.carry)break;
        if(out->iterations==limit){out->status=3;out->next_segment=cs;out->next_ip=0x611;goto finish;}++out->iterations;r.registers.di=(uint16_t)(r.registers.di-4);r.registers.ax=(uint16_t)(word(m,r.registers.ds,r.registers.di)|word(m,r.registers.ds,(uint16_t)(r.registers.di+2)));r.carry=0;if(r.registers.ax==0)continue;
        a=address(r.registers.ds,r.registers.di);ip=physicalword(m,a);segment=physicalword(m,(a+2)&UINT32_C(0xfffff));sp=(uint16_t)(sp-2);put(m,ss,sp,cs);sp=(uint16_t)(sp-2);put(m,ss,sp,0x61d);out->bus_writes+=2;out->next_segment=segment;out->next_ip=ip;request=(td2ega_finalizer_request){0x61b,segment,ip,ss,sp,r};returned=r;
        if(service==NULL || !service(context,m,&request,&returned) || !valid(&returned)){out->status=4;goto finish;}++out->calls;r=returned;
        ip=word(m,ss,sp);sp=(uint16_t)(sp+2);segment=word(m,ss,sp);sp=(uint16_t)(sp+2);if(segment!=cs || ip!=0x61d){out->status=1;out->next_segment=segment;out->next_ip=ip;goto finish;}
    }
    out->next_segment=cs;out->next_ip=word(m,ss,sp);sp=(uint16_t)(sp+2);out->status=0;
finish:
    out->current_sp=sp;out->returned=r;
}
