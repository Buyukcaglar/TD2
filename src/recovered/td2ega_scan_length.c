#include "td2ega_scan_length.h"
#include <stddef.h>
static uint32_t address(uint16_t s,uint16_t o)
{return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(const uint8_t *m,uint16_t s,uint16_t o)
{uint32_t a=address(s,o);return (uint16_t)(m[a]|((uint16_t)m[(a+1)&UINT32_C(0xfffff)]<<8));}
static void put(uint8_t *m,uint16_t s,uint16_t o,uint16_t v)
{uint32_t a=address(s,o);m[a]=(uint8_t)v;m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);}
static uint16_t pop(const uint8_t *m,uint16_t ss,uint16_t *sp)
{uint16_t v=word(m,ss,*sp);*sp=(uint16_t)(*sp+2);return v;}
void td2ega_scan_length(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,
    uint16_t sp,const td2ega_state_registers *in,uint32_t limit,
    td2ega_scan_length_result *out)
{
    td2ega_state_registers r;uint8_t value;(void)load;
    if(out==NULL)return;
    *out=(td2ega_scan_length_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || sp<16 || sp>UINT16_C(0xffe0) || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1)return;
    r=*in;sp=(uint16_t)(sp-2);put(m,ss,sp,r.bp);r.bp=sp;out->bus_writes=1;
    r.registers.dx=r.registers.di;r.registers.ax=r.registers.ds;r.registers.es=r.registers.ax;r.registers.di=word(m,ss,(uint16_t)(r.bp+6));r.registers.ax=0;r.carry=0;r.registers.cx=0xffff;
    while(r.registers.cx!=0){
        if(out->scans==limit){out->status=3;goto finish;}
        ++out->scans;value=m[address(r.registers.es,r.registers.di)];r.carry=(uint16_t)(value!=0);r.registers.di=(uint16_t)(r.registers.di+(r.registers.direction?-1:1));--r.registers.cx;
        if(value==0)break;
    }
    r.registers.cx=(uint16_t)~r.registers.cx;r.registers.cx=(uint16_t)(r.registers.cx-1);r.registers.ax=r.registers.cx;r.registers.cx=0;r.registers.di=r.registers.dx;r.bp=pop(m,ss,&sp);out->next_ip=pop(m,ss,&sp);out->next_segment=pop(m,ss,&sp);out->status=0;
finish:
    out->current_sp=sp;out->returned=r;
}
