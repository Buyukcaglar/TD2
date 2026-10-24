#include "td2ega_far_member.h"
#include <stddef.h>
static uint32_t address(uint16_t s,uint16_t o)
{return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(const uint8_t *m,uint16_t s,uint16_t o)
{uint32_t a=address(s,o);return (uint16_t)(m[a]|((uint16_t)m[(a+1)&UINT32_C(0xfffff)]<<8));}
static void put(uint8_t *m,uint16_t s,uint16_t o,uint16_t v)
{uint32_t a=address(s,o);m[a]=(uint8_t)v;m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);}
static uint16_t pop(const uint8_t *m,uint16_t ss,uint16_t *sp)
{uint16_t v=word(m,ss,*sp);*sp=(uint16_t)(*sp+2);return v;}
void td2ega_far_member(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,
    uint16_t sp,const td2ega_state_registers *in,td2ega_far_member_result *out)
{
    td2ega_state_registers r;uint16_t count,table,base,index;uint32_t linear,displacement;(void)load;
    if(out==NULL)return;
    *out=(td2ega_far_member_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || sp<16 || sp>UINT16_C(0xffe0) || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1)return;
    r=*in;sp=(uint16_t)(sp-2);put(m,ss,sp,r.bp);r.bp=sp;sp=(uint16_t)(sp-2);put(m,ss,sp,r.registers.si);out->bus_writes=2;r.registers.es=word(m,ss,(uint16_t)(r.bp+8));r.registers.si=word(m,ss,(uint16_t)(r.bp+6));count=word(m,r.registers.es,(uint16_t)(r.registers.si+4));r.registers.ax=(uint16_t)(count<<2);index=word(m,ss,(uint16_t)(r.bp+10));table=(uint16_t)((uint16_t)(index<<2)+r.registers.ax+6);base=(uint16_t)((uint16_t)(r.registers.ax<<1)+6);r.registers.cx=(uint16_t)(r.registers.es<<4);displacement=(uint32_t)word(m,r.registers.es,table)|((uint32_t)word(m,r.registers.es,(uint16_t)(table+2))<<16);linear=((uint32_t)r.registers.es<<4)+base+displacement;r.carry=(uint16_t)((linear>>3)&1);r.registers.bx=(uint16_t)(linear&15);r.registers.dx=(uint16_t)(linear>>4);r.registers.ax=r.registers.bx;r.registers.si=pop(m,ss,&sp);r.bp=pop(m,ss,&sp);out->next_ip=pop(m,ss,&sp);out->next_segment=pop(m,ss,&sp);out->status=0;out->current_sp=sp;out->returned=r;
}
