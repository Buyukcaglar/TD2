#include "td2ega_shift_assign.h"
#include <stddef.h>
static uint32_t address(uint16_t s,uint16_t o)
{return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(const uint8_t *m,uint16_t s,uint16_t o)
{uint32_t a=address(s,o);return (uint16_t)(m[a]|((uint16_t)m[(a+1)&UINT32_C(0xfffff)]<<8));}
static void put(uint8_t *m,uint16_t s,uint16_t o,uint16_t v)
{uint32_t a=address(s,o);m[a]=(uint8_t)v;m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);}
static void push(uint8_t *m,uint16_t ss,uint16_t *sp,uint16_t v)
{*sp=(uint16_t)(*sp-2);put(m,ss,*sp,v);}
static uint16_t pop(const uint8_t *m,uint16_t ss,uint16_t *sp)
{uint16_t v=word(m,ss,*sp);*sp=(uint16_t)(*sp+2);return v;}
void td2ega_shift_assign(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,
    uint16_t sp,const td2ega_state_registers *in,td2ega_shift_assign_result *out)
{
    td2ega_state_registers r;td2ega_small_state_result child;uint16_t cs;
    if(out==NULL)return;
    *out=(td2ega_shift_assign_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || sp<32 || sp>UINT16_C(0xffe0) || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1)return;
    cs=(uint16_t)(load+0x13a8);r=*in;push(m,ss,&sp,r.bp);r.bp=sp;out->bus_writes=1;
    r.registers.bx=word(m,ss,(uint16_t)(r.bp+6));r.registers.ax=word(m,r.registers.ds,r.registers.bx);r.registers.dx=word(m,r.registers.ds,(uint16_t)(r.registers.bx+2));r.registers.cx=word(m,ss,(uint16_t)(r.bp+8));out->shift_count=(uint8_t)r.registers.cx;
    push(m,ss,&sp,cs);push(m,ss,&sp,0x2fe3);out->bus_writes+=2;
    td2ega_small_state(m,bytes,load,ss,sp,6,&r,&child);r=child.returned;sp=child.current_sp;out->bus_writes+=child.writes;
    if(child.status!=0){out->status=child.status;goto finish;}
    if(child.next_segment!=cs || child.next_ip!=0x2fe3){out->status=1;out->next_segment=child.next_segment;out->next_ip=child.next_ip;goto finish;}
    r.registers.bx=word(m,ss,(uint16_t)(r.bp+6));put(m,r.registers.ds,r.registers.bx,r.registers.ax);put(m,r.registers.ds,(uint16_t)(r.registers.bx+2),r.registers.dx);out->bus_writes+=2;
    sp=r.bp;r.bp=pop(m,ss,&sp);out->next_ip=pop(m,ss,&sp);out->next_segment=pop(m,ss,&sp);sp=(uint16_t)(sp+4);out->status=0;
finish:
    out->current_sp=sp;out->returned=r;
}
