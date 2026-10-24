#include "td2ega_config_apply.h"
#include <stddef.h>
static uint32_t address(uint16_t s,uint16_t o)
{return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(const uint8_t *m,uint16_t s,uint16_t o)
{uint32_t a=address(s,o);return (uint16_t)(m[a]|((uint16_t)m[(a+1)&UINT32_C(0xfffff)]<<8));}
static void put(uint8_t *m,uint16_t s,uint16_t o,uint16_t v)
{uint32_t a=address(s,o);m[a]=(uint8_t)v;m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);}
static void push(uint8_t *m,uint16_t ss,uint16_t *sp,uint16_t v)
{*sp=(uint16_t)(*sp-2);put(m,ss,*sp,v);}
void td2ega_config_apply(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,
    uint16_t sp,const td2ega_state_registers *in,uint32_t limit,
    td2ega_config_apply_result *out)
{
    td2ega_copy_config_result child;uint16_t cs;uint32_t sum;
    if(out==NULL)return;
    *out=(td2ega_config_apply_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || sp<32 || sp>UINT16_C(0xffe0) || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1)return;
    cs=(uint16_t)(load+0x6c9);
    push(m,ss,&sp,word(m,in->registers.ds,0x9b4));
    push(m,ss,&sp,word(m,in->registers.ds,0x9b2));
    push(m,ss,&sp,cs);push(m,ss,&sp,0x3f09);out->writes=4;out->calls=1;
    td2ega_copy_config(m,bytes,load,ss,sp,1,in,limit,&child);
    out->work=child.work;out->writes+=child.writes;out->returned=child.returned;sp=child.current_sp;
    if(child.status!=0){out->status=child.status;goto finish;}
    if(child.next_segment!=cs || child.next_ip!=0x3f09){out->status=1;out->next_segment=child.next_segment;out->next_ip=child.next_ip;goto finish;}
    sum=(uint32_t)sp+4;sp=(uint16_t)sum;out->returned.carry=(uint16_t)(sum>>16);
    out->next_ip=word(m,ss,sp);sp=(uint16_t)(sp+2);out->next_segment=word(m,ss,sp);sp=(uint16_t)(sp+2);out->status=0;
finish:
    out->current_sp=sp;
}
