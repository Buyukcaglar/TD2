#include "td2ega_record_flags.h"
#include <stddef.h>
static uint32_t address(uint16_t s,uint16_t o){return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(const uint8_t *m,uint16_t s,uint16_t o){uint32_t a=address(s,o);return (uint16_t)(m[a]|((uint16_t)m[(a+1)&UINT32_C(0xfffff)]<<8));}
static int32_t sw(uint16_t v){return v&0x8000?(int32_t)v-65536:(int32_t)v;}
static uint16_t parity(uint16_t v){unsigned i,n=0;for(i=0;i<8;++i)n+=(v>>i)&1;return (uint16_t)((n&1)?0:4);}
static uint16_t result_flags(uint16_t value){return (uint16_t)(parity(value)|(value==0?0x40:0)|(value&0x8000?0x80:0));}
static uint16_t compare_flags(uint16_t a,uint16_t b){uint16_t r=(uint16_t)(a-b);return (uint16_t)(result_flags(r)|(((a^b^r)&0x10)?0x10:0)|(((a^b)&(a^r)&0x8000)?0x800:0));}
static uint16_t classify(const uint8_t *m,const td2ega_state_registers *r)
{
    uint16_t ds=r->registers.ds,at=(uint16_t)(r->bp+r->registers.si),low=word(m,ds,(uint16_t)(at+4)),high=word(m,ds,(uint16_t)(at+2)),borrow=(uint16_t)(low<r->registers.ax),bx=(uint16_t)(high-r->registers.dx-borrow),di=r->registers.di,value;int32_t difference=sw(high)-sw(r->registers.dx)-borrow;uint8_t flag;
    if(difference>0)bx=(uint16_t)(bx-word(m,ds,0x380d));
    if(sw(bx)<-4)return 0x4fa9;
    if(m[address(ds,0x33b9)]!=0)return 0x5016;
    flag=m[address(ds,0x33b4)];if(flag!=0 && !(flag&0x80))return 0x5021;
    di=(uint16_t)(di-180);value=word(m,ds,(uint16_t)(at+6));if(sw(value)<sw(di))return 0x5021;di=(uint16_t)(di+360);value=word(m,ds,(uint16_t)(at+6));if(sw(value)>sw(di))return 0x5021;return 0x5016;
}
void td2ega_record_flags(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,uint16_t sp,const td2ega_state_registers *in,uint32_t limit,td2ega_record_flags_result *out)
{
    uint16_t path,value;
    if(out==NULL)return;
    *out=(td2ega_record_flags_result){0};out->body.status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || sp<16 || sp>UINT16_C(0xffe0) || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1)return;
    path=classify(m,in);td2ega_record_math(m,bytes,load,ss,sp,3,in,limit,&out->body);out->defined_flags=(uint16_t)(2|out->body.returned.carry|(out->body.returned.registers.interrupts_enabled<<9)|(out->body.returned.registers.direction<<10));out->defined_mask=0x0603;
    if(out->body.status!=0)return;
    out->return_site=path;out->defined_mask=0x0ed7;
    if(path==0x5016){out->defined_flags|=0x44;out->defined_mask=0x0ec7;}
    else if(path==0x4fa9)out->defined_flags|=compare_flags(out->body.returned.registers.bx,0xfffc);
    else{value=out->body.returned.registers.dx;out->defined_flags|=(uint16_t)(result_flags(value)|((value&15)==0?0x10:0)|(value==0x8000?0x800:0));}
}
