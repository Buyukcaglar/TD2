#include "td2ega_small_arithmetic.h"
#include <stddef.h>
static uint32_t address(uint16_t s,uint16_t o)
{return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(const uint8_t *m,uint16_t s,uint16_t o)
{uint32_t a=address(s,o);return (uint16_t)(m[a]|((uint16_t)m[(a+1)&UINT32_C(0xfffff)]<<8));}
static void put(uint8_t *m,uint16_t s,uint16_t o,uint16_t v)
{uint32_t a=address(s,o);m[a]=(uint8_t)v;m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);}
static int32_t signedword(uint16_t v)
{return v&0x8000?(int32_t)v-65536:(int32_t)v;}
void td2ega_small_arithmetic(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,
    uint16_t sp,uint16_t entry,const td2ega_state_registers *in,uint32_t limit,
    td2ega_small_arithmetic_result *out)
{
    td2ega_state_registers r;uint16_t value,borrow;uint32_t wide,numerator;int32_t difference,divisor,quotient,remainder;
    if(out==NULL)return;
    *out=(td2ega_small_arithmetic_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || entry>3 || sp<16 || sp>UINT16_C(0xffe0) || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1)return;
    r=*in;out->next_segment=(uint16_t)(load+(entry==1?0x143:0x6c9));
    if(entry==0){
        r.carry=(uint16_t)((r.registers.cx>>2)&1);r.registers.cx>>=3;r.bp=word(m,r.registers.ds,0x380d);
        do{
            if(out->iterations==limit){out->status=3;out->next_ip=0x5c3a;goto finish;}++out->iterations;
            r.registers.bx=word(m,r.registers.ds,(uint16_t)(r.registers.si+4));borrow=(uint16_t)(r.registers.bx<r.registers.ax);r.registers.bx=word(m,r.registers.ds,(uint16_t)(r.registers.si+2));difference=signedword(r.registers.bx)-signedword(r.registers.dx)-borrow;r.registers.bx=(uint16_t)(r.registers.bx-r.registers.dx-borrow);
            if(difference<0)r.registers.bx=(uint16_t)(r.registers.bx+word(m,r.registers.ds,0x380d));
            if(r.registers.bx<=r.bp){r.registers.di=r.registers.si;r.bp=r.registers.bx;}
            wide=(uint32_t)r.registers.si+8;r.registers.si=(uint16_t)wide;r.carry=(uint16_t)(wide>65535);--r.registers.cx;
        }while(r.registers.cx!=0);
        r.registers.si=r.registers.di;
    }else if(entry==1){
        value=(uint16_t)(word(m,r.registers.ds,0x2de)+1);put(m,r.registers.ds,0x2de,value);value=(uint16_t)(word(m,r.registers.ds,0x83c8)+1);put(m,r.registers.ds,0x83c8,value);out->bus_writes=2;value=word(m,r.registers.ds,0x2de);if(signedword(value)>200){put(m,r.registers.ds,0x2de,200);++out->bus_writes;}
        r.registers.ax=word(m,r.registers.ds,0x2de);r.registers.dx=r.registers.ax&0x8000?0xffff:0;r.registers.cx=20;quotient=signedword(r.registers.ax)/20;remainder=signedword(r.registers.ax)%20;r.registers.ax=(uint16_t)quotient;r.registers.dx=(uint16_t)remainder;wide=(uint32_t)word(m,r.registers.ds,0x2e0)+r.registers.ax;put(m,r.registers.ds,0x2e0,(uint16_t)wide);++out->bus_writes;r.carry=(uint16_t)(wide>65535);
        r.registers.ax=word(m,r.registers.ds,0x83c8);r.registers.dx=r.registers.ax&0x8000?0xffff:0;r.registers.cx=word(m,r.registers.ds,0x83ca);divisor=signedword(r.registers.cx);
        if(divisor==0 || (r.registers.ax==0x8000 && divisor==-1)){out->status=5;out->next_ip=0x1c9;goto finish;}
        quotient=signedword(r.registers.ax)/divisor;remainder=signedword(r.registers.ax)%divisor;r.registers.ax=(uint16_t)quotient;r.registers.dx=(uint16_t)remainder;r.carry=0;
        if(remainder==0){value=(uint16_t)(word(m,r.registers.ds,0x83cc)+1);put(m,r.registers.ds,0x83cc,value);++out->bus_writes;r.registers.ax=word(m,r.registers.ds,0x83ce);value=word(m,r.registers.ds,0x83cc);r.carry=(uint16_t)(value<r.registers.ax);if(signedword(value)>=signedword(r.registers.ax)){--r.registers.ax;put(m,r.registers.ds,0x83cc,r.registers.ax);++out->bus_writes;}}
    }else if(entry==2){
        r.carry=0;if(word(m,r.registers.ds,(uint16_t)(r.registers.si+2))==0 || word(m,r.registers.ds,(uint16_t)(r.registers.di+2))==0)goto returned;
        r.registers.cx=word(m,r.registers.ds,r.registers.di);borrow=(uint16_t)(r.registers.cx<word(m,r.registers.ds,r.registers.si));r.registers.cx=(uint16_t)(word(m,r.registers.ds,(uint16_t)(r.registers.di+2))-word(m,r.registers.ds,(uint16_t)(r.registers.si+2))-borrow);--r.registers.cx;r.registers.ax=(uint16_t)(r.registers.bx^r.registers.cx);if((r.registers.ax&0x8000)==0)goto returned;
        r.registers.ax=(uint16_t)(r.registers.dx+180);value=word(m,r.registers.ds,(uint16_t)(r.registers.di+4));if(signedword(r.registers.ax)<signedword(value))goto returned;r.registers.ax=(uint16_t)(r.registers.ax-360);value=word(m,r.registers.ds,(uint16_t)(r.registers.di+4));if(signedword(r.registers.ax)>signedword(value))goto returned;
        r.registers.ax=(uint16_t)(word(m,r.registers.ds,(uint16_t)(r.registers.si+2))+1);r.registers.cx=1;if(signedword(r.registers.bx)<0){r.registers.ax=(uint16_t)(r.registers.ax-2);r.registers.cx=0xffff;}put(m,r.registers.ds,(uint16_t)(r.registers.di+2),r.registers.ax);r.registers.ax=word(m,r.registers.ds,r.registers.si);put(m,r.registers.ds,r.registers.di,r.registers.ax);out->bus_writes=2;r.carry=1;
    }else{
        r.registers.dx=(uint16_t)(word(m,r.registers.ds,0x380f)+0x3b42);r.carry=(uint16_t)(r.registers.bx<r.registers.dx);if(r.registers.bx>=r.registers.dx)goto rejected;
        wide=(uint32_t)r.registers.si*r.registers.si;r.registers.dx=(uint16_t)(wide>>16);r.registers.ax=r.registers.dx;r.registers.dx=0;r.registers.cx=r.registers.ax;wide=(uint32_t)r.registers.ax*3;r.registers.ax=(uint16_t)wide;r.registers.dx=(uint16_t)(wide>>16);r.carry=0;numerator=wide;
        if(r.registers.di==0 || numerator/r.registers.di>65535){out->status=5;out->next_ip=0x5c79;goto finish;}
        r.registers.ax=(uint16_t)(numerator/r.registers.di);r.registers.dx=(uint16_t)(numerator%r.registers.di);r.carry=(uint16_t)(r.registers.ax&1);r.registers.ax>>=1;r.registers.dx=(uint16_t)(word(m,r.registers.ds,0x380f)+0x3b42);r.registers.dx=(uint16_t)(r.registers.dx-r.registers.bx);r.carry=(uint16_t)(r.registers.dx<r.registers.ax);if(r.registers.dx>r.registers.ax){r.registers.ax=0;r.carry=0;goto returned;}
rejected:
        put(m,r.registers.ds,0x3344,0);++out->bus_writes;r.registers.ax=(uint16_t)((r.registers.ax&0xff00)|1);
    }
returned:
    out->next_ip=word(m,ss,sp);sp=(uint16_t)(sp+2);if(entry==1){out->next_segment=word(m,ss,sp);sp=(uint16_t)(sp+2);}out->status=0;
finish:
    out->current_sp=sp;out->returned=r;
}
