#include "td2ega_table_scalar.h"
#include <stddef.h>
static uint32_t address(uint16_t s,uint16_t o)
{return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(const uint8_t *m,uint16_t s,uint16_t o)
{uint32_t a=address(s,o);return (uint16_t)(m[a]|((uint16_t)m[(a+1)&UINT32_C(0xfffff)]<<8));}
static void put(uint8_t *m,uint16_t s,uint16_t o,uint16_t v,unsigned size)
{uint32_t a=address(s,o);m[a]=(uint8_t)v;if(size==2)m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);}
static int32_t signedword(uint16_t v)
{return (v&0x8000)?(int32_t)v-65536:(int32_t)v;}
static uint16_t signbyte(uint8_t v)
{return (uint16_t)(v|((v&0x80)?0xff00:0));}
void td2ega_table_scalar(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,
    uint16_t sp,uint16_t entry,const td2ega_state_registers *in,
    td2ega_table_scalar_result *out)
{
    td2ega_state_registers r;uint16_t value,threshold;uint8_t al,ah;
    if(out==NULL)return;
    *out=(td2ega_table_scalar_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || entry>4 || sp<16 || sp>UINT16_C(0xffe0) || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1)return;
    r=*in;
    if(entry==0){
        al=(uint8_t)r.registers.ax;ah=(uint8_t)(r.registers.ax>>8);put(m,r.registers.ds,0x6da0,al,1);++out->bus_writes;r.carry=0;
        if(ah){al=ah;}else{
            value=m[address(r.registers.ds,0x6d9d)];r.carry=(uint16_t)(value<3);
            if(value>=3){r.carry=(uint16_t)(al<0x22);if(al>=0x22)al=0x13;else{r.carry=(uint16_t)(al<0x20);if(al>=0x20)al=5;else{r.carry=(uint16_t)(al<0x13);if(al>0x13)al=0x13;}}}
            else{r.carry=(uint16_t)(al<0x13);if(al>0x13)al=0x13;}
            r.registers.bx=0x6dda;al=m[address(r.registers.ds,(uint16_t)(r.registers.bx+al))];
        }
        r.registers.ax=signbyte(al);put(m,r.registers.ds,0x6d95,r.registers.ax,2);++out->bus_writes;
    }else if(entry==1){
        sp=(uint16_t)(sp-2);put(m,ss,sp,r.bp,2);++out->bus_writes;r.bp=sp;r.registers.bx=0x2cb3;r.registers.cx=6;al=(uint8_t)r.registers.ax;
        for(;;){value=m[address((uint16_t)(load+0x13a8),r.registers.bx)];r.carry=(uint16_t)(value<al);if(value==al){--r.registers.cx;r.registers.ax=(uint16_t)(r.registers.cx*4);r.registers.bx=(uint16_t)(0x7058+r.registers.ax);r.carry=0;break;}--r.registers.bx;--r.registers.cx;if(r.registers.cx==0){r.carry=1;break;}}
        sp=r.bp;r.bp=word(m,ss,sp);sp=(uint16_t)(sp+2);
    }else if(entry==2){
        sp=(uint16_t)(sp-2);put(m,ss,sp,r.registers.bx,2);sp=(uint16_t)(sp-2);put(m,ss,sp,r.registers.dx,2);out->bus_writes=2;r.registers.ax=signbyte((uint8_t)r.registers.ax);r.registers.bx=r.registers.ax;r.registers.dx=r.registers.bx;
        if(signedword(r.registers.bx)<0)r.registers.bx=(uint16_t)(0-r.registers.bx);
        al=(uint8_t)r.registers.bx;if((int32_t)(al&0x80?al-256:al)>0x5a){al=(uint8_t)(0xb4-al);r.registers.bx=(uint16_t)((r.registers.bx&0xff00)|al);}
        r.registers.bx=(uint16_t)(r.registers.bx<<1);r.registers.ax=word(m,r.registers.ds,(uint16_t)(r.registers.bx+0x54aa));r.carry=0;if(signedword(r.registers.dx)<0){r.carry=(uint16_t)(r.registers.ax!=0);r.registers.ax=(uint16_t)(0-r.registers.ax);}r.registers.dx=word(m,ss,sp);sp=(uint16_t)(sp+2);r.registers.bx=word(m,ss,sp);sp=(uint16_t)(sp+2);
    }else if(entry==3){
        r.registers.si=0;r.carry=(uint16_t)(r.registers.bx<0xfe70);if(signedword(r.registers.bx)<-400)goto returned;
        r.carry=0;if(signedword(r.registers.bx)>=0){r.registers.si=2;r.carry=(uint16_t)(r.registers.bx<0x190);if(signedword(r.registers.bx)>=400){r.registers.si=4;r.carry=(uint16_t)(r.registers.bx<0x320);if(signedword(r.registers.bx)>800)goto returned;}}
        threshold=word(m,r.registers.ds,(uint16_t)(r.registers.si+0x333e));r.carry=(uint16_t)(r.registers.ax<threshold);if(signedword(r.registers.ax)<signedword(threshold)){put(m,r.registers.ds,(uint16_t)(r.registers.si+0x333e),r.registers.ax,2);++out->bus_writes;}
    }else{
        r.registers.dx=word(m,r.registers.ds,0x333e);r.registers.cx=0xff38;value=word(m,r.registers.ds,0x3340);if(signedword(r.registers.dx)<=signedword(value)){r.registers.dx=value;r.registers.cx=0xc8;}r.carry=0;
        if(m[address(r.registers.ds,0x33be)]&0x80){value=word(m,r.registers.ds,0x3342);r.carry=(uint16_t)(r.registers.dx<value);if(signedword(r.registers.dx)<signedword(value))r.registers.cx=0x258;}
        r.carry=(uint16_t)(r.registers.ax<0xffd8);if(signedword(r.registers.ax)<-40)r.registers.dx=word(m,r.registers.ds,0x333e);
        else{r.carry=(uint16_t)(r.registers.ax<0x28);if(signedword(r.registers.ax)<=40)r.registers.dx=100;else{r.carry=(uint16_t)(r.registers.ax<0x1b8);if(signedword(r.registers.ax)>440)r.registers.dx=word(m,r.registers.ds,0x3342);else{r.carry=(uint16_t)(r.registers.ax<0x168);r.registers.dx=signedword(r.registers.ax)<360?100:word(m,r.registers.ds,0x3340);}}}
    }
returned:
    out->next_ip=word(m,ss,sp);sp=(uint16_t)(sp+2);out->next_segment=(uint16_t)(load+(entry==2?0x13a3:entry>=3?0x6c9:0x13a8));if(entry==1 || entry==2){out->next_segment=word(m,ss,sp);sp=(uint16_t)(sp+2);}out->current_sp=sp;out->returned=r;out->status=0;
}
