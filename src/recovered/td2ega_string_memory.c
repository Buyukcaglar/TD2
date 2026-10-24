#include "td2ega_string_memory.h"
#include <stddef.h>
typedef struct work {
    uint8_t *m;uint16_t ss,sp,cs;uint32_t limit;
    td2ega_state_registers r;td2ega_string_memory_result *out;
} work;
static uint32_t address(uint16_t s,uint16_t o)
{return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(work *w,uint16_t s,uint16_t o)
{uint32_t a=address(s,o);return (uint16_t)(w->m[a]|((uint16_t)w->m[(a+1)&UINT32_C(0xfffff)]<<8));}
static void put(work *w,uint16_t s,uint16_t o,uint16_t v,unsigned size)
{uint32_t a=address(s,o);w->m[a]=(uint8_t)v;if(size==2)w->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++w->out->bus_writes;}
static uint16_t pop(work *w)
{uint16_t v=word(w,w->ss,w->sp);w->sp=(uint16_t)(w->sp+2);return v;}
static int step(work *w,uint16_t ip)
{if(w->out->operations==w->limit){w->out->status=3;w->out->next_segment=w->cs;w->out->next_ip=ip;return 0;}++w->out->operations;return 1;}
static uint16_t advance(work *w,uint16_t v,unsigned size)
{return (uint16_t)(v+(w->r.registers.direction?-(int)size:(int)size));}
static int scan(work *w,uint16_t ip)
{
    while(w->r.registers.cx!=0){uint8_t value;if(!step(w,ip))return 0;value=w->m[address(w->r.registers.es,w->r.registers.di)];w->r.carry=(uint16_t)((uint8_t)w->r.registers.ax<value);w->r.registers.di=advance(w,w->r.registers.di,1);--w->r.registers.cx;if((uint8_t)w->r.registers.ax==value)break;}
    return 1;
}
static int transfer(work *w,uint16_t ip,unsigned size,int repeat,int fill)
{
    do{uint16_t value;if(repeat && w->r.registers.cx==0)break;if(!step(w,ip))return 0;value=fill?w->r.registers.ax:(size==2?word(w,w->r.registers.ds,w->r.registers.si):w->m[address(w->r.registers.ds,w->r.registers.si)]);put(w,w->r.registers.es,w->r.registers.di,value,size);if(!fill)w->r.registers.si=advance(w,w->r.registers.si,size);w->r.registers.di=advance(w,w->r.registers.di,size);if(repeat)--w->r.registers.cx;}while(repeat);
    return 1;
}
static uint8_t folded(uint8_t v)
{return (uint8_t)(v+((uint8_t)(v-0x41)<0x1a?0x20:0));}
void td2ega_string_memory(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,
    uint16_t sp,uint16_t entry,const td2ega_state_registers *in,uint32_t limit,
    td2ega_string_memory_result *out)
{
    work w;uint16_t old,count;uint8_t first,second;int equal=0;
    if(out==NULL)return;
    *out=(td2ega_string_memory_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || entry>4 || sp<16 || sp>UINT16_C(0xffe0) || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1)return;
    w=(work){m,ss,(uint16_t)(sp-2),(uint16_t)(load+0x13a8),limit,*in,out};put(&w,ss,w.sp,w.r.bp,2);w.r.bp=w.sp;
    if(entry==3){
        w.r.registers.dx=w.r.registers.si;w.r.registers.si=word(&w,ss,(uint16_t)(w.r.bp+8));w.r.registers.bx=word(&w,ss,(uint16_t)(w.r.bp+6));w.r.registers.ax=(uint16_t)((w.r.registers.ax&0xff00)|0xff);
        for(;;){
            w.r.carry=0;if((uint8_t)w.r.registers.ax==0)break;
            if(!step(&w,0x2b51))goto finish;
            second=w.m[address(w.r.registers.ds,w.r.registers.si)];w.r.registers.si=advance(&w,w.r.registers.si,1);first=w.m[address(w.r.registers.ds,w.r.registers.bx)];++w.r.registers.bx;w.r.registers.ax=(uint16_t)(((uint16_t)first<<8)|second);w.r.carry=(uint16_t)(first<second);
            if(first==second)continue;
            first=folded(first);second=folded(second);w.r.registers.cx=(uint16_t)((w.r.registers.cx&0xff00)|((uint8_t)((w.r.registers.ax>>8)-0x41)<0x1a?0x20:0));w.r.registers.ax=(uint16_t)(((uint16_t)second<<8)|first);w.r.carry=(uint16_t)(first<second);
            if(first==second)continue;
            w.r.registers.ax=(uint16_t)((w.r.registers.ax&0xff00)|(first<second?0xff:1));w.r.carry=1;break;
        }
        w.r.registers.ax=(uint16_t)((uint8_t)w.r.registers.ax|(((uint8_t)w.r.registers.ax&0x80)?0xff00:0));w.r.registers.si=w.r.registers.dx;
    }else{
        w.r.registers.dx=w.r.registers.di;
        if(entry!=4)w.r.registers.bx=w.r.registers.si;
        if(entry==1)w.r.registers.si=word(&w,ss,(uint16_t)(w.r.bp+8));
        w.r.registers.ax=w.r.registers.ds;w.r.registers.es=w.r.registers.ax;
        if(entry==4){
            w.r.registers.di=word(&w,ss,(uint16_t)(w.r.bp+6));w.r.registers.bx=w.r.registers.di;w.r.registers.cx=word(&w,ss,(uint16_t)(w.r.bp+10));
            if(w.r.registers.cx!=0){
                first=(uint8_t)word(&w,ss,(uint16_t)(w.r.bp+8));w.r.registers.ax=(uint16_t)(first|((uint16_t)first<<8));w.r.carry=0;
                if(w.r.registers.di&1){if(!transfer(&w,0x2ba0,1,0,1))goto finish;--w.r.registers.cx;}
                w.r.carry=(uint16_t)(w.r.registers.cx&1);w.r.registers.cx>>=1;if(!transfer(&w,0x2ba4,2,1,1))goto finish;w.r.registers.cx=w.r.carry;w.r.carry=0;if(!transfer(&w,0x2ba8,1,1,1))goto finish;
            }
            w.r.registers.di=w.r.registers.dx;old=w.r.registers.ax;w.r.registers.ax=w.r.registers.bx;w.r.registers.bx=old;
        }else{
            if(entry==2)w.r.registers.si=word(&w,ss,(uint16_t)(w.r.bp+6));
            w.r.registers.di=entry==1?w.r.registers.si:word(&w,ss,(uint16_t)(w.r.bp+(entry==0?6:8)));w.r.registers.ax=0;w.r.carry=0;w.r.registers.cx=0xffff;
            if(!scan(&w,entry==0?0x2929:entry==1?0x296b:0x299e))goto finish;
            if(entry==0){w.r.registers.si=(uint16_t)(w.r.registers.di-1);w.r.registers.di=word(&w,ss,(uint16_t)(w.r.bp+8));w.r.registers.cx=0xffff;if(!scan(&w,0x2934))goto finish;}
            w.r.registers.cx=(uint16_t)~w.r.registers.cx;
            if(entry!=1){old=w.r.registers.di;w.r.registers.di=(uint16_t)(old-w.r.registers.cx);w.r.carry=(uint16_t)(old<w.r.registers.cx);}
            if(entry==2){
                while(w.r.registers.cx!=0){if(!step(&w,0x29a4))goto finish;first=w.m[address(w.r.registers.ds,w.r.registers.si)];second=w.m[address(w.r.registers.es,w.r.registers.di)];equal=first==second;w.r.carry=(uint16_t)(first<second);w.r.registers.si=advance(&w,w.r.registers.si,1);w.r.registers.di=advance(&w,w.r.registers.di,1);--w.r.registers.cx;if(!equal)break;}
                if(!equal){w.r.registers.ax=w.r.carry?0xffff:1;w.r.carry=1;}
            }else{
                if(entry==0){old=w.r.registers.si;w.r.registers.si=w.r.registers.di;w.r.registers.di=old;}else w.r.registers.di=word(&w,ss,(uint16_t)(w.r.bp+6));
                w.r.registers.ax=entry==0?word(&w,ss,(uint16_t)(w.r.bp+6)):w.r.registers.di;w.r.carry=0;
                if((entry==0?w.r.registers.si:w.r.registers.ax)&1){if(!transfer(&w,entry==0?0x2945:0x2978,1,0,0))goto finish;--w.r.registers.cx;}
                count=w.r.registers.cx;w.r.carry=(uint16_t)(count&1);w.r.registers.cx=(uint16_t)(count>>1);if(!transfer(&w,entry==0?0x2949:0x297c,2,1,0))goto finish;w.r.registers.cx=w.r.carry;w.r.carry=0;if(!transfer(&w,entry==0?0x294d:0x2980,1,1,0))goto finish;
            }
            w.r.registers.si=w.r.registers.bx;w.r.registers.di=w.r.registers.dx;
        }
    }
    w.r.bp=pop(&w);out->next_ip=pop(&w);out->next_segment=pop(&w);out->status=0;
finish:
    out->current_sp=w.sp;out->returned=w.r;
}
