#include "td2ega_long_arithmetic.h"
#include <stddef.h>
typedef struct work {uint8_t *m;uint16_t cs,ss,sp;uint32_t limit;td2ega_state_registers r;td2ega_long_arithmetic_result *o;} work;
static uint32_t address(uint16_t s,uint16_t o){return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(work *w,uint16_t s,uint16_t o){uint32_t a=address(s,o);return (uint16_t)(w->m[a]|((uint16_t)w->m[(a+1)&UINT32_C(0xfffff)]<<8));}
static void put(work *w,uint16_t s,uint16_t o,uint16_t v){uint32_t a=address(s,o);w->m[a]=(uint8_t)v;w->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++w->o->bus_writes;}
static void push(work *w,uint16_t v){w->sp=(uint16_t)(w->sp-2);put(w,w->ss,w->sp,v);}
static uint16_t pop(work *w){uint16_t v=word(w,w->ss,w->sp);w->sp=(uint16_t)(w->sp+2);return v;}
static uint16_t sub(work *w,uint16_t a,uint16_t b){w->r.carry=(uint16_t)(a<b);return (uint16_t)(a-b);}
static uint16_t sbb(work *w,uint16_t a,uint16_t b){uint32_t right=(uint32_t)b+w->r.carry;w->r.carry=(uint16_t)((uint32_t)a<right);return (uint16_t)(a-right);}
static void cmp(work *w,uint16_t a,uint16_t b){w->r.carry=(uint16_t)(a<b);}
static int step(work *w,uint16_t ip){if(w->o->steps==w->limit){w->o->status=3;w->o->next_segment=w->cs;w->o->next_ip=ip;return 0;}++w->o->steps;return 1;}
static int divide(work *w,uint16_t ip){uint32_t value=((uint32_t)w->r.registers.dx<<16)|w->r.registers.ax;uint16_t by=w->r.registers.cx;if(by==0 || value/by>65535){w->o->status=5;w->o->next_segment=w->cs;w->o->next_ip=ip;return 0;}w->r.registers.ax=(uint16_t)(value/by);w->r.registers.dx=(uint16_t)(value%by);return 1;}
static void negate_result(work *w){uint16_t low=w->r.registers.ax,high=w->r.registers.dx;w->r.registers.dx=(uint16_t)(0-high);w->r.registers.ax=(uint16_t)(0-low);w->r.carry=(uint16_t)(low!=0);w->r.registers.dx=sbb(w,w->r.registers.dx,0);}
static int multiply(work *w,uint16_t site)
{
    td2ega_sim_target_result result;uint16_t expected=(uint16_t)(w->sp+8),parent_bp=w->r.bp,low,high,other_low,other_high;uint32_t first,second,lowproduct;
    if(!step(w,site))return 0;
    ++w->o->calls;push(w,w->cs);push(w,(uint16_t)(site+5));push(w,w->r.bp);w->r.bp=w->sp;low=word(w,w->ss,(uint16_t)(w->r.bp+6));high=word(w,w->ss,(uint16_t)(w->r.bp+8));other_low=word(w,w->ss,(uint16_t)(w->r.bp+10));other_high=word(w,w->ss,(uint16_t)(w->r.bp+12));first=((uint32_t)high<<16)|low;second=((uint32_t)other_high<<16)|other_low;td2ega_long_multiply(first,second,w->r.registers.cx,&result);w->r.registers.ax=result.ax;w->r.registers.bx=result.bx;w->r.registers.cx=result.cx;w->r.registers.dx=result.dx;lowproduct=(uint32_t)low*other_low;w->r.carry=(uint16_t)((high|other_high)==0?(lowproduct>65535):((lowproduct>>16)+result.cx>65535));w->sp=w->r.bp;w->r.bp=pop(w);w->o->next_ip=pop(w);w->o->next_segment=pop(w);w->sp=(uint16_t)(w->sp+8);
    if(w->o->next_segment!=w->cs || w->o->next_ip!=(uint16_t)(site+5) || w->sp!=expected || w->r.bp!=parent_bp){w->o->status=1;return 0;}return 1;
}
#define AX w.r.registers.ax
#define BX w.r.registers.bx
#define CX w.r.registers.cx
#define DX w.r.registers.dx
#define SI w.r.registers.si
#define DI w.r.registers.di
#define BP w.r.bp
#define CF w.r.carry
#define ARG(n) word(&w,ss,(uint16_t)(BP+(n)))
#define STORE(n,v) put(&w,ss,(uint16_t)(BP+(n)),(v))
void td2ega_long_arithmetic(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,uint16_t sp,uint16_t entry,const td2ega_state_registers *in,uint32_t limit,td2ega_long_arithmetic_result *out)
{
    work w;uint16_t carry,old,v;int greater;
    if(out==NULL)return;
    *out=(td2ega_long_arithmetic_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || entry>1 || sp<32 || sp>UINT16_C(0xffe0) || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1)return;
    w=(work){m,(uint16_t)(load+0x13a8),ss,sp,limit,*in,out};push(&w,BP);BP=w.sp;if(entry==0){push(&w,DI);push(&w,SI);push(&w,BX);}else{push(&w,BX);push(&w,DI);}DI=0;CF=0;AX=ARG(8);CF=0;
    if(AX&0x8000){DI=(uint16_t)~DI;DX=ARG(6);AX=(uint16_t)(0-AX);old=DX;DX=(uint16_t)(0-DX);CF=(uint16_t)(old!=0);AX=sbb(&w,AX,0);STORE(8,AX);STORE(6,DX);}
    AX=ARG(12);CF=0;if(AX&0x8000){if(entry==0)DI=(uint16_t)~DI;DX=ARG(10);AX=(uint16_t)(0-AX);old=DX;DX=(uint16_t)(0-DX);CF=(uint16_t)(old!=0);AX=sbb(&w,AX,0);STORE(12,AX);STORE(10,DX);}CF=0;
    if(AX==0){
        CX=ARG(10);AX=ARG(8);DX=0;CF=0;if(!divide(&w,(uint16_t)(entry==0?0x2e88:0x2f5f)))goto finish;if(entry==0)BX=AX;AX=ARG(6);if(!divide(&w,(uint16_t)(entry==0?0x2e8f:0x2f64)))goto finish;
        if(entry==0){DX=BX;CF=0;if(DI!=0)negate_result(&w);}
        else{AX=DX;DX=0;CF=0;if(DI!=0)negate_result(&w);}
    }else{
        BX=AX;CX=ARG(10);DX=ARG(8);AX=ARG(6);
        do{
            if(!step(&w,(uint16_t)(entry==0?0x2ea1:0x2f7c)))goto finish;
            carry=(uint16_t)(BX&1);BX>>=1;CX=(uint16_t)((CX>>1)|(carry<<15));carry=(uint16_t)(DX&1);DX>>=1;AX=(uint16_t)((AX>>1)|(carry<<15));CF=0;
        }while(BX!=0);
        if(!divide(&w,(uint16_t)(entry==0?0x2ead:0x2f88)))goto finish;if(entry==0)SI=AX;DX=0;CF=0;push(&w,DX);push(&w,AX);push(&w,ARG(12));push(&w,ARG(10));if(!multiply(&w,(uint16_t)(entry==0?0x2ebb:0x2f94)))goto finish;
        v=ARG(8);cmp(&w,DX,v);greater=DX>v;if(DX==v){v=ARG(6);cmp(&w,AX,v);greater=AX>v;}
        if(entry==0){if(greater)SI=sub(&w,SI,1);DX=0;AX=SI;CF=0;if(DI!=0)negate_result(&w);}
        else{if(greater){AX=sub(&w,AX,ARG(10));DX=sbb(&w,DX,ARG(12));}AX=sub(&w,AX,ARG(6));DX=sbb(&w,DX,ARG(8));CF=0;if(DI==0)negate_result(&w);}
    }
    if(entry==0){BX=pop(&w);SI=pop(&w);DI=pop(&w);}else{DI=pop(&w);BX=pop(&w);}w.sp=BP;BP=pop(&w);out->next_ip=pop(&w);out->next_segment=pop(&w);w.sp=(uint16_t)(w.sp+8);out->status=0;
finish:
    out->current_sp=w.sp;out->returned=w.r;
}
