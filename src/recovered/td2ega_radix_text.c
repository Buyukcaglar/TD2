#include "td2ega_radix_text.h"
#include <stddef.h>
typedef struct work {uint8_t *m;uint16_t cs,ss,sp;uint32_t limit;td2ega_state_registers r;td2ega_radix_text_result *o;} work;
static uint32_t address(uint16_t s,uint16_t o){return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(work *w,uint16_t s,uint16_t o){uint32_t a=address(s,o);return (uint16_t)(w->m[a]|((uint16_t)w->m[(a+1)&UINT32_C(0xfffff)]<<8));}
static void put(work *w,uint16_t s,uint16_t o,uint16_t v,unsigned n){uint32_t a=address(s,o);w->m[a]=(uint8_t)v;if(n==2)w->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++w->o->bus_writes;}
static void push(work *w,uint16_t v){w->sp=(uint16_t)(w->sp-2);put(w,w->ss,w->sp,v,2);}
static uint16_t pop(work *w){uint16_t v=word(w,w->ss,w->sp);w->sp=(uint16_t)(w->sp+2);return v;}
static int step(work *w,uint16_t ip){if(w->o->iterations==w->limit){w->o->status=3;w->o->next_segment=w->cs;w->o->next_ip=ip;return 0;}++w->o->iterations;return 1;}
static int divide(work *w,uint16_t ip){uint32_t value=((uint32_t)w->r.registers.dx<<16)|w->r.registers.ax;uint16_t by=w->r.registers.cx;if(by==0 || value/by>65535){w->o->status=5;w->o->next_segment=w->cs;w->o->next_ip=ip;return 0;}w->r.registers.ax=(uint16_t)(value/by);w->r.registers.dx=(uint16_t)(value%by);return 1;}
#define AX w.r.registers.ax
#define BX w.r.registers.bx
#define CX w.r.registers.cx
#define DX w.r.registers.dx
#define SI w.r.registers.si
#define DI w.r.registers.di
#define BP w.r.bp
#define DS w.r.registers.ds
#define ES w.r.registers.es
#define CF w.r.carry
void td2ega_radix_text(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,uint16_t sp,uint16_t entry,const td2ega_state_registers *in,uint32_t limit,td2ega_radix_text_result *out)
{
    work w;uint16_t swap;uint32_t wide;uint8_t v,old;
    if(out==NULL)return;
    *out=(td2ega_radix_text_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || entry>1 || sp<32 || sp>UINT16_C(0xffe0) || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1)return;
    w=(work){m,(uint16_t)(load+0x13a8),ss,sp,limit,*in,out};push(&w,BP);BP=w.sp;push(&w,SI);push(&w,DI);BX=(uint16_t)((BX&0xff00)|(entry==0?1:0));
    if(entry==0){CX=word(&w,ss,(uint16_t)(BP+10));AX=word(&w,ss,(uint16_t)(BP+6));DX=0;CF=(uint16_t)(CX<10);if(CX==10)DX=(AX&0x8000)?0xffff:0;DI=word(&w,ss,(uint16_t)(BP+8));}
    else{CX=word(&w,ss,(uint16_t)(BP+12));AX=word(&w,ss,(uint16_t)(BP+6));DX=word(&w,ss,(uint16_t)(BP+8));DI=word(&w,ss,(uint16_t)(BP+10));}
    push(&w,DI);push(&w,DS);ES=pop(&w);w.r.registers.direction=0;swap=AX;AX=BX;BX=swap;CF=0;
    if((uint8_t)AX!=0){CF=(uint16_t)(CX<10);if(CX==10){CF=0;if(DX&0x8000){AX=(uint16_t)((AX&0xff00)|0x2d);put(&w,ES,DI,AX,1);DI=(uint16_t)(DI+1);CF=(uint16_t)(BX!=0);BX=(uint16_t)(0-BX);wide=(uint32_t)DX+CF;DX=(uint16_t)wide;CF=(uint16_t)(DX!=0);DX=(uint16_t)(0-DX);}}}
    SI=DI;
    for(;;){
        if(!step(&w,0x2bda))goto finish;
        swap=DX;DX=AX;AX=swap;DX=0;CF=0;
        if(AX!=0 && !divide(&w,0x2be1))goto finish;
        swap=BX;BX=AX;AX=swap;if(!divide(&w,0x2be4))goto finish;swap=DX;DX=AX;AX=swap;swap=BX;BX=DX;DX=swap;v=(uint8_t)((uint8_t)AX+0x30);AX=(uint16_t)((AX&0xff00)|v);CF=(uint16_t)(v<0x39);if(v>0x39){old=v;v=(uint8_t)(v+0x27);CF=(uint16_t)(v<old);AX=(uint16_t)((AX&0xff00)|v);}put(&w,ES,DI,AX,1);DI=(uint16_t)(DI+1);AX=(uint16_t)(DX|BX);CF=0;if(AX==0)break;
    }
    put(&w,DS,DI,AX,1);
    do{
        if(!step(&w,0x2bfa))goto finish;
        DI=(uint16_t)(DI-1);v=w.m[address(DS,SI)];AX=(uint16_t)((AX&0xff00)|v);SI=(uint16_t)(SI+1);old=w.m[address(DS,DI)];put(&w,DS,DI,AX,1);AX=(uint16_t)((AX&0xff00)|old);put(&w,DS,(uint16_t)(SI-1),AX,1);AX=(uint16_t)(SI+1);CF=(uint16_t)(AX<DI);
    }while(CF);
    AX=pop(&w);DI=pop(&w);SI=pop(&w);w.sp=BP;BP=pop(&w);out->next_ip=pop(&w);out->next_segment=pop(&w);out->status=0;
finish:
    out->current_sp=w.sp;out->returned=w.r;
}
