#include "td2ega_control_bus.h"
#include <stddef.h>
typedef struct work {uint8_t *m;uint16_t cs,ss,sp;td2ega_state_registers r;td2ega_control_bus_result *o;} work;
static uint32_t address(uint16_t s,uint16_t o){return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(work *w,uint16_t s,uint16_t o){uint32_t a=address(s,o);return (uint16_t)(w->m[a]|((uint16_t)w->m[(a+1)&UINT32_C(0xfffff)]<<8));}
static uint16_t rd(work *w,uint16_t o){return word(w,w->r.registers.ds,o);}
static uint8_t byte(work *w,uint16_t o){return w->m[address(w->r.registers.ds,o)];}
static void put(work *w,uint16_t s,uint16_t o,uint16_t v,unsigned n){uint32_t a=address(s,o);w->m[a]=(uint8_t)v;if(n==2)w->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++w->o->bus_writes;}
static void wr(work *w,uint16_t o,uint16_t v){put(w,w->r.registers.ds,o,v,2);}
static void wb(work *w,uint16_t o,uint16_t v){put(w,w->r.registers.ds,o,v,1);}
static void push(work *w,uint16_t v){w->sp=(uint16_t)(w->sp-2);put(w,w->ss,w->sp,v,2);}
static uint16_t pop(work *w){uint16_t v=word(w,w->ss,w->sp);w->sp=(uint16_t)(w->sp+2);return v;}
static int32_t sw(uint16_t v){return v&0x8000?(int32_t)v-65536:(int32_t)v;}
static uint16_t add(work *w,uint16_t a,uint16_t b){uint32_t v=(uint32_t)a+b;w->r.carry=(uint16_t)(v>65535);return (uint16_t)v;}
static uint16_t sub(work *w,uint16_t a,uint16_t b){w->r.carry=(uint16_t)(a<b);return (uint16_t)(a-b);}
static void cmp(work *w,uint16_t a,uint16_t b){w->r.carry=(uint16_t)(a<b);}
static void product(work *w){uint32_t wide;w->r.carry=0;if(byte(w,0x2f56)!=0){w->r.registers.cx=rd(w,0x332c);wb(w,0x2f5b,1);w->r.registers.ax=rd(w,0x3328);w->r.registers.dx=rd(w,0x52ce);wide=(uint32_t)w->r.registers.ax*w->r.registers.dx;w->r.registers.ax=(uint16_t)wide;w->r.registers.dx=(uint16_t)(wide>>16);cmp(w,w->r.registers.dx,800);if(w->r.registers.dx<800)w->r.registers.dx=800;wr(w,0x332c,w->r.registers.dx);}}
#define AX w.r.registers.ax
#define BX w.r.registers.bx
#define CX w.r.registers.cx
#define DX w.r.registers.dx
#define CF w.r.carry
void td2ega_control_bus(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,uint16_t sp,uint16_t entry,const td2ega_state_registers *in,uint32_t limit,td2ega_control_bus_result *out)
{
    work w;uint8_t b;uint16_t expected,ret;uint32_t wide;
    if(out==NULL)return;
    *out=(td2ega_control_bus_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || sp<18 || sp>UINT16_C(0xffe0) || entry>4 || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1)return;
    w=(work){m,(uint16_t)(load+0x6c9),ss,sp,*in,out};
    if(entry==0){AX=rd(&w,0x332c);CF=0;if(byte(&w,0x2f56)!=0)goto reduce;CF=0;b=byte(&w,0x336c);if(b==0 || b>=0x80)goto reduce;wb(&w,0x2f5b,1);AX=add(&w,AX,600);wr(&w,0x332c,AX);goto returned;
reduce:
        DX=AX;AX=sub(&w,AX,200);cmp(&w,AX,800);if(sw(AX)<=800)AX=800;cmp(&w,AX,DX);if(AX!=DX){wr(&w,0x332c,AX);wb(&w,0x2f5b,1);}goto returned;
    }
    if(entry==3){product(&w);goto returned;}
    if(entry==1)DX=1600;
    if(entry==2){AX=1600;b=byte(&w,0x336c);cmp(&w,b,255);if(b==255)goto decelerate;AX=rd(&w,0x52ce);BX=(uint16_t)((AX>>8)>>2);CX=byte(&w,(uint16_t)(BX+0x324a));CF=0;if(DX==0){wide=(uint32_t)CX*2;CX=(uint16_t)wide;CF=(uint16_t)(wide>65535);}DX=sub(&w,DX,CX);if(DX==0)goto returned;CF=0;if(DX&0x8000){DX=(uint16_t)(0-DX);CF=(uint16_t)(DX!=0);AX=sub(&w,AX,DX);if(CF)goto returned;}else AX=add(&w,AX,DX);wr(&w,0x52ce,AX);wb(&w,0x2f5b,1);goto returned;}
decelerate:
    AX=rd(&w,0x52ce);BX=AX;AX=sub(&w,AX,DX);if(CF){AX=0;CF=0;}BX=sub(&w,BX,AX);if(BX==0)goto returned;wr(&w,0x52ce,AX);if(limit==0){out->status=3;out->next_segment=w.cs;out->next_ip=0x460e;goto finish;}++out->calls;expected=w.sp;push(&w,0x4611);product(&w);ret=pop(&w);if(ret!=0x4611 || w.sp!=expected){out->status=1;out->next_segment=w.cs;out->next_ip=ret;goto finish;}
returned:
    out->next_ip=pop(&w);out->next_segment=w.cs;out->status=0;
finish:
    out->current_sp=w.sp;out->returned=w.r;
}
