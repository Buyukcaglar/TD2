#include "td2ega_sample_adjust.h"
#include <stddef.h>
typedef struct work {uint8_t *m;uint32_t bytes;uint16_t load,ss,sp,cs,zf;td2ega_state_registers r;const td2ega_sample_adjust_limits *limits;td2ega_sample_adjust_result *o;} work;
static uint32_t address(uint16_t s,uint16_t o){return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(work *w,uint16_t s,uint16_t o){uint32_t a=address(s,o);return (uint16_t)(w->m[a]|((uint16_t)w->m[(a+1)&UINT32_C(0xfffff)]<<8));}
static uint16_t rd(work *w,uint16_t o){return word(w,w->r.registers.ds,o);}
static uint8_t byte(work *w,uint16_t o){return w->m[address(w->r.registers.ds,o)];}
static void put(work *w,uint16_t s,uint16_t o,uint16_t v){uint32_t a=address(s,o);w->m[a]=(uint8_t)v;w->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++w->o->bus_writes;}
static void wr(work *w,uint16_t o,uint16_t v){put(w,w->r.registers.ds,o,v);}
static void wb(work *w,uint16_t o,uint8_t v){w->m[address(w->r.registers.ds,o)]=v;++w->o->bus_writes;}
static void push(work *w,uint16_t v){w->sp=(uint16_t)(w->sp-2);put(w,w->ss,w->sp,v);}
static uint16_t pop(work *w){uint16_t v=word(w,w->ss,w->sp);w->sp=(uint16_t)(w->sp+2);return v;}
static uint16_t add(work *w,uint16_t a,uint16_t b){uint32_t v=(uint32_t)a+b;w->r.carry=(uint16_t)(v>65535);return (uint16_t)v;}
static void cmp(work *w,uint16_t a,uint16_t b){w->r.carry=(uint16_t)(a<b);w->zf=(uint16_t)(a==b);}
static int32_t sw(uint16_t v){return v<0x8000?v:(int32_t)v-65536;}
static void low(work *w,uint16_t v){w->r.registers.ax=(uint16_t)((w->r.registers.ax&0xff00)|(v&255));}
static int begin_call(work *w,uint16_t site){w->o->next_segment=w->cs;w->o->next_ip=site;if(w->o->calls==w->limits->calls){w->o->status=3;return 0;}++w->o->calls;return 1;}
static int control(work *w)
{
    td2ega_control_bus_result h;uint16_t expected=w->sp;
    if(!begin_call(w,0x4a31))return 0;
    push(w,0x4a34);td2ega_control_bus(w->m,w->bytes,w->load,w->ss,w->sp,4,&w->r,w->limits->control_calls,&h);w->r=h.returned;w->sp=h.current_sp;w->o->control_calls+=h.calls;w->o->bus_writes+=h.bus_writes;w->o->next_segment=h.next_segment;w->o->next_ip=h.next_ip;
    if(h.status!=0){w->o->status=h.status;return 0;}
    if(h.next_segment!=w->cs || h.next_ip!=0x4a34 || w->sp!=expected){w->o->status=1;return 0;}return 1;
}
static int returned(work *w,uint16_t ip,uint16_t expected)
{
    uint16_t next=pop(w),segment=pop(w);w->o->next_segment=segment;w->o->next_ip=next;
    if(next!=ip || segment!=w->cs || w->sp!=expected){w->o->status=1;return 0;}return 1;
}
static int setter(work *w)
{
    uint16_t expected=w->sp;
    if(!begin_call(w,0x4a39))return 0;
    push(w,w->cs);push(w,0x4a3e);push(w,w->r.bp);w->r.bp=w->sp;w->r.registers.interrupts_enabled=0;w->r.registers.ax=word(w,w->ss,(uint16_t)(w->r.bp+8));wr(w,0x5eee,w->r.registers.ax);w->r.registers.ax=word(w,w->ss,(uint16_t)(w->r.bp+6));wr(w,0x5ef0,w->r.registers.ax);wb(w,0x5efc,1);w->r.registers.interrupts_enabled=1;w->r.bp=pop(w);return returned(w,0x4a3e,expected);
}
static int ring(work *w)
{
    TD2EgaByteRing state={0};uint16_t expected=w->sp,index;
    if(!begin_call(w,0x4a41))return 0;
    push(w,w->cs);push(w,0x4a46);push(w,w->r.registers.si);wr(w,0x66e6,(uint16_t)(rd(w,0x66e6)-1));w->r.registers.si=(uint16_t)(rd(w,0x66e6)&0xff);w->r.carry=0;index=w->r.registers.si;
    state.cursor=(uint16_t)(rd(w,0x66e6)+1);state.bytes[index]=byte(w,(uint16_t)(0x66e8+index));w->r.registers.ax=td2ega_byte_ring_step(&state);wb(w,(uint16_t)(0x66e8+index),(uint8_t)w->r.registers.ax);w->r.carry=0;w->r.registers.si=pop(w);return returned(w,0x4a46,expected);
}
#define AX w.r.registers.ax
#define BX w.r.registers.bx
#define DX w.r.registers.dx
#define CF w.r.carry
void td2ega_sample_adjust(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,uint16_t sp,const td2ega_state_registers *in,const td2ega_sample_adjust_limits *limits,td2ega_sample_adjust_result *out)
{
    work w;uint16_t v;uint8_t b,al;
    if(out==NULL)return;
    *out=(td2ega_sample_adjust_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || limits==NULL || sp<20 || sp>UINT16_C(0xffe0) || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1)return;
    w=(work){m,bytes,load,ss,sp,(uint16_t)(load+0x6c9),0,*in,limits,out};DX=0x640;if(!control(&w))goto done;AX=0x5494;push(&w,w.r.registers.ds);push(&w,AX);if(!setter(&w))goto done;w.sp=add(&w,w.sp,4);if(!ring(&w))goto done;
    al=(uint8_t)AX;CF=0;w.zf=(uint16_t)(al==0);if(al==0 || al>=0x80)goto root;v=rd(&w,0x8a9a);cmp(&w,v,0);if(v!=0)goto root;b=(uint8_t)(byte(&w,0x337b)+1);wb(&w,0x337b,b);cmp(&w,b,4);if(b>4){wb(&w,0x5490,8);goto root;}
    cmp(&w,al,25);if(al<=25){low(&w,byte(&w,0x33c6));low(&w,(uint8_t)((uint8_t)AX+25));wb(&w,0x33c6,(uint8_t)(byte(&w,0x33c6)+(uint8_t)AX));low(&w,(uint8_t)((uint8_t)AX<<1));cmp(&w,(uint8_t)AX,byte(&w,0x2418));if(!CF)wb(&w,0x5490,5);goto root;}
    cmp(&w,al,50);if(al<=50){AX=rd(&w,0x33c8);AX=add(&w,AX,1000);wr(&w,0x33c8,(uint16_t)(rd(&w,0x33c8)+AX));AX=(uint16_t)(AX<<1);cmp(&w,AX,rd(&w,0x23b2));if(!CF)wb(&w,0x5490,6);goto root;}
    cmp(&w,al,75);if(al<=75){AX=(uint16_t)(rd(&w,0x33ca)-75);wr(&w,0x33ca,AX);cmp(&w,AX,125);if(CF)wb(&w,0x5490,7);goto root;}
    cmp(&w,al,100);if(al<=100){BX=rd(&w,0x33cc);CF=0;w.zf=(uint16_t)(BX==0);if(sw(BX)>=0 && (al&1)){BX=add(&w,BX,37);wr(&w,0x33cc,BX);cmp(&w,BX,62);if(sw(BX)>=62)wb(&w,0x5490,7);}
        else{BX=(uint16_t)(BX-37);wr(&w,0x33cc,BX);cmp(&w,BX,0xffc2);if(sw(BX)<=-62)wb(&w,0x5490,7);}goto root;}
    b=byte(&w,0x90a8);cmp(&w,b,0);if(b!=0)goto root;BX=byte(&w,0x2f56);CF=0;w.zf=1;wb(&w,(uint16_t)(BX+0x33bf),1);
root:
    out->next_ip=pop(&w);out->next_segment=w.cs;out->status=0;out->zero_flag=w.zf;out->flags_valid=1;
done:
    out->current_sp=w.sp;out->returned=w.r;
}
