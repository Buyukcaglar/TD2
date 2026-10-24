#include "td2ega_motion_scan_bus.h"
#include <stddef.h>
typedef struct work {uint8_t *m;uint16_t load,ss,sp,cs,zf,valid;uint32_t limit;td2ega_state_registers r;td2ega_motion_scan_bus_result *o;} work;
static uint32_t address(uint16_t s,uint16_t o){return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(work *w,uint16_t s,uint16_t o){uint32_t a=address(s,o);return (uint16_t)(w->m[a]|((uint16_t)w->m[(a+1)&UINT32_C(0xfffff)]<<8));}
static uint16_t rd(work *w,uint16_t o){return word(w,w->r.registers.ds,o);}
static uint8_t byte(work *w,uint16_t o){return w->m[address(w->r.registers.ds,o)];}
static void put(work *w,uint16_t s,uint16_t o,uint16_t v){uint32_t a=address(s,o);w->m[a]=(uint8_t)v;w->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++w->o->bus_writes;}
static void wr(work *w,uint16_t o,uint16_t v){put(w,w->r.registers.ds,o,v);}
static void wb(work *w,uint16_t o,uint8_t v){w->m[address(w->r.registers.ds,o)]=v;++w->o->bus_writes;}
static void push(work *w,uint16_t v){w->sp=(uint16_t)(w->sp-2);put(w,w->ss,w->sp,v);}
static uint16_t pop(work *w){uint16_t v=word(w,w->ss,w->sp);w->sp=(uint16_t)(w->sp+2);return v;}
static uint16_t local(work *w,uint16_t n){return word(w,w->ss,(uint16_t)(w->r.bp-n));}
static void save(work *w,uint16_t n,uint16_t v){put(w,w->ss,(uint16_t)(w->r.bp-n),v);}
static int32_t sw(uint16_t v){return v<0x8000?v:(int32_t)v-65536;}
static int32_t sb(uint8_t v){return v<0x80?v:(int32_t)v-256;}
static void cmp(work *w,uint16_t a,uint16_t b){w->r.carry=(uint16_t)(a<b);w->zf=(uint16_t)(a==b);}
static uint16_t sub(work *w,uint16_t a,uint16_t b){uint16_t v=(uint16_t)(a-b);w->r.carry=(uint16_t)(a<b);w->zf=(uint16_t)(v==0);return v;}
static uint16_t add(work *w,uint16_t a,uint16_t b,uint16_t carry){uint32_t v=(uint32_t)a+b+carry;w->r.carry=(uint16_t)(v>65535);w->zf=(uint16_t)((uint16_t)v==0);return (uint16_t)v;}
static uint16_t sbb(work *w,uint16_t a,uint16_t b){uint32_t v=(uint32_t)b+w->r.carry;w->r.carry=(uint16_t)((uint32_t)a<v);a=(uint16_t)(a-v);w->zf=(uint16_t)(a==0);return a;}
static uint16_t shift(work *w,uint16_t v,unsigned count,int arithmetic){unsigned i;for(i=0;i<count;++i){w->r.carry=(uint16_t)(v&1);v=(uint16_t)((v>>1)|(arithmetic?(v&0x8000):0));}w->zf=(uint16_t)(v==0);return v;}
static void low(work *w,uint8_t v){w->r.registers.ax=(uint16_t)((w->r.registers.ax&0xff00)|v);}
static void high(work *w,uint8_t v){w->r.registers.ax=(uint16_t)((w->r.registers.ax&255)|((uint16_t)v<<8));}
static int far_return(work *w,uint16_t site,uint16_t clean)
{
    if(w->sp>UINT16_C(0xfffc)){w->o->status=5;w->o->next_segment=w->cs;w->o->next_ip=site;return 0;}
    w->o->next_ip=pop(w);w->o->next_segment=pop(w);w->sp=(uint16_t)(w->sp+clean);w->o->status=0;return 1;
}
static int multiply(work *w)
{
    td2ega_sim_target_result r;uint16_t lo,hi,other_lo,other_hi;uint32_t product;
    push(w,w->r.bp);w->r.bp=w->sp;
    hi=word(w,w->ss,(uint16_t)(w->r.bp+8));other_hi=word(w,w->ss,(uint16_t)(w->r.bp+12));
    other_lo=word(w,w->ss,(uint16_t)(w->r.bp+10));lo=word(w,w->ss,(uint16_t)(w->r.bp+6));
    td2ega_long_multiply(((uint32_t)hi<<16)|lo,((uint32_t)other_hi<<16)|other_lo,w->r.registers.cx,&r);
    w->r.registers.ax=r.ax;w->r.registers.bx=r.bx;w->r.registers.cx=r.cx;w->r.registers.dx=r.dx;
    product=(uint32_t)lo*other_lo;w->valid=(uint16_t)((hi|other_hi)!=0);
    w->r.carry=(uint16_t)(w->valid?((product>>16)+r.cx>65535):(product>65535));
    w->zf=w->valid?(uint16_t)(r.dx==0):0;w->sp=w->r.bp;w->r.bp=pop(w);
    return far_return(w,(uint16_t)(w->valid?0x2f19:0x2f00),8);
}
#define AX w.r.registers.ax
#define BX w.r.registers.bx
#define CX w.r.registers.cx
#define DX w.r.registers.dx
#define DI w.r.registers.di
#define BP w.r.bp
#define CF w.r.carry
void td2ega_motion_scan_bus(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,uint16_t sp,uint16_t entry,const td2ega_state_registers *in,uint32_t max_calls,td2ega_motion_scan_bus_result *out)
{
    work w;uint16_t v,expected_sp,parent_bp,parent_cs,target;uint32_t product;int32_t signed_product;uint8_t b;
    if(out==NULL)return;
    *out=(td2ega_motion_scan_bus_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || entry>2 || (entry==0?(sp<20 || sp>UINT16_C(0xffe0)):(entry==2 && sp==UINT16_C(0xffff))) || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1)return;
    w=(work){m,load,ss,sp,(uint16_t)(load+(entry==0?0x6b3:entry==1?0x13a8:0x6c9)),0,1,max_calls,*in,out};
    if(entry==1){if(!multiply(&w))goto done;goto root_done;}
    if(entry==2){
        CF=0;w.zf=(uint16_t)(AX==0);if(w.zf)goto near_return;
        CX=5;DI=0x33da;w.r.registers.direction=1;
        do{b=m[address(w.r.registers.es,DI)];cmp(&w,(uint8_t)AX,b);DI=(uint16_t)(DI-1);CX=(uint16_t)(CX-1);}while(CX!=0 && !w.zf);
        w.r.registers.direction=0;if(!w.zf)goto near_return;
        CF=(uint16_t)(CX>>15);CX=(uint16_t)(CX<<1);w.zf=(uint16_t)(CX==0);BX=CX;target=rd(&w,(uint16_t)(BX+0x33dc));
        if(target==0x44bf)wb(&w,0x5490,0xff);
        else if(target==0x44c5){b=byte(&w,0x90a8);cmp(&w,b,0);if(b==0){b=(uint8_t)(byte(&w,0x33af)^1);CF=0;w.zf=(uint16_t)(b==0);wb(&w,0x33af,b);}}
        else if(target==0x44d2){b=(uint8_t)(byte(&w,0x2f58)^1);CF=0;w.zf=(uint16_t)(b==0);wb(&w,0x2f58,b);}
        else if(target!=0x44be){out->status=4;out->unresolved_target=target;out->next_segment=w.cs;out->next_ip=0x44ba;goto done;}
near_return:
        out->next_ip=pop(&w);out->next_segment=w.cs;out->status=0;goto root_done;
    }
    push(&w,BP);BP=w.sp;w.sp=sub(&w,w.sp,4);CX=(uint16_t)((CX&0xff00)|9);v=shift(&w,rd(&w,0x335a),9,0);wr(&w,0x335a,v);
    high(&w,byte(&w,0x30e4));low(&w,0);CF=0;w.zf=1;CX=(uint16_t)((CX&0xff00)|5);AX=shift(&w,AX,5,1);AX=sub(&w,0,AX);CX=rd(&w,0x2f4a);CX=shift(&w,CX,1,1);CX=shift(&w,CX,1,1);AX=sub(&w,AX,CX);save(&w,2,AX);
    low(&w,byte(&w,0x336d));AX=(uint16_t)(sb((uint8_t)AX)&0xffff);CX=120;signed_product=sw(AX)*sw(CX);AX=(uint16_t)signed_product;DX=(uint16_t)((uint32_t)signed_product>>16);CF=(uint16_t)(signed_product!=sw(AX));save(&w,4,AX);
    b=byte(&w,0x336d);cmp(&w,b,0);if(b!=0)goto correction;
    b=byte(&w,0x336e);cmp(&w,b,0);if(b==0)goto correction;
    v=rd(&w,0x3322);cmp(&w,v,0);if(v!=0)goto correction;
    v=rd(&w,0x2f46);cmp(&w,v,0);AX=rd(&w,0x2f46);if(sw(v)<0)AX=sub(&w,0,AX);cmp(&w,AX,0x600);if(sw(AX)>=0x600)goto correction;
    v=rd(&w,0x2f4a);cmp(&w,v,0);AX=rd(&w,0x2f4a);if(sw(v)<0)AX=sub(&w,0,AX);cmp(&w,AX,0xc00);if(sw(AX)>=0xc00)goto correction;
    AX=rd(&w,0x2f4a);CX=(uint16_t)((CX&0xff00)|3);AX=shift(&w,AX,3,1);v=sub(&w,rd(&w,0x2f4a),AX);wr(&w,0x2f4a,v);AX=rd(&w,0x2f46);AX=shift(&w,AX,1,1);AX=shift(&w,AX,1,1);v=sub(&w,rd(&w,0x2f46),AX);wr(&w,0x2f46,v);AX=rd(&w,0x2f46);if(v&0x8000)AX=sub(&w,0,AX);cmp(&w,AX,0x100);if(sw(AX)<0x100)wr(&w,0x2f46,0);AX=sub(&w,AX,AX);goto epilogue;
correction:
    b=byte(&w,0x336e);cmp(&w,b,0);if(b!=0){b=byte(&w,0x336d);cmp(&w,b,0);if(b==0){v=rd(&w,0x2f46);cmp(&w,v,0);if(v!=0){AX=rd(&w,0x2f46);CX=(uint16_t)((CX&0xff00)|7);AX=shift(&w,AX,7,1);product=(uint32_t)AX*rd(&w,0x335a);AX=(uint16_t)product;DX=(uint16_t)(product>>16);CF=(uint16_t)(DX!=0);v=sub(&w,local(&w,4),AX);save(&w,4,v);}}}
    b=byte(&w,0x336d);cmp(&w,b,0);if(sb(b)>0){AX=rd(&w,0x2f46);v=local(&w,2);cmp(&w,v,AX);if(sw(v)>sw(AX))goto adjustment;}
    b=byte(&w,0x336d);cmp(&w,b,0);if(sb(b)>=0)goto factor;AX=rd(&w,0x2f46);v=local(&w,2);cmp(&w,v,AX);if(sw(v)>=sw(AX))goto factor;
adjustment:
    AX=sub(&w,AX,local(&w,2));CX=(uint16_t)((CX&0xff00)|3);AX=shift(&w,AX,3,1);v=sub(&w,local(&w,4),AX);save(&w,4,v);
factor:
    AX=rd(&w,0x30e6);CX=(uint16_t)((CX&0xff00)|10);AX=shift(&w,AX,10,0);DX=sub(&w,DX,DX);AX=sub(&w,AX,0x100);DX=sbb(&w,DX,DX);AX=sub(&w,0,AX);DX=add(&w,DX,0,CF);DX=sub(&w,0,DX);push(&w,DX);push(&w,AX);AX=local(&w,4);DX=(AX&0x8000)?0xffff:0;push(&w,DX);push(&w,AX);
    if(out->calls==w.limit){out->status=3;out->next_segment=w.cs;out->next_ip=0x114;goto done;}
    ++out->calls;expected_sp=(uint16_t)(w.sp+8);parent_bp=BP;parent_cs=w.cs;push(&w,parent_cs);push(&w,0x119);w.cs=(uint16_t)(load+0x13a8);if(!multiply(&w))goto done;
    if(out->next_segment!=parent_cs || out->next_ip!=0x119 || w.sp!=expected_sp || BP!=parent_bp){out->status=1;goto done;}w.cs=parent_cs;w.valid=1;
    low(&w,(uint8_t)(AX>>8));high(&w,(uint8_t)DX);DX=(uint16_t)((DX&0xff00)|(DX>>8));DX=(uint16_t)(DX&255);CF=0;w.zf=1;save(&w,4,AX);cmp(&w,AX,0xa00);if(sw(AX)>0xa00)save(&w,4,0xa00);v=local(&w,4);cmp(&w,v,0xf600);if(sw(v)<-0xa00)save(&w,4,0xf600);AX=local(&w,4);v=add(&w,rd(&w,0x2f46),AX,0);wr(&w,0x2f46,v);v=rd(&w,0x2f46);cmp(&w,v,0xe80);if(sw(v)>0xe80)wr(&w,0x2f46,0xe80);v=rd(&w,0x2f46);cmp(&w,v,0xf180);if(sw(v)<-0xe80)wr(&w,0x2f46,0xf180);
epilogue:
    w.sp=BP;BP=pop(&w);if(!far_return(&w,0x160,0))goto done;
root_done:
    out->zero_flag=w.zf;out->flags_valid=w.valid;
done:
    out->current_sp=w.sp;out->returned=w.r;
}
