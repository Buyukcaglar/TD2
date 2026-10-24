#include "td2ega_record_projection.h"
#include <stddef.h>
typedef struct work {uint8_t *m;uint16_t ss,sp;td2ega_state_registers r;td2ega_record_projection_result *o;} work;
static uint32_t address(uint16_t s,uint16_t o){return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(work *w,uint16_t s,uint16_t o){uint32_t a=address(s,o);return (uint16_t)(w->m[a]|((uint16_t)w->m[(a+1)&UINT32_C(0xfffff)]<<8));}
static uint16_t rd(work *w,uint16_t o){return word(w,w->r.registers.ds,o);}
static uint8_t byte(work *w,uint16_t o){return w->m[address(w->r.registers.ds,o)];}
static void put(work *w,uint16_t o,uint16_t v,unsigned n){uint32_t a=address(w->r.registers.ds,o);w->m[a]=(uint8_t)v;if(n==2)w->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++w->o->bus_writes;}
static int32_t sw(uint16_t v){return v&0x8000?(int32_t)v-65536:(int32_t)v;}
static uint16_t sub(work *w,uint16_t a,uint16_t b){w->r.carry=(uint16_t)(a<b);return (uint16_t)(a-b);}
static int32_t sbb(work *w,uint16_t a,uint16_t b,uint16_t *v){uint16_t borrow=w->r.carry;uint32_t rhs=(uint32_t)b+borrow;int32_t d=sw(a)-sw(b)-borrow;w->r.carry=(uint16_t)((uint32_t)a<rhs);*v=(uint16_t)((uint32_t)a-rhs);return d;}
static uint16_t add(work *w,uint16_t a,uint16_t b){uint32_t v=(uint32_t)a+b;w->r.carry=(uint16_t)(v>65535);return (uint16_t)v;}
static uint16_t pop(work *w){uint16_t v=word(w,w->ss,w->sp);w->sp=(uint16_t)(w->sp+2);return v;}
#define AX w.r.registers.ax
#define BX w.r.registers.bx
#define CX w.r.registers.cx
#define DX w.r.registers.dx
#define SI w.r.registers.si
#define DI w.r.registers.di
#define BP w.r.bp
#define CF w.r.carry
void td2ega_record_projection(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,uint16_t sp,const td2ega_state_registers *in,uint32_t limit,td2ega_record_projection_result *out)
{
    work w;unsigned i,which;uint16_t v,base,count;int32_t d;
    if(out==NULL)return;
    *out=(td2ega_record_projection_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || sp>UINT16_C(0xffe0) || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1)return;
    w=(work){m,ss,sp,*in,out};AX=0;CF=0;BX=w.r.registers.ds;w.r.registers.es=BX;DI=0x1308;CX=17;w.r.registers.direction=0;
    for(i=0;i<17;++i){put(&w,DI,AX,2);DI=(uint16_t)(DI+2);--CX;}
    AX=320;put(&w,0x12d2,AX,2);put(&w,0x12d0,AX,2);put(&w,0x12d6,AX,2);AX=92;put(&w,0x12ce,AX,2);put(&w,0x12d4,AX,2);AX=(uint16_t)((AX&0xff00)|byte(&w,0x5491));put(&w,0x133b,AX,1);put(&w,0x133c,AX,1);put(&w,0x133e,AX,1);put(&w,0x133f,AX,1);AX=rd(&w,0x533e);put(&w,0x1306,AX,2);AX=rd(&w,0x2f48);put(&w,0x12c8,AX,2);AX=rd(&w,0x52ca);AX=(uint16_t)(AX+1);put(&w,0x12ca,AX,2);AX=rd(&w,0x52c8);put(&w,0x12cc,AX,2);AX=rd(&w,0x52cc);CF=(uint16_t)(AX!=0);AX=(uint16_t)(0-AX);put(&w,0x12c4,AX,2);AX=(uint16_t)((AX&0xff00)|byte(&w,0x3372));put(&w,0x9ac,AX,1);AX=(uint16_t)((AX&0xff00)|byte(&w,0x3373));put(&w,0x9ad,AX,1);AX=(uint16_t)((AX&0xff00)|byte(&w,0x3375));put(&w,0x9ae,AX,1);AX=rd(&w,0x9b0);put(&w,0x12c6,AX,2);BX=rd(&w,0x12cc);CX=rd(&w,0x12ca);SI=0;CF=0;DI=SI;
    for(which=0;which<2;++which){
        if(which){SI=0;CF=0;}base=(uint16_t)(which?0x39a3:0x3813);count=(uint16_t)(which?0x5356:0x5354);
        do{
            if(out->records==limit){out->status=3;out->next_segment=(uint16_t)(load+0x6c9);out->next_ip=(uint16_t)(which?0x2b4:0x279);goto done;}++out->records;
            BP=rd(&w,(uint16_t)(base+SI));AX=rd(&w,(uint16_t)(base+SI+4));DX=rd(&w,(uint16_t)(base+SI+2));AX=sub(&w,AX,BX);d=sbb(&w,DX,CX,&v);DX=v;if(d<0)DX=add(&w,DX,rd(&w,0x380d));CF=(uint16_t)(DX<60);if(DX<=60){CF=(uint16_t)(DX>>15);DX=(uint16_t)(DX<<1);put(&w,(uint16_t)(DI+0x73c),DX,2);put(&w,(uint16_t)(DI+0x73e),BP,2);AX=rd(&w,(uint16_t)(base+SI+6));put(&w,(uint16_t)(DI+0x740),AX,2);DI=add(&w,DI,8);}SI=add(&w,SI,8);v=rd(&w,count);CF=(uint16_t)(SI<v);
        }while(SI<v);
    }
    put(&w,0x804,DI,2);AX=rd(&w,0x52d0);DX=rd(&w,0x52d2);AX=sub(&w,AX,BX);d=sbb(&w,DX,CX,&v);DX=v;if(d<0)DX=add(&w,DX,rd(&w,0x380d));CF=(uint16_t)(DX>>15);DX=(uint16_t)(DX<<1);put(&w,0x806,DX,2);AX=rd(&w,0x52d4);put(&w,0x808,AX,2);AX=rd(&w,0x52d8);DX=rd(&w,0x52da);AX=sub(&w,AX,BX);d=sbb(&w,DX,CX,&v);DX=v;if(d<0)DX=add(&w,DX,rd(&w,0x380d));CF=(uint16_t)(DX>>15);DX=(uint16_t)(DX<<1);put(&w,0x80a,DX,2);AX=rd(&w,0x52dc);put(&w,0x80c,AX,2);AX=(uint16_t)((AX&0xff00)|byte(&w,0x33b8));put(&w,0x1340,AX,1);AX=(uint16_t)((AX&0xff00)|byte(&w,0x33b7));put(&w,0x1341,AX,1);out->next_ip=pop(&w);out->next_segment=pop(&w);out->status=0;
done:
    out->current_sp=w.sp;out->returned=w.r;
}
