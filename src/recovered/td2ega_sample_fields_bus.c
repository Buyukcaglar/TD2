#include "td2ega_sample_fields_bus.h"
#include <stddef.h>
typedef struct work {uint8_t *m;uint16_t ds,zf;td2ega_state_registers r;td2ega_sample_fields_bus_result *o;} work;
static uint32_t address(uint16_t s,uint16_t o){return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(work *w,uint16_t s,uint16_t o){uint32_t a=address(s,o);return (uint16_t)(w->m[a]|((uint16_t)w->m[(a+1)&UINT32_C(0xfffff)]<<8));}
static uint16_t rd(work *w,uint16_t o){return word(w,w->ds,o);}
static uint8_t byte(work *w,uint16_t o){return w->m[address(w->ds,o)];}
static void wr(work *w,uint16_t o,uint16_t v){uint32_t a=address(w->ds,o);w->m[a]=(uint8_t)v;w->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++w->o->bus_writes;}
static void wb(work *w,uint16_t o,uint8_t v){w->m[address(w->ds,o)]=v;++w->o->bus_writes;}
static int32_t sw(uint16_t v){return v<0x8000?v:(int32_t)v-65536;}
static int32_t sb(uint8_t v){return v<0x80?v:(int32_t)v-256;}
static void cmp(work *w,uint16_t a,uint16_t b){w->r.carry=(uint16_t)(a<b);w->zf=(uint16_t)(a==b);}
static uint16_t add(work *w,uint16_t a,uint16_t b){uint32_t v=(uint32_t)a+b;w->r.carry=(uint16_t)(v>65535);w->zf=(uint16_t)((uint16_t)v==0);return (uint16_t)v;}
static uint16_t sub(work *w,uint16_t a,uint16_t b){uint16_t v=(uint16_t)(a-b);w->r.carry=(uint16_t)(a<b);w->zf=(uint16_t)(v==0);return v;}
#define AX w.r.registers.ax
#define BX w.r.registers.bx
#define CX w.r.registers.cx
#define CF w.r.carry
void td2ega_sample_fields_bus(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,uint16_t sp,uint16_t entry,const td2ega_state_registers *in,td2ega_sample_fields_bus_result *out)
{
    work w;uint16_t v;uint8_t b,old;unsigned i;
    if(out==NULL)return;
    *out=(td2ega_sample_fields_bus_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || entry>1 || sp==UINT16_C(0xffff) || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1)return;
    w=(work){m,in->registers.ds,0,*in,out};
    if(entry==1){
        b=byte(&w,0x33b3);BX=(uint16_t)((BX&0xff00)|b);AX=rd(&w,0x332c);v=rd(&w,0x23aa);cmp(&w,AX,v);
        if(AX<v){old=b;b=(uint8_t)(b-1);BX=(uint16_t)((BX&0xff00)|b);w.zf=(uint16_t)(b==0);if(sb(old)-1>=0)wb(&w,0x33b3,b);goto done;}
        v=rd(&w,0x23a8);cmp(&w,AX,v);if(AX>v)goto limit;
        b=(uint8_t)(b+1);BX=(uint16_t)((BX&0xff00)|b);w.zf=(uint16_t)(b==0);cmp(&w,b,30);if(b>=30)goto limit;wb(&w,0x33b3,b);goto done;
limit:
        v=rd(&w,0x23a8);cmp(&w,AX,v);if(AX>=v)AX=rd(&w,0x23a8);wr(&w,0x332c,AX);wb(&w,0x5490,3);goto done;
    }
    b=(uint8_t)(byte(&w,0x336a)+1);wb(&w,0x336a,b);BX=(uint16_t)(b&31);BX=(uint16_t)(BX<<1);CF=0;w.zf=(uint16_t)(BX==0);AX=rd(&w,(uint16_t)(BX+0x32ae));wr(&w,0x5fde,AX);BX=rd(&w,0x332a);CX=rd(&w,0x332c);cmp(&w,BX,CX);
    if(sw(BX)>sw(CX)){BX=sub(&w,BX,96);cmp(&w,BX,CX);if(sw(BX)<=sw(CX))BX=CX;}else{BX=add(&w,BX,96);cmp(&w,BX,CX);if(sw(BX)>=sw(CX))BX=CX;}wr(&w,0x332a,BX);
    for(i=0;i<5;++i){CF=(uint16_t)(BX&1);BX=(uint16_t)(BX>>1);w.zf=(uint16_t)(BX==0);}BX=(uint16_t)(BX&0xfffe);CF=0;w.zf=(uint16_t)(BX==0);BX=rd(&w,(uint16_t)(BX+0x30e8));wr(&w,0x5fd8,BX);
    b=byte(&w,0x3374);cmp(&w,b,0);
    if(b==0){
        b=byte(&w,0x33bc);cmp(&w,b,0);if(b!=0){wr(&w,0x5fda,0x384);goto done;}
        b=byte(&w,0x3368);cmp(&w,b,1);if(b==1){b=byte(&w,0x33b2);AX=(uint16_t)((AX&0xff00)|b);CF=0;w.zf=(uint16_t)(b==0);if(b!=0){b=(uint8_t)(b-1);AX=(uint16_t)((AX&0xff00)|b);w.zf=(uint16_t)(b==0);wb(&w,0x33b2,b);wr(&w,0x5fda,0x474);}else wr(&w,0x5fda,0xffff);}
        b=byte(&w,0x336f);cmp(&w,b,0);if(b!=0)wr(&w,0x5fda,0x8e8);goto done;
    }
    CF=0;w.zf=(uint16_t)((rd(&w,0x942e)&8)==0);
    if(w.zf){CF=0;w.zf=(uint16_t)((rd(&w,0x3346)&4)==0);wr(&w,0x5fda,w.zf?0x7d0:0x5dc);goto done;}
    AX=rd(&w,0x3350);b=byte(&w,0x335c);cmp(&w,b,0);
    if(sb(b)<0){AX=(uint16_t)(AX-1);w.zf=(uint16_t)(AX==0);AX=(uint16_t)(AX-1);w.zf=(uint16_t)(AX==0);cmp(&w,AX,0x5dc);if(sw(AX)<=1500)wb(&w,0x335c,1);}
    else{AX=(uint16_t)(AX+1);w.zf=(uint16_t)(AX==0);AX=(uint16_t)(AX+1);w.zf=(uint16_t)(AX==0);cmp(&w,AX,0x708);if(sw(AX)>=1800)wb(&w,0x335c,0xff);}
    wr(&w,0x3350,AX);wr(&w,0x5fda,AX);
done:
    out->next_segment=(uint16_t)(load+0x6c9);out->next_ip=word(&w,ss,sp);out->current_sp=(uint16_t)(sp+2);out->returned=w.r;out->zero_flag=w.zf;out->flags_valid=1;out->status=0;
}
