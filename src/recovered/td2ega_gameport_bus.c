#include "td2ega_gameport_bus.h"
#include <stddef.h>
typedef struct work {uint8_t *m;uint16_t cs,ss,sp,zf;uint32_t limit;td2ega_state_registers r;td2ega_gameport_bus_service service;void *context;td2ega_gameport_bus_result *o;} work;
static uint32_t address(uint16_t s,uint16_t o){return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(work *w,uint16_t s,uint16_t o){uint32_t a=address(s,o);return (uint16_t)(w->m[a]|((uint16_t)w->m[(a+1)&UINT32_C(0xfffff)]<<8));}
static uint16_t rd(work *w,uint16_t o){return word(w,w->r.registers.ds,o);}
static uint8_t byte(work *w,uint16_t o){return w->m[address(w->r.registers.ds,o)];}
static void put(work *w,uint16_t s,uint16_t o,uint16_t v){uint32_t a=address(s,o);w->m[a]=(uint8_t)v;w->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++w->o->bus_writes;}
static void wr(work *w,uint16_t o,uint16_t v){put(w,w->r.registers.ds,o,v);}
static void wb(work *w,uint16_t o,uint8_t v){w->m[address(w->r.registers.ds,o)]=v;++w->o->bus_writes;}
static void push(work *w,uint16_t v){w->sp=(uint16_t)(w->sp-2);put(w,w->ss,w->sp,v);}
static uint16_t pop(work *w){uint16_t v=word(w,w->ss,w->sp);w->sp=(uint16_t)(w->sp+2);return v;}
static int32_t sw(uint16_t v){return v<0x8000?v:(int32_t)v-65536;}
static void cmp(work *w,uint16_t a,uint16_t b){w->r.carry=(uint16_t)(a<b);w->zf=(uint16_t)(a==b);}
static uint16_t sub(work *w,uint16_t a,uint16_t b){uint16_t v=(uint16_t)(a-b);w->r.carry=(uint16_t)(a<b);w->zf=(uint16_t)(v==0);return v;}
static uint16_t add(work *w,uint16_t a,uint16_t b){uint32_t v=(uint32_t)a+b;w->r.carry=(uint16_t)(v>65535);w->zf=(uint16_t)((uint16_t)v==0);return (uint16_t)v;}
static uint16_t logic(work *w,uint16_t v){w->r.carry=0;w->zf=(uint16_t)(v==0);return v;}
static uint16_t shr(work *w,uint16_t v){w->r.carry=(uint16_t)(v&1);v>>=1;w->zf=(uint16_t)(v==0);return v;}
static void low(work *w,uint8_t v){w->r.registers.ax=(uint16_t)((w->r.registers.ax&0xff00)|v);}
static int transfer(work *w,uint16_t ip,uint16_t operation)
{
    td2ega_gameport_bus_request request;uint8_t value=0;
    w->o->next_segment=w->cs;w->o->next_ip=ip;
    if(operation==0 && w->o->reads==w->limit){w->o->status=3;return 0;}
    request=(td2ega_gameport_bus_request){operation,w->r.registers.dx,(uint8_t)w->r.registers.ax,w->cs,ip,w->ss,w->sp,w->zf,w->r};
    if(w->service==NULL || !w->service(w->context,&request,&value)){w->o->status=4;return 0;}
    ++w->o->transfers;if(operation==0){++w->o->reads;low(w,value);}return 1;
}
static void calibrate(work *w,uint16_t base,int y)
{
    td2ega_music_registers *r=&w->r.registers;uint16_t v,old;int positive;
    r->ax=rd(w,(uint16_t)(y?0x627e:0x627c));v=rd(w,base);cmp(w,r->ax,v);
    if(y?r->ax<v:sw(r->ax)<sw(v)){wr(w,base,r->ax);r->bx=rd(w,(uint16_t)(base+2));goto recalculate;}
    v=rd(w,(uint16_t)(base+2));cmp(w,r->ax,v);if(sw(r->ax)<=sw(v))goto reset;
    v=(uint16_t)(rd(w,(uint16_t)(base+6))-1);w->zf=(uint16_t)(v==0);wr(w,(uint16_t)(base+6),v);
    if(v==0){r->bx=rd(w,(uint16_t)(base+4));wr(w,(uint16_t)(base+2),r->bx);goto recalculate;}
    v=rd(w,(uint16_t)(base+4));cmp(w,r->ax,v);if(sw(r->ax)<sw(v))wr(w,(uint16_t)(base+4),r->ax);goto threshold;
recalculate:
    old=r->bx;v=rd(w,base);positive=sw(old)>sw(v);r->bx=sub(w,old,v);
    if(positive){r->dx=logic(w,0);r->ax=0x4000;r->ax=(uint16_t)(UINT16_C(0x4000)/r->bx);r->dx=(uint16_t)(UINT16_C(0x4000)%r->bx);wr(w,(uint16_t)(y?0x629c:0x629a),r->ax);}
    r->ax=r->bx;r->dx=0x201;r->ax=shr(w,r->ax);r->bx=r->ax;r->bx=shr(w,r->bx);r->ax=add(w,r->ax,rd(w,base));r->ax=add(w,r->ax,r->bx);wr(w,(uint16_t)(base+10),r->ax);r->ax=sub(w,r->ax,r->bx);r->ax=sub(w,r->ax,r->bx);wr(w,(uint16_t)(base+8),r->ax);r->ax=rd(w,(uint16_t)(y?0x627e:0x627c));
reset:
    wr(w,(uint16_t)(base+6),8);wr(w,(uint16_t)(base+4),0x4e20);
threshold:
    v=rd(w,(uint16_t)(base+8));cmp(w,r->ax,v);
    if(y?r->ax<v:sw(r->ax)<sw(v)){v=logic(w,(uint16_t)(byte(w,0x6281)|(y?1:8)));wb(w,0x6281,(uint8_t)v);}
    else{v=rd(w,(uint16_t)(base+10));cmp(w,r->ax,v);if(!(y?r->ax<v:sw(r->ax)<sw(v))){v=logic(w,(uint16_t)(byte(w,0x6281)|(y?2:4)));wb(w,0x6281,(uint8_t)v);}}
}
#define AX w.r.registers.ax
#define BX w.r.registers.bx
#define CX w.r.registers.cx
#define DX w.r.registers.dx
#define BP w.r.bp
#define CF w.r.carry
void td2ega_gameport_bus(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,uint16_t sp,uint16_t entry,uint16_t incoming_zero,const td2ega_state_registers *in,uint32_t max_reads,td2ega_gameport_bus_service service,void *context,td2ega_gameport_bus_result *out)
{
    work w;uint16_t ret_site=0,v;uint8_t b,active;
    if(out==NULL)return;
    *out=(td2ega_gameport_bus_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || entry>2 || incoming_zero>1 || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1)return;
    w=(work){m,(uint16_t)(load+0x6c9),ss,sp,incoming_zero,max_reads,*in,service,context,out};
    if(entry==1){wb(&w,0x6cfc,1);wr(&w,0x6282,0x50);wr(&w,0x6284,0);wr(&w,0x628e,0x50);wr(&w,0x6290,0);ret_site=0x6827;goto root;}
    if(entry==2){push(&w,BP);BP=w.sp;BX=word(&w,ss,(uint16_t)(BP+6));BX=logic(&w,(uint16_t)(BX&15));low(&w,byte(&w,(uint16_t)(BX+0x629e)));AX=(uint16_t)(AX&255);CF=0;w.zf=1;BP=pop(&w);ret_site=0x6838;goto root;}
    b=byte(&w,0x6cfc);cmp(&w,b,0);if(b==0)goto disabled;v=logic(&w,(uint16_t)(byte(&w,0x6cfe)&1));if(v==0)goto disabled;
    wb(&w,0x6281,0);DX=0x201;if(!transfer(&w,0x669f,0))goto done;wb(&w,0x6280,(uint8_t)AX);BX=(uint16_t)((BX&0xff00)|3);wr(&w,0x627c,0x50);wr(&w,0x627e,0x50);CX=0;w.r.registers.interrupts_enabled=0;if(!transfer(&w,0x66b5,1))goto done;
    for(;;){
        if(!transfer(&w,0x66ba,0))goto done;b=(uint8_t)logic(&w,(uint16_t)((uint8_t)AX&(uint8_t)BX));low(&w,b);active=(uint8_t)logic(&w,(uint16_t)(b^(uint8_t)BX));low(&w,active);
        if(active==0){CX=(uint16_t)(CX+1);w.zf=(uint16_t)(CX==0);cmp(&w,CX,4000);if(sw(CX)<4000)continue;break;}
        v=logic(&w,(uint16_t)(active&1));if(v!=0){wr(&w,0x627c,CX);b=(uint8_t)logic(&w,(uint16_t)((uint8_t)BX&2));BX=(uint16_t)((BX&0xff00)|b);if(b==0)break;}
        v=logic(&w,(uint16_t)(active&2));if(v==0)continue;wr(&w,0x627e,CX);b=(uint8_t)logic(&w,(uint16_t)((uint8_t)BX&1));BX=(uint16_t)((BX&0xff00)|b);if(b==0)break;
    }
    w.r.registers.interrupts_enabled=1;calibrate(&w,0x6282,0);calibrate(&w,0x628e,1);if(!transfer(&w,0x67f0,0))goto done;
    b=(uint8_t)logic(&w,(uint16_t)((uint8_t)AX&byte(&w,0x6280)));low(&w,b);b=(uint8_t)logic(&w,(uint16_t)(b&0x30));low(&w,b);b=(uint8_t)logic(&w,(uint16_t)(b^0x30));low(&w,b);v=logic(&w,(uint16_t)(byte(&w,0x6281)|b));wb(&w,0x6281,(uint8_t)v);low(&w,byte(&w,0x6281));AX=(uint16_t)(AX&255);CF=0;w.zf=1;ret_site=0x6802;goto root;
disabled:
    AX=logic(&w,0);ret_site=0x668f;
root:
    if(w.sp>UINT16_C(0xfffc)){out->status=5;out->next_segment=w.cs;out->next_ip=ret_site;goto done;}
    out->next_ip=pop(&w);out->next_segment=pop(&w);out->status=0;out->zero_flag=w.zf;out->flags_valid=1;
done:
    out->current_sp=w.sp;out->returned=w.r;
}
