#include "td2ega_plane_shift_strip.h"
#include <stddef.h>
typedef struct work {uint8_t *m;uint16_t ss,sp,cs;td2ega_state_registers r;td2ega_line_draw_service service;void *context;uint32_t limit;td2ega_plane_shift_strip_result *o;} work;
static uint32_t address(uint16_t s,uint16_t o){return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(work *w,uint16_t s,uint16_t o){uint32_t a=address(s,o);return (uint16_t)(w->m[a]|((uint16_t)w->m[(a+1)&UINT32_C(0xfffff)]<<8));}
static void put(work *w,uint16_t s,uint16_t o,uint16_t v){uint32_t a=address(s,o);w->m[a]=(uint8_t)v;w->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++w->o->bus_writes;}
static void byteput(work *w,uint16_t s,uint16_t o,uint8_t v){w->m[address(s,o)]=v;++w->o->bus_writes;}
static void push(work *w,uint16_t v){w->sp=(uint16_t)(w->sp-2);put(w,w->ss,w->sp,v);}
static uint16_t pop(work *w){uint16_t v=word(w,w->ss,w->sp);w->sp=(uint16_t)(w->sp+2);return v;}
static uint16_t stack(work *w,int delta){return word(w,w->ss,(uint16_t)(w->r.bp+delta));}
static void local(work *w,int delta,uint16_t v){put(w,w->ss,(uint16_t)(w->r.bp+delta),v);}
static uint16_t add(work *w,uint16_t a,uint16_t b){uint32_t v=(uint32_t)a+b;w->r.carry=(uint16_t)(v>65535);return (uint16_t)v;}
static uint16_t sub(work *w,uint16_t a,uint16_t b){w->r.carry=(uint16_t)(a<b);return (uint16_t)(a-b);}
static int32_t signed_word(uint16_t v){return v<0x8000?v:(int32_t)v-65536;}
static void low(work *w,uint16_t v){w->r.registers.ax=(uint16_t)((w->r.registers.ax&0xff00)|(v&255));}
static void high(work *w,uint16_t v){w->r.registers.ax=(uint16_t)((w->r.registers.ax&255)|((v&255)<<8));}
static int begin(work *w,uint16_t site){w->o->next_segment=w->cs;w->o->next_ip=site;if(w->o->work==w->limit){w->o->status=3;return 0;}return 1;}
static int effect(work *w,uint16_t site,uint16_t kind,uint16_t *value)
{
    td2ega_line_draw_request q={0};td2ega_line_draw_response r={0};
    if(!begin(w,site))return 0;
    q.kind=kind;q.site=site;q.segment=w->cs;q.stack_segment=w->ss;q.stack_sp=w->sp;q.port=w->r.registers.dx;q.value=kind==2?0:kind==7?w->m[address(w->r.registers.ds,w->r.registers.si)]:(uint8_t)w->r.registers.ax;q.incoming=w->r;
    if(kind!=1)q.address=address(w->r.registers.es,w->r.registers.di);
    if(kind==7){q.arguments[0]=w->r.registers.ds;q.arguments[1]=w->r.registers.si;q.arguments[2]=w->r.registers.es;q.arguments[3]=w->r.registers.di;}
    r.returned=w->r;r.value=q.value;
    if(w->service==NULL || !w->service(w->context,w->m,&q,&r)){w->o->status=4;return 0;}
    ++w->o->work;if(kind==1)++w->o->ports;else if(kind==2){++w->o->reads;*value=(uint8_t)r.value;}else{if(kind==7)++w->o->copies;else ++w->o->writes;++w->o->bus_writes;}return 1;
}
#define AX w.r.registers.ax
#define BX w.r.registers.bx
#define CX w.r.registers.cx
#define DX w.r.registers.dx
#define SI w.r.registers.si
#define DI w.r.registers.di
#define DS w.r.registers.ds
#define ES w.r.registers.es
#define BP w.r.bp
#define CF w.r.carry
void td2ega_plane_shift_strip(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,uint16_t sp,const td2ega_state_registers *in,td2ega_line_draw_service service,void *context,uint32_t limit,td2ega_plane_shift_strip_result *out)
{
    work w;uint16_t v;uint8_t counter;int32_t relation;
    if(out==NULL)return;
    *out=(td2ega_plane_shift_strip_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1)return;
    w=(work){m,ss,sp,(uint16_t)(load+0x6c9),*in,service,context,limit,out};push(&w,BP);BP=w.sp;w.sp=sub(&w,w.sp,8);push(&w,SI);push(&w,DI);push(&w,DS);w.r.registers.direction=0;AX=0xa000;ES=AX;DS=AX;
    DX=0x3ce;low(&w,5);if(!effect(&w,0xae78,1,NULL))goto done;DX=(uint16_t)(DX+1);low(&w,1);if(!effect(&w,0xae7c,1,NULL))goto done;DX=0x3c4;low(&w,2);if(!effect(&w,0xae82,1,NULL))goto done;DX=(uint16_t)(DX+1);low(&w,0xf);if(!effect(&w,0xae86,1,NULL))goto done;
    AX=stack(&w,6);CF=(uint16_t)((AX>>2)&1);AX=(uint16_t)(AX>>3);local(&w,-2,AX);BX=stack(&w,8);BX=(uint16_t)(BX<<1);BX=add(&w,BX,word(&w,w.cs,0xaf44));DI=word(&w,w.cs,BX);DI=add(&w,DI,stack(&w,-2));AX=stack(&w,0xe);SI=DI;SI=add(&w,SI,AX);AX=sub(&w,AX,stack(&w,0xa));BX=AX;DX=stack(&w,0xc);
    do{
        if(!begin(&w,0xaeb2))goto done;
        ++out->work;++out->rows;CX=stack(&w,0xa);
        while(CX!=0){if(!effect(&w,0xaeb5,7,NULL))goto done;SI=(uint16_t)(SI+1);DI=(uint16_t)(DI+1);CX=(uint16_t)(CX-1);}
        SI=add(&w,SI,BX);DI=add(&w,DI,BX);relation=signed_word(DX)-1;DX=(uint16_t)(DX-1);
    }while(relation>0);
    DX=0x3ce;low(&w,5);if(!effect(&w,0xaec3,1,NULL))goto done;DX=(uint16_t)(DX+1);low(&w,0);if(!effect(&w,0xaec7,1,NULL))goto done;AX=stack(&w,0x12);CF=0;if(AX==0)goto root;
    DS=AX;SI=stack(&w,0x10);AX=word(&w,DS,(uint16_t)(SI+2));BX=word(&w,DS,SI);AX=(uint16_t)((uint8_t)AX*(uint8_t)BX);BX=(uint16_t)(w.m[address(DS,(uint16_t)(SI+0xf))]>>4);AX=add(&w,AX,BX);AX=sub(&w,AX,stack(&w,0xa));local(&w,-4,AX);
    AX=stack(&w,0x14);BX=stack(&w,0xa);AX=(uint16_t)((uint8_t)AX*(uint8_t)BX);BX=SI;SI=add(&w,SI,0x10);SI=add(&w,SI,AX);BX=add(&w,BX,0xc);local(&w,-6,DI);byteput(&w,ss,(uint16_t)(BP-8),4);
    do{
        if(!begin(&w,0xaf09))goto done;
        ++out->work;++out->planes;CX=(uint16_t)((CX&0xff00)|(w.m[address(DS,BX)]&0xf));CF=0;if((uint8_t)CX==0)goto root;DX=0x3c4;low(&w,2);if(!effect(&w,0xaf15,1,NULL))goto done;DX=(uint16_t)(DX+1);low(&w,CX);if(!effect(&w,0xaf19,1,NULL))goto done;DI=stack(&w,-6);CX=stack(&w,0xa);
        do{
            if(!begin(&w,0xaf20))goto done;
            ++out->work;++out->loads;low(&w,w.m[address(DS,SI)]);SI=(uint16_t)(SI+1);if(!effect(&w,0xaf21,2,&v))goto done;high(&w,v);if(!effect(&w,0xaf24,3,NULL))goto done;DI=(uint16_t)(DI+1);CX=(uint16_t)(CX-1);
        }while(CX!=0);
        SI=add(&w,SI,stack(&w,-4));BX=(uint16_t)(BX+1);counter=w.m[address(ss,(uint16_t)(BP-8))];relation=(counter<128?counter:(int32_t)counter-256)-1;byteput(&w,ss,(uint16_t)(BP-8),(uint8_t)(counter-1));
    }while(relation>0);
root:
    DS=pop(&w);DI=pop(&w);SI=pop(&w);w.sp=BP;BP=pop(&w);if(w.sp>0xfffc){out->status=5;out->next_segment=w.cs;out->next_ip=0xaf39;goto done;}out->next_ip=pop(&w);out->next_segment=pop(&w);out->status=0;
done:
    out->current_sp=w.sp;out->returned=w.r;
}
