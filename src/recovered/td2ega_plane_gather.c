#include "td2ega_plane_gather.h"
#include <stddef.h>
typedef struct work {uint8_t *m;uint16_t ss,sp,cs;td2ega_state_registers r;td2ega_line_draw_service service;void *context;uint32_t limit;td2ega_plane_gather_result *o;} work;
static uint32_t address(uint16_t s,uint16_t o){return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(work *w,uint16_t s,uint16_t o){uint32_t a=address(s,o);return (uint16_t)(w->m[a]|((uint16_t)w->m[(a+1)&UINT32_C(0xfffff)]<<8));}
static void put(work *w,uint16_t s,uint16_t o,uint16_t v){uint32_t a=address(s,o);w->m[a]=(uint8_t)v;w->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++w->o->bus_writes;}
static void push(work *w,uint16_t v){w->sp=(uint16_t)(w->sp-2);put(w,w->ss,w->sp,v);}
static uint16_t pop(work *w){uint16_t v=word(w,w->ss,w->sp);w->sp=(uint16_t)(w->sp+2);return v;}
static int32_t sw(uint16_t v){return v<0x8000?v:(int32_t)v-65536;}
static int32_t sb(uint8_t v){return v<0x80?v:(int32_t)v-256;}
static void byteput(work *w,uint16_t s,uint16_t o,uint8_t v){w->m[address(s,o)]=v;++w->o->bus_writes;}
static uint16_t sar3(uint16_t v){return (uint16_t)((v>>3)|((v&0x8000)?0xe000:0));}
static uint16_t add(work *w,uint16_t a,uint16_t b){uint32_t n=(uint32_t)a+b;w->r.carry=(uint16_t)(n>65535);return (uint16_t)n;}
static uint16_t sub(work *w,uint16_t a,uint16_t b){w->r.carry=(uint16_t)(a<b);return (uint16_t)(a-b);}
static uint16_t stack(work *w,int delta){return word(w,w->ss,(uint16_t)(w->r.bp+delta));}
static void local(work *w,int delta,uint16_t v){put(w,w->ss,(uint16_t)(w->r.bp+delta),v);}
static int begin(work *w,uint16_t site){w->o->next_segment=w->cs;w->o->next_ip=site;if(w->o->work==w->limit){w->o->status=3;return 0;}return 1;}
static int effect(work *w,uint16_t site,uint16_t kind)
{
    td2ega_line_draw_request q={0};td2ega_line_draw_response r={0};
    if(!begin(w,site))return 0;
    q.kind=kind;q.site=site;q.segment=w->cs;q.stack_segment=w->ss;q.stack_sp=w->sp;q.port=w->r.registers.dx;q.value=kind==1?(uint8_t)w->r.registers.ax:w->m[address(w->r.registers.ds,w->r.registers.si)];q.incoming=w->r;
    if(kind==7){q.arguments[0]=w->r.registers.ds;q.arguments[1]=w->r.registers.si;q.arguments[2]=w->r.registers.es;q.arguments[3]=w->r.registers.di;q.address=address(w->r.registers.es,w->r.registers.di);}
    r.returned=w->r;r.value=q.value;
    if(w->service==NULL || !w->service(w->context,w->m,&q,&r)){w->o->status=4;return 0;}
    ++w->o->work;if(kind==1)++w->o->ports;else{++w->o->copies;++w->o->bus_writes;}return 1;
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
static void low(work *w,uint16_t v){w->r.registers.ax=(uint16_t)((w->r.registers.ax&0xff00)|(v&255));}
void td2ega_plane_gather(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,uint16_t sp,const td2ega_state_registers *in,td2ega_line_draw_service service,void *context,uint32_t limit,td2ega_plane_gather_result *out)
{
    work w;uint16_t v;uint8_t counter;int32_t relation;
    if(out==NULL)return;
    *out=(td2ega_plane_gather_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1)return;
    w=(work){m,ss,sp,(uint16_t)(load+0x6c9),*in,service,context,limit,out};push(&w,BP);BP=w.sp;push(&w,DS);push(&w,SI);push(&w,DI);w.sp=sub(&w,w.sp,0x12);
    DS=stack(&w,8);DI=stack(&w,6);AX=stack(&w,0xa);local(&w,-8,AX);put(&w,DS,(uint16_t)(DI+8),AX);AX=stack(&w,0xc);local(&w,-0xa,AX);put(&w,DS,(uint16_t)(DI+0xa),AX);
    AX=word(&w,DS,DI);local(&w,-0xc,AX);AX=word(&w,DS,(uint16_t)(DI+2));local(&w,-0xe,AX);AX=stack(&w,-8);CF=(uint16_t)((AX>>2)&1);AX=sar3(AX);local(&w,-8,AX);
    BX=stack(&w,-0xa);BX=(uint16_t)(BX<<1);BX=add(&w,BX,word(&w,w.cs,0xaf44));AX=word(&w,w.cs,BX);AX=add(&w,AX,stack(&w,-8));local(&w,-0x10,AX);AX=word(&w,w.cs,0xaf4e);AX=sub(&w,AX,stack(&w,-0xc));local(&w,-0x12,AX);
    AX=(uint16_t)(DI+0xc);local(&w,-0x16,AX);low(&w,w.m[address(DS,(uint16_t)(DI+0xf))]);AX=(uint16_t)(((uint8_t)AX)>>4);CF=0;local(&w,-0x18,AX);DI=(uint16_t)(DI+0x10);ES=stack(&w,8);AX=0xa000;DS=AX;w.r.registers.direction=0;byteput(&w,ss,(uint16_t)(BP-0x14),4);
    do{
        if(!begin(&w,0xacdc))goto done;
        ++out->work;++out->planes;BX=stack(&w,-0x16);BX=word(&w,ES,BX);BX=(uint16_t)(BX&0xf);CF=0;
        if(BX!=0){CX=(uint16_t)((CX&0xff00)|w.m[address(w.cs,(uint16_t)(BX+0xac0c))]);DX=0x3ce;low(&w,4);if(!effect(&w,0xacf1,1))goto done;DX=(uint16_t)(DX+1);low(&w,CX);if(!effect(&w,0xacf5,1))goto done;SI=stack(&w,-0x10);DX=stack(&w,-0xe);
            do{
                if(!begin(&w,0xacfc))goto done;
                ++out->work;++out->rows;CX=stack(&w,-0xc);
                while(CX!=0){if(!effect(&w,0xacff,7))goto done;SI=(uint16_t)(SI+1);DI=(uint16_t)(DI+1);CX=(uint16_t)(CX-1);}
                SI=add(&w,SI,stack(&w,-0x12));relation=sw(DX)-1;DX=(uint16_t)(DX-1);
            }while(relation>0);
        }
        v=(uint16_t)(stack(&w,-0x16)+1);local(&w,-0x16,v);DI=add(&w,DI,stack(&w,-0x18));counter=w.m[address(ss,(uint16_t)(BP-0x14))];relation=sb(counter)-1;byteput(&w,ss,(uint16_t)(BP-0x14),(uint8_t)(counter-1));
    }while(relation>0);
    w.sp=add(&w,w.sp,0x12);DI=pop(&w);SI=pop(&w);DS=pop(&w);BP=pop(&w);
    if(w.sp>0xfffc){out->status=5;out->next_segment=w.cs;out->next_ip=0xad19;goto done;}
    out->next_ip=pop(&w);out->next_segment=pop(&w);out->status=0;
done:
    out->current_sp=w.sp;out->returned=w.r;
}
