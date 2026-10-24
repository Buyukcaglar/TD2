#include "td2ega_view_fill.h"
#include <stddef.h>
typedef struct work {uint8_t *m;uint16_t ss,sp,cs;td2ega_state_registers r;td2ega_line_draw_service service;void *context;uint32_t limit;td2ega_view_fill_result *o;} work;
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
static int32_t sw(uint16_t v){return v<0x8000?v:(int32_t)v-65536;}
static void low(work *w,uint16_t v){w->r.registers.ax=(uint16_t)((w->r.registers.ax&0xff00)|(v&255));}
static int begin(work *w,uint16_t site){w->o->next_segment=w->cs;w->o->next_ip=site;if(w->o->work==w->limit){w->o->status=3;return 0;}return 1;}
static int effect(work *w,uint16_t site,uint16_t kind)
{
    td2ega_line_draw_request q={0};td2ega_line_draw_response r={0};
    if(!begin(w,site))return 0;
    q.kind=kind;q.site=site;q.segment=w->cs;q.stack_segment=w->ss;q.stack_sp=w->sp;q.port=w->r.registers.dx;q.value=kind==4?w->r.registers.ax:(uint8_t)w->r.registers.ax;q.address=kind==1?0:address(w->r.registers.es,w->r.registers.di);q.incoming=w->r;r.returned=w->r;r.value=q.value;
    if(w->service==NULL || !w->service(w->context,w->m,&q,&r)){w->o->status=4;return 0;}
    ++w->o->work;if(kind==1)++w->o->ports;else{if(kind==4)++w->o->word_writes;else ++w->o->byte_writes;++w->o->bus_writes;}return 1;
}
static int repeat(work *w,uint16_t site,uint16_t kind)
{
    uint16_t step=kind==4?2:1;
    while(w->r.registers.cx!=0){if(!effect(w,site,kind))return 0;w->r.registers.di=(uint16_t)(w->r.registers.di+(w->r.registers.direction?(uint16_t)(0-step):step));w->r.registers.cx=(uint16_t)(w->r.registers.cx-1);}return 1;
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
void td2ega_view_fill(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,uint16_t sp,const td2ega_state_registers *in,td2ega_line_draw_service service,void *context,uint32_t limit,td2ega_view_fill_result *out)
{
    work w;uint16_t hardware,v,product;uint8_t counter;int32_t relation;
    if(out==NULL)return;
    *out=(td2ega_view_fill_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1)return;
    w=(work){m,ss,sp,(uint16_t)(load+0x6c9),*in,service,context,limit,out};push(&w,BP);BP=w.sp;push(&w,DS);push(&w,SI);push(&w,DI);w.sp=sub(&w,w.sp,0xc);
    DX=word(&w,w.cs,0xaf4c);BX=word(&w,w.cs,0xaf4a);DX=sub(&w,DX,BX);BX=(uint16_t)(BX<<1);BX=add(&w,BX,word(&w,w.cs,0xaf44));CX=word(&w,w.cs,0xaf48);SI=word(&w,w.cs,0xaf46);CX=sub(&w,CX,SI);DI=word(&w,w.cs,BX);DI=add(&w,DI,SI);AX=word(&w,w.cs,0xaf4e);AX=sub(&w,AX,CX);local(&w,-0xa,DI);local(&w,-0xc,AX);local(&w,-0xe,DX);local(&w,-8,CX);
    v=word(&w,w.cs,0xaf3c);CF=(uint16_t)(v<0xa000);hardware=(uint16_t)(v==0xa000);if(hardware)goto device;
    v=word(&w,w.cs,0xaf4e);CF=(uint16_t)(CX<v);if(CX!=v)goto rows;
    AX=word(&w,w.cs,0xaf4e);product=(uint16_t)((uint32_t)AX*DX);AX=product;BX=AX;CF=(uint16_t)(AX&1);AX=(uint16_t)(AX>>1);local(&w,-8,AX);DX=stack(&w,6);SI=0;CF=0;
    do{
        if(!begin(&w,0x849f))goto done;
        ++out->work;++out->planes;AX=word(&w,w.cs,(uint16_t)(SI+0xaf3c));CF=0;
        if(AX!=0){ES=AX;DI=stack(&w,-0xa);AX=0;CF=0;if(DX&1)AX=0xffff;CX=stack(&w,-8);if(!repeat(&w,0x84ba,4))goto done;CF=0;if(BX&1){if(!effect(&w,0x84c2,3))goto done;DI=(uint16_t)(DI+(w.r.registers.direction?0xffff:1));}}
        v=(uint8_t)DX;CF=(uint16_t)(v&1);DX=(uint16_t)((DX&0xff00)|(v>>1));SI=add(&w,SI,2);CF=(uint16_t)(SI<8);
    }while(SI<8);
    goto cleanup;
rows:
    DX=stack(&w,6);AX=0xaf3c;local(&w,-0x10,AX);byteput(&w,ss,(uint16_t)(BP-0x12),4);
    do{
        if(!begin(&w,0x84e6))goto done;
        ++out->work;++out->planes;SI=stack(&w,-0x10);AX=word(&w,w.cs,SI);CF=0;
        if(AX!=0){ES=AX;AX=0;CF=0;if(stack(&w,6)&1)AX=0xffff;DI=stack(&w,-0xa);SI=stack(&w,-0xc);DX=stack(&w,-0xe);BX=stack(&w,-8);
            do{
                if(!begin(&w,0x8509))goto done;
                ++out->work;++out->rows;CX=BX;if(!repeat(&w,0x850b,3))goto done;DI=add(&w,DI,SI);relation=sw(DX)-1;DX=(uint16_t)(DX-1);
            }while(relation>0);
        }
        v=stack(&w,6);CF=(uint16_t)(v&1);local(&w,6,(uint16_t)(v>>1));v=add(&w,stack(&w,-0x10),2);local(&w,-0x10,v);counter=w.m[address(ss,(uint16_t)(BP-0x12))];relation=(counter<128?counter:(int32_t)counter-256)-1;byteput(&w,ss,(uint16_t)(BP-0x12),(uint8_t)(counter-1));
    }while(relation>0);
    goto cleanup;
device:
    DX=0x3ce;low(&w,5);if(!effect(&w,0x8525,1))goto done;DX=(uint16_t)(DX+1);low(&w,2);if(!effect(&w,0x8529,1))goto done;DX=0x3c4;low(&w,2);if(!effect(&w,0x852f,1))goto done;DX=(uint16_t)(DX+1);low(&w,0xf);if(!effect(&w,0x8533,1))goto done;ES=word(&w,w.cs,0xaf3c);CF=(uint16_t)(CX<0x28);
    if(CX==0x28){AX=CX;DX=stack(&w,-0xe);product=(uint16_t)((uint8_t)AX*(uint8_t)DX);AX=product;CF=(uint16_t)(product>255);CX=AX;DI=stack(&w,-0xa);AX=stack(&w,6);if(!repeat(&w,0x854d,3))goto done;}
    else{DI=stack(&w,-0xa);SI=stack(&w,-0xc);DX=stack(&w,-0xe);AX=stack(&w,6);
        do{
            if(!begin(&w,0x856d))goto done;
            ++out->work;++out->rows;CX=stack(&w,-8);if(!repeat(&w,0x8570,3))goto done;DI=add(&w,DI,SI);relation=sw(DX)-1;DX=(uint16_t)(DX-1);
        }while(relation>0);
    }
    DX=0x3ce;low(&w,5);if(!effect(&w,0x8554,1))goto done;DX=(uint16_t)(DX+1);low(&w,0);if(!effect(&w,0x8558,1))goto done;
cleanup:
    w.sp=add(&w,w.sp,0xc);DI=pop(&w);SI=pop(&w);DS=pop(&w);BP=pop(&w);if(w.sp>0xfffc){out->status=5;out->next_segment=w.cs;out->next_ip=hardware?0x8560:0x84d4;goto done;}out->next_ip=pop(&w);out->next_segment=pop(&w);out->status=0;
done:
    out->current_sp=w.sp;out->returned=w.r;
}
