#include "td2ega_plane_fill.h"
#include <stddef.h>
typedef struct work {uint8_t *m;uint16_t ss,sp,cs;td2ega_state_registers r;td2ega_line_draw_service service;void *context;uint32_t limit;td2ega_plane_fill_result *o;} work;
static uint32_t address(uint16_t s,uint16_t o){return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(work *w,uint16_t s,uint16_t o){uint32_t a=address(s,o);return (uint16_t)(w->m[a]|((uint16_t)w->m[(a+1)&UINT32_C(0xfffff)]<<8));}
static void push(work *w,uint16_t v){uint32_t a;w->sp=(uint16_t)(w->sp-2);a=address(w->ss,w->sp);w->m[a]=(uint8_t)v;w->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++w->o->bus_writes;}
static uint16_t pop(work *w){uint16_t v=word(w,w->ss,w->sp);w->sp=(uint16_t)(w->sp+2);return v;}
static int valid(const td2ega_state_registers *r){return r->carry<=1 && r->registers.interrupts_enabled<=1 && r->registers.direction<=1;}
static int effect(work *w,uint16_t site,uint16_t kind)
{
    td2ega_line_draw_request q={0};td2ega_line_draw_response response={0};w->o->next_segment=w->cs;w->o->next_ip=site;
    if(w->o->events==w->limit){w->o->status=3;return 0;}
    q.kind=kind;q.site=site;q.segment=w->cs;q.stack_segment=w->ss;q.stack_sp=w->sp;q.port=w->r.registers.dx;q.value=(uint8_t)w->r.registers.ax;q.address=kind==3?address(w->r.registers.es,w->r.registers.di):0;q.incoming=w->r;response.returned=w->r;response.value=q.value;
    if(w->service==NULL || !w->service(w->context,w->m,&q,&response)){w->o->status=4;return 0;}++w->o->events;
    if(kind==3){++w->o->bytes;++w->o->bus_writes;}return 1;
}
#define AX w.r.registers.ax
#define CX w.r.registers.cx
#define DX w.r.registers.dx
#define DI w.r.registers.di
#define BP w.r.bp
#define CF w.r.carry
static void low(work *w,uint16_t value){w->r.registers.ax=(uint16_t)((w->r.registers.ax&0xff00)|(value&255));}
void td2ega_plane_fill(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,uint16_t sp,const td2ega_state_registers *in,td2ega_line_draw_service callback,void *context,uint32_t events,td2ega_plane_fill_result *out)
{
    work w;
    if(out==NULL)return;
    *out=(td2ega_plane_fill_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || !valid(in))return;
    w=(work){m,ss,sp,(uint16_t)(load+0x6c9),*in,callback,context,events,out};push(&w,BP);BP=w.sp;push(&w,DI);AX=0xa000;w.r.registers.es=AX;DX=0x3ce;low(&w,5);if(!effect(&w,0x8418,1))goto done;DX=(uint16_t)(DX+1);low(&w,2);if(!effect(&w,0x841c,1))goto done;DX=0x3c4;low(&w,2);if(!effect(&w,0x8422,1))goto done;DX=(uint16_t)(DX+1);low(&w,0xf);if(!effect(&w,0x8426,1))goto done;
    AX=word(&w,ss,(uint16_t)(BP+6));DI=0;CF=0;CX=0x1f40;
    while(CX!=0){if(!effect(&w,0x842f,3))goto done;DI=(uint16_t)(DI+(w.r.registers.direction?-1:1));--CX;}
    DX=0x3ce;low(&w,5);if(!effect(&w,0x8436,1))goto done;DX=(uint16_t)(DX+1);low(&w,0);if(!effect(&w,0x843a,1))goto done;DI=pop(&w);BP=pop(&w);if(w.sp>0xfffc){out->status=5;out->next_segment=w.cs;out->next_ip=0x843d;goto done;}out->next_ip=pop(&w);out->next_segment=pop(&w);out->status=0;
done:
    out->current_sp=w.sp;out->returned=w.r;
}
