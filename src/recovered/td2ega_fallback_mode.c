#include "td2ega_fallback_mode.h"
#include <stddef.h>
typedef struct work {uint8_t *m;uint16_t ss,sp,cs;td2ega_state_registers r;td2ega_small_platform_service bios;void *bios_context;td2ega_line_draw_service device;void *device_context;uint32_t limit;td2ega_fallback_mode_result *o;} work;
static uint32_t address(uint16_t s,uint16_t o){return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(work *w,uint16_t s,uint16_t o){uint32_t a=address(s,o);return (uint16_t)(w->m[a]|((uint16_t)w->m[(a+1)&UINT32_C(0xfffff)]<<8));}
static void put(work *w,uint16_t s,uint16_t o,uint16_t v){uint32_t a=address(s,o);w->m[a]=(uint8_t)v;w->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++w->o->bus_writes;}
static void push(work *w,uint16_t v){w->sp=(uint16_t)(w->sp-2);put(w,w->ss,w->sp,v);}
static uint16_t pop(work *w){uint16_t v=word(w,w->ss,w->sp);w->sp=(uint16_t)(w->sp+2);return v;}
static int valid(const td2ega_state_registers *r){return r->carry<=1 && r->registers.interrupts_enabled<=1 && r->registers.direction<=1;}
static int begin(work *w,uint16_t site){w->o->next_segment=w->cs;w->o->next_ip=site;if(w->o->events==w->limit){w->o->status=3;return 0;}return 1;}
static int video_bios(work *w)
{
    td2ega_small_platform_request q;td2ega_state_registers r=w->r;if(!begin(w,0x5f81))return 0;q=(td2ega_small_platform_request){0x10,0x5f81,w->cs,w->ss,w->sp,w->r};
    if(w->bios==NULL || !w->bios(w->bios_context,w->m,&q,&r) || !valid(&r)){w->o->status=4;return 0;}++w->o->events;++w->o->services;w->r=r;return 1;
}
static int effect(work *w,uint16_t site,uint16_t kind)
{
    td2ega_line_draw_request q={0};td2ega_line_draw_response r={0};if(!begin(w,site))return 0;q.kind=kind;q.site=site;q.segment=w->cs;q.stack_segment=w->ss;q.stack_sp=w->sp;q.port=w->r.registers.dx;q.value=kind==1?(uint8_t)w->r.registers.ax:w->r.registers.ax;q.address=kind==4?address(w->r.registers.es,w->r.registers.di):0;q.incoming=w->r;r.returned=w->r;r.value=q.value;
    if(w->device==NULL || !w->device(w->device_context,w->m,&q,&r)){w->o->status=4;return 0;}++w->o->events;if(kind==1)++w->o->ports;else{++w->o->words;++w->o->bus_writes;}return 1;
}
#define AX w.r.registers.ax
#define BX w.r.registers.bx
#define CX w.r.registers.cx
#define DX w.r.registers.dx
#define DI w.r.registers.di
#define CF w.r.carry
static void low(work *w,uint16_t v){w->r.registers.ax=(uint16_t)((w->r.registers.ax&0xff00)|(v&255));}
void td2ega_fallback_mode(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,uint16_t sp,const td2ega_state_registers *in,td2ega_small_platform_service bios,void *bios_context,td2ega_line_draw_service device,void *device_context,uint32_t events,td2ega_fallback_mode_result *out)
{
    work w;
    if(out==NULL)return;
    *out=(td2ega_fallback_mode_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || !valid(in))return;
    w=(work){m,ss,sp,(uint16_t)(load+0x6c9),*in,bios,bios_context,device,device_context,events,out};push(&w,DI);m[address(w.r.registers.ds,0x5e6e)]=1;++out->bus_writes;AX=0x40;w.r.registers.es=AX;AX=word(&w,w.r.registers.es,0x10);AX=(uint16_t)((AX&0xffcf)|0x20);CF=0;put(&w,w.r.registers.es,0x10,AX);AX=4;if(!video_bios(&w))goto done;
    low(&w,3);DX=0x3bf;if(!effect(&w,0x5f88,1))goto done;low(&w,2);DX=0x3b8;if(!effect(&w,0x5f8e,1))goto done;CX=12;DX=0x3b4;BX=0;CF=0;
    do{low(&w,BX);if(!effect(&w,0x5f99,1))goto done;DX=(uint16_t)(DX+1);low(&w,m[address(w.r.registers.ds,(uint16_t)(BX+0x5e70))]);if(!effect(&w,0x5f9f,1))goto done;DX=(uint16_t)(DX-1);BX=(uint16_t)(BX+1);--CX;}while(CX!=0);
    w.r.registers.direction=0;AX=0xb800;w.r.registers.es=AX;DI=0;CF=0;CX=0x4000;AX=0;CF=0;
    while(CX!=0){if(!effect(&w,0x5fb1,4))goto done;DI=(uint16_t)(DI+2);--CX;}
    low(&w,0x8a);DX=0x3b8;if(!effect(&w,0x5fb8,1))goto done;DI=pop(&w);if(w.sp>0xfffc){out->status=5;out->next_segment=w.cs;out->next_ip=0x5fba;goto done;}out->next_ip=pop(&w);out->next_segment=pop(&w);out->status=0;
done:
    out->current_sp=w.sp;out->returned=w.r;
}
