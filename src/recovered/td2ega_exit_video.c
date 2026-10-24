#include "td2ega_exit_video.h"
#include <stddef.h>
typedef struct work {uint8_t *m;uint32_t bytes;uint16_t load,ss,sp,cs;td2ega_state_registers r;td2ega_small_platform_service bios;void *bios_context;td2ega_line_draw_service device;void *device_context;uint32_t calls,events;td2ega_exit_video_result *o;} work;
static uint32_t address(uint16_t s,uint16_t o){return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(work *w,uint16_t s,uint16_t o){uint32_t a=address(s,o);return (uint16_t)(w->m[a]|((uint16_t)w->m[(a+1)&UINT32_C(0xfffff)]<<8));}
static void put(work *w,uint16_t s,uint16_t o,uint16_t v){uint32_t a=address(s,o);w->m[a]=(uint8_t)v;w->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++w->o->bus_writes;}
static void push(work *w,uint16_t v){w->sp=(uint16_t)(w->sp-2);put(w,w->ss,w->sp,v);}
static uint16_t pop(work *w){uint16_t v=word(w,w->ss,w->sp);w->sp=(uint16_t)(w->sp+2);return v;}
static int valid(const td2ega_state_registers *r){return r->carry<=1 && r->registers.interrupts_enabled<=1 && r->registers.direction<=1;}
static int event(work *w,uint16_t site){w->o->next_segment=w->cs;w->o->next_ip=site;if(w->o->events==w->events){w->o->status=3;return 0;}return 1;}
static int device(work *w,uint16_t site,uint16_t kind)
{
    td2ega_line_draw_request q={0};td2ega_line_draw_response r={0};
    if(!event(w,site))return 0;
    q.kind=kind;q.site=site;q.segment=w->cs;q.stack_segment=w->ss;q.stack_sp=w->sp;q.port=w->r.registers.dx;q.value=kind==1?(uint8_t)w->r.registers.ax:w->r.registers.ax;q.address=kind==4?address(w->r.registers.es,w->r.registers.di):0;q.incoming=w->r;r.returned=w->r;r.value=q.value;
    if(w->device==NULL || !w->device(w->device_context,w->m,&q,&r)){w->o->status=4;return 0;}
    ++w->o->events;if(kind==1)++w->o->ports;else{++w->o->words;++w->o->bus_writes;}return 1;
}
static int bios(work *w)
{
    td2ega_small_platform_request q;td2ega_state_registers r=w->r;
    if(!event(w,0x6018))return 0;
    q=(td2ega_small_platform_request){0x10,0x6018,w->cs,w->ss,w->sp,w->r};
    if(w->bios==NULL || !w->bios(w->bios_context,w->m,&q,&r) || !valid(&r)){w->o->status=4;return 0;}
    ++w->o->events;++w->o->services;w->r=r;return 1;
}
static int reset(work *w)
{
    td2ega_video_reset_result h;uint16_t expected=w->sp;
    w->o->next_segment=w->cs;w->o->next_ip=0x5fc4;
    if(w->o->calls==w->calls){w->o->status=3;return 0;}
    ++w->o->calls;push(w,w->cs);push(w,0x5fc9);
    td2ega_video_reset(w->m,w->bytes,w->load,w->ss,w->sp,&w->r,w->bios,w->bios_context,w->device,w->device_context,w->calls-w->o->calls,w->events-w->o->events,&h);
    w->r=h.returned;w->sp=h.current_sp;w->o->calls+=h.calls;w->o->events+=h.events;w->o->services+=h.services;w->o->ports+=h.ports;w->o->bytes+=h.bytes;w->o->bus_writes+=h.bus_writes;w->o->next_segment=h.next_segment;w->o->next_ip=h.next_ip;
    if(h.status!=0){w->o->status=h.status;return 0;}
    if(h.next_segment!=w->cs || h.next_ip!=0x5fc9 || h.current_sp!=expected){w->o->status=1;return 0;}
    return 1;
}
#define AX w.r.registers.ax
#define BX w.r.registers.bx
#define CX w.r.registers.cx
#define DX w.r.registers.dx
#define DI w.r.registers.di
#define ES w.r.registers.es
#define CF w.r.carry
static void low(work *w,uint16_t v){w->r.registers.ax=(uint16_t)((w->r.registers.ax&0xff00)|(v&255));}
void td2ega_exit_video(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,uint16_t sp,const td2ega_state_registers *in,td2ega_small_platform_service b,void *bc,td2ega_line_draw_service d,void *dc,uint32_t calls,uint32_t events,td2ega_exit_video_result *out)
{
    work w;uint8_t flag;
    if(out==NULL)return;
    *out=(td2ega_exit_video_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || !valid(in))return;
    w=(work){m,bytes,load,ss,sp,(uint16_t)(load+0x6c9),*in,b,bc,d,dc,calls,events,out};push(&w,DI);flag=m[address(w.r.registers.ds,0x5e6e)];CF=0;
    if(flag==0){if(!reset(&w))goto done;}
    else{
        AX=0x40;ES=AX;AX=word(&w,ES,0x10);AX=(uint16_t)((AX&0xffcf)|0x30);CF=0;put(&w,ES,0x10,AX);
        low(&w,3);DX=0x3bf;if(!device(&w,0x5fe3,1))goto done;low(&w,0x20);DX=0x3b8;if(!device(&w,0x5fe9,1))goto done;CX=12;DX=0x3b4;BX=0;CF=0;
        do{low(&w,BX);if(!device(&w,0x5ff4,1))goto done;DX=(uint16_t)(DX+1);low(&w,m[address(w.r.registers.ds,(uint16_t)(BX+0x5e7c))]);if(!device(&w,0x5ffa,1))goto done;DX=(uint16_t)(DX-1);BX=(uint16_t)(BX+1);CX=(uint16_t)(CX-1);}while(CX!=0);
        w.r.registers.direction=0;AX=0xb800;ES=AX;DI=0;CX=0x4000;AX=0;CF=0;
        while(CX!=0){if(!device(&w,0x600c,4))goto done;DI=(uint16_t)(DI+2);CX=(uint16_t)(CX-1);}
        low(&w,0x28);DX=0x3b8;if(!device(&w,0x6013,1))goto done;AX=7;if(!bios(&w))goto done;
    }
    DI=pop(&w);
    if(w.sp>0xfffc){out->status=5;out->next_segment=w.cs;out->next_ip=flag?0x601b:0x5fca;goto done;}
    out->next_ip=pop(&w);out->next_segment=pop(&w);out->status=0;
done:
    out->current_sp=w.sp;out->returned=w.r;
}
