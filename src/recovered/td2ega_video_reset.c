#include "td2ega_video_reset.h"
#include <stddef.h>
typedef struct work {uint8_t *m;uint32_t bytes;uint16_t load,ss,sp,cs;td2ega_state_registers r;td2ega_small_platform_service bios;void *bios_context;td2ega_line_draw_service device;void *device_context;uint32_t call_limit,event_limit;td2ega_video_reset_result *o;} work;
static uint32_t address(uint16_t s,uint16_t o){return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(work *w,uint16_t s,uint16_t o){uint32_t a=address(s,o);return (uint16_t)(w->m[a]|((uint16_t)w->m[(a+1)&UINT32_C(0xfffff)]<<8));}
static void put(work *w,uint16_t s,uint16_t o,uint16_t v){uint32_t a=address(s,o);w->m[a]=(uint8_t)v;w->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++w->o->bus_writes;}
static void push(work *w,uint16_t v){w->sp=(uint16_t)(w->sp-2);put(w,w->ss,w->sp,v);}
static uint16_t pop(work *w){uint16_t v=word(w,w->ss,w->sp);w->sp=(uint16_t)(w->sp+2);return v;}
static int valid(const td2ega_state_registers *r){return r->carry<=1 && r->registers.interrupts_enabled<=1 && r->registers.direction<=1;}
static int begin(work *w,uint16_t site){w->o->next_segment=w->cs;w->o->next_ip=site;if(w->o->events==w->event_limit){w->o->status=3;return 0;}return 1;}
static int video_bios(work *w,uint16_t site)
{
    td2ega_small_platform_request q;td2ega_state_registers r=w->r;if(!begin(w,site))return 0;q=(td2ega_small_platform_request){0x10,site,w->cs,w->ss,w->sp,w->r};if(w->bios==NULL || !w->bios(w->bios_context,w->m,&q,&r) || !valid(&r)){w->o->status=4;return 0;}++w->o->events;++w->o->services;w->r=r;return 1;
}
static int fill(work *w)
{
    td2ega_plane_fill_result h;uint16_t expected=w->sp;
    if(w->o->calls==w->call_limit){w->o->status=3;w->o->next_segment=w->cs;w->o->next_ip=0x6431;return 0;}++w->o->calls;push(w,w->cs);push(w,0x6436);
    td2ega_plane_fill(w->m,w->bytes,w->load,w->ss,w->sp,&w->r,w->device,w->device_context,w->event_limit-w->o->events,&h);w->r=h.returned;w->sp=h.current_sp;w->o->events+=h.events;w->o->ports+=h.events-h.bytes;w->o->bytes+=h.bytes;w->o->bus_writes+=h.bus_writes;w->o->next_segment=h.next_segment;w->o->next_ip=h.next_ip;
    if(h.status!=0){w->o->status=h.status;return 0;}if(h.next_segment!=w->cs || h.next_ip!=0x6436 || h.current_sp!=expected){w->o->status=1;return 0;}return 1;
}
#define AX w.r.registers.ax
#define CF w.r.carry
void td2ega_video_reset(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,uint16_t sp,const td2ega_state_registers *in,td2ega_small_platform_service bios,void *bios_context,td2ega_line_draw_service device,void *device_context,uint32_t calls,uint32_t events,td2ega_video_reset_result *out)
{
    work w;uint32_t wide;
    if(out==NULL)return;
    *out=(td2ega_video_reset_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || !valid(in))return;
    w=(work){m,bytes,load,ss,sp,(uint16_t)(load+0x6c9),*in,bios,bios_context,device,device_context,calls,events,out};
    AX=0;CF=0;push(&w,AX);if(!fill(&w))goto done;
    wide=(uint32_t)w.sp+2;CF=(uint16_t)(wide>65535);w.sp=(uint16_t)wide;
    AX=0x40;w.r.registers.es=AX;AX=word(&w,w.r.registers.es,0x10);
    AX=(uint16_t)((AX&0xffcf)|0x10);CF=0;put(&w,w.r.registers.es,0x10,AX);
    AX=3;if(!video_bios(&w,0x6450))goto done;
    AX=(uint16_t)((AX&0xff)|0x0b00);w.r.registers.bx=0;
    if(!video_bios(&w,0x6457))goto done;
    if(w.sp>0xfffc){out->status=5;out->next_segment=w.cs;out->next_ip=0x6459;goto done;}
    out->next_ip=pop(&w);out->next_segment=pop(&w);out->status=0;
done:
    out->current_sp=w.sp;out->returned=w.r;
}
