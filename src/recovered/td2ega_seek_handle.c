#include "td2ega_seek_handle.h"
#include "td2ega_table_scalar.h"
#include <stddef.h>
typedef struct work {uint8_t *m;uint32_t bytes;uint16_t cs,ss,sp,load;td2ega_state_registers r;td2ega_small_platform_service service;void *context;uint32_t limit;td2ega_seek_handle_result *o;} work;
static uint32_t address(uint16_t s,uint16_t o){return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(work *w,uint16_t s,uint16_t o){uint32_t a=address(s,o);return (uint16_t)(w->m[a]|((uint16_t)w->m[(a+1)&UINT32_C(0xfffff)]<<8));}
static void put(work *w,uint16_t s,uint16_t o,uint16_t v){uint32_t a=address(s,o);w->m[a]=(uint8_t)v;w->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++w->o->bus_writes;}
static uint16_t arg(work *w,uint16_t o){return word(w,w->ss,(uint16_t)(w->r.bp+o));}
static int valid(const td2ega_state_registers *r){return r->carry<=1 && r->registers.interrupts_enabled<=1 && r->registers.direction<=1;}
static int service(work *w,uint16_t site){td2ega_small_platform_request request;td2ega_state_registers returned;w->o->next_segment=w->cs;w->o->next_ip=site;if(w->o->services==w->limit){w->o->status=3;return 0;}request=(td2ega_small_platform_request){0x21,site,w->cs,w->ss,w->sp,w->r};returned=w->r;if(w->service==NULL || !w->service(w->context,w->m,&request,&returned) || !valid(&returned)){w->o->status=4;return 0;}++w->o->services;w->r=returned;return 1;}
static uint16_t add(work *w,uint16_t a,uint16_t b){uint32_t v=(uint32_t)a+b;w->r.carry=(uint16_t)(v>65535);return (uint16_t)v;}
static uint16_t adc(work *w,uint16_t a,uint16_t b){uint32_t v=(uint32_t)a+b+w->r.carry;w->r.carry=(uint16_t)(v>65535);return (uint16_t)v;}
static uint16_t pop(work *w){uint16_t v=word(w,w->ss,w->sp);w->sp=(uint16_t)(w->sp+2);return v;}
#define AX w.r.registers.ax
#define BX w.r.registers.bx
#define CX w.r.registers.cx
#define DX w.r.registers.dx
#define BP w.r.bp
#define CF w.r.carry
void td2ega_seek_handle(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,uint16_t sp,const td2ega_state_registers *in,td2ega_small_platform_service callback,void *context,uint32_t limit,td2ega_seek_handle_result *out)
{
    work w;td2ega_table_scalar_result mapped;uint16_t expected,v;uint8_t mode;
    if(out==NULL)return;
    *out=(td2ega_seek_handle_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || sp<24 || sp>UINT16_C(0xffe0) || !valid(in))return;
    w=(work){m,bytes,(uint16_t)(load+0x13a8),ss,sp,load,*in,callback,context,limit,out};w.sp=(uint16_t)(w.sp-2);put(&w,ss,w.sp,BP);BP=w.sp;w.sp=(uint16_t)(w.sp-4);CF=0;BX=arg(&w,6);v=word(&w,w.r.registers.ds,0x6da2);CF=(uint16_t)(BX<v);if(BX>=v){AX=0x900;CF=1;goto tail;}
    CF=0;if(arg(&w,10)&0x8000){v=arg(&w,12);CF=0;if(v==0)goto negative;CX=0;CF=0;DX=CX;AX=0x4201;if(!service(&w,0x2286))goto finish;if(CF)goto tail;v=arg(&w,12);CF=0;if((v&2)==0){AX=add(&w,AX,arg(&w,8));DX=adc(&w,DX,arg(&w,10));if((DX&0x8000)==0)goto final_seek;goto negative;}
        put(&w,ss,(uint16_t)(BP-2),DX);put(&w,ss,(uint16_t)(BP-4),AX);DX=CX;AX=0x4202;if(!service(&w,0x22aa))goto finish;AX=add(&w,AX,arg(&w,8));DX=adc(&w,DX,arg(&w,10));if((DX&0x8000)==0)goto final_seek;CX=arg(&w,(uint16_t)-2);DX=arg(&w,(uint16_t)-4);AX=0x4200;if(!service(&w,0x22bd))goto finish;
negative:
        AX=0x1600;CF=1;goto tail;
    }
final_seek:
    DX=arg(&w,8);CX=arg(&w,10);mode=(uint8_t)arg(&w,12);AX=(uint16_t)(0x4200|mode);if(!service(&w,0x22cc))goto finish;if(!CF){uint32_t a=address(w.r.registers.ds,(uint16_t)(BX+0x6da4));w.m[a]=(uint8_t)(w.m[a]&0xfd);++out->bus_writes;CF=0;}
tail:
    if(CF){expected=w.sp;w.sp=(uint16_t)(w.sp-2);put(&w,ss,w.sp,0x93c);++out->error_calls;td2ega_table_scalar(w.m,w.bytes,w.load,ss,w.sp,0,&w.r,&mapped);out->bus_writes+=mapped.bus_writes;w.r=mapped.returned;w.sp=mapped.current_sp;if(mapped.status!=0 || mapped.next_segment!=w.cs || mapped.next_ip!=0x93c || w.sp!=expected){out->status=1;out->next_segment=mapped.next_segment;out->next_ip=mapped.next_ip;goto finish;}AX=0xffff;DX=0xffff;}
    w.sp=BP;BP=pop(&w);out->next_ip=pop(&w);out->next_segment=pop(&w);out->status=0;
finish:
    out->current_sp=w.sp;out->returned=w.r;
}
