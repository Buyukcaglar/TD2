#include "td2ega_block_adjust.h"
#include <stddef.h>
typedef struct work {uint8_t *m;uint16_t ss,sp;td2ega_state_registers r;td2ega_block_adjust_result *o;} work;
static uint32_t address(uint16_t s,uint16_t o){return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(work *w,uint16_t s,uint16_t o){uint32_t a=address(s,o);return (uint16_t)(w->m[a]|((uint16_t)w->m[(a+1)&UINT32_C(0xfffff)]<<8));}
static uint16_t rd(work *w,uint16_t o){return word(w,w->r.registers.ds,o);}
static void put(work *w,uint16_t o,uint16_t v){uint32_t a=address(w->r.registers.ds,o);w->m[a]=(uint8_t)v;w->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++w->o->bus_writes;}
static int valid(const td2ega_state_registers *r){return r->carry<=1 && r->registers.interrupts_enabled<=1 && r->registers.direction<=1;}
static uint16_t add(work *w,uint16_t a,uint16_t b){uint32_t v=(uint32_t)a+b;w->r.carry=(uint16_t)(v>65535);return (uint16_t)v;}
#define AX w.r.registers.ax
#define BX w.r.registers.bx
#define CX w.r.registers.cx
#define DX w.r.registers.dx
#define SI w.r.registers.si
#define DI w.r.registers.di
#define CF w.r.carry
void td2ega_block_adjust(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,uint16_t sp,const td2ega_state_registers *in,td2ega_small_platform_service callback,void *context,uint32_t record_limit,uint32_t service_limit,td2ega_block_adjust_result *out)
{
    work w;uint16_t v,old;unsigned shift;td2ega_small_platform_request request;td2ega_state_registers returned;
    if(out==NULL)return;
    *out=(td2ega_block_adjust_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || sp>UINT16_C(0xffe0) || !valid(in))return;
    w=(work){m,ss,sp,*in,out};CX=word(&w,ss,(uint16_t)(w.r.bp+14));SI=DI;
    for(;;){
        if(out->records==record_limit){out->status=3;out->next_segment=(uint16_t)(load+0x13a8);out->next_ip=0x28c5;goto done;}++out->records;v=rd(&w,(uint16_t)(SI+2));CF=(uint16_t)(v<CX);if(v==CX)break;SI=add(&w,SI,4);CF=(uint16_t)(SI<0x6d7a);if(SI==0x6d7a){CF=1;goto ret;}
    }
    BX=DX;BX=add(&w,BX,rd(&w,SI));if(CF)goto ret;DX=BX;w.r.registers.es=CX;CF=(uint16_t)(SI<DI);if(SI==DI){v=rd(&w,0x6d24);CF=(uint16_t)(v<BX);if(v>=BX)goto exchange;}
    BX=add(&w,BX,15);old=BX;BX=(uint16_t)((BX>>1)|(CF<<15));CF=(uint16_t)(old&1);for(shift=0;shift<3;++shift){CF=(uint16_t)(BX&1);BX>>=1;}CF=(uint16_t)(SI<DI);if(SI==DI){BX=add(&w,BX,CX);AX=rd(&w,0x6d9b);CF=(uint16_t)(BX<AX);BX=(uint16_t)(BX-AX);w.r.registers.es=AX;}AX=(uint16_t)((AX&255)|0x4a00);out->next_segment=(uint16_t)(load+0x13a8);out->next_ip=0x2904;
    if(service_limit==0){out->status=3;goto done;}request=(td2ega_small_platform_request){0x21,0x2904,(uint16_t)(load+0x13a8),ss,sp,w.r};returned=w.r;if(callback==NULL || !callback(context,m,&request,&returned) || !valid(&returned)){out->status=4;goto done;}++out->services;w.r=returned;if(CF)goto ret;CF=(uint16_t)(SI<DI);if(SI==DI)put(&w,0x6d24,DX);
exchange:
    v=DX;DX=AX;AX=v;v=rd(&w,SI);put(&w,SI,AX);AX=v;DX=CX;
ret:
    out->next_ip=word(&w,ss,sp);w.sp=(uint16_t)(sp+2);out->next_segment=(uint16_t)(load+0x13a8);out->status=0;
done:
    out->current_sp=w.sp;out->returned=w.r;
}
