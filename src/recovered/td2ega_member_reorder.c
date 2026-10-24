#include "td2ega_member_reorder.h"
#include <stddef.h>
typedef struct work {uint8_t *m;uint32_t bytes;uint16_t load,cs,ss,sp;uint32_t limit;td2ega_state_registers r;td2ega_member_reorder_result *o;} work;
static uint32_t address(uint16_t s,uint16_t o){return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(work *w,uint16_t s,uint16_t o){uint32_t a=address(s,o);return (uint16_t)(w->m[a]|((uint16_t)w->m[(a+1)&UINT32_C(0xfffff)]<<8));}
static uint8_t byte(work *w,uint16_t s,uint16_t o){return w->m[address(s,o)];}
static void put(work *w,uint16_t s,uint16_t o,uint16_t v,unsigned n){uint32_t a=address(s,o);w->m[a]=(uint8_t)v;if(n==2)w->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++w->o->bus_writes;}
static void push(work *w,uint16_t v){w->sp=(uint16_t)(w->sp-2);put(w,w->ss,w->sp,v,2);}
static uint16_t pop(work *w){uint16_t v=word(w,w->ss,w->sp);w->sp=(uint16_t)(w->sp+2);return v;}
static int32_t sw(uint16_t v){return v&0x8000?(int32_t)v-65536:(int32_t)v;}
static uint16_t add(work *w,uint16_t a,uint16_t b){uint32_t v=(uint32_t)a+b;w->r.carry=(uint16_t)(v>65535);return (uint16_t)v;}
static int step(work *w,uint16_t ip){if(w->o->steps==w->limit){w->o->status=3;w->o->next_segment=w->cs;w->o->next_ip=ip;return 0;}++w->o->steps;return 1;}
static int member(work *w){td2ega_far_member_result result;uint16_t expected=w->sp;push(w,w->cs);push(w,0xc869);++w->o->calls;td2ega_far_member(w->m,w->bytes,w->load,w->ss,w->sp,&w->r,&result);w->r=result.returned;w->sp=result.current_sp;w->o->bus_writes+=result.bus_writes;w->o->next_segment=result.next_segment;w->o->next_ip=result.next_ip;if(result.status!=0){w->o->status=result.status;return 0;}if(result.next_segment!=w->cs || result.next_ip!=0xc869 || w->sp!=expected){w->o->status=1;return 0;}return 1;}
#define AX w.r.registers.ax
#define BX w.r.registers.bx
#define CX w.r.registers.cx
#define DX w.r.registers.dx
#define SI w.r.registers.si
#define DI w.r.registers.di
#define BP w.r.bp
#define DS w.r.registers.ds
#define ES w.r.registers.es
#define CF w.r.carry
#define LOCAL(n) word(&w,ss,(uint16_t)(BP+(n)))
#define STORE(n,v) put(&w,ss,(uint16_t)(BP+(n)),(v),2)
void td2ega_member_reorder(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,uint16_t sp,const td2ega_state_registers *in,uint32_t limit,td2ega_member_reorder_result *out)
{
    work w;uint16_t v,stride;uint8_t b;uint32_t wide;
    if(out==NULL)return;
    *out=(td2ega_member_reorder_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || sp<54 || sp>UINT16_C(0xffe0) || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1)return;
    w=(work){m,bytes,load,(uint16_t)(load+0x6c9),ss,sp,limit,*in,out};push(&w,BP);BP=w.sp;w.sp=(uint16_t)(w.sp-20);CF=0;push(&w,DS);push(&w,SI);push(&w,DI);AX=LOCAL(8);DS=AX;AX=LOCAL(6);SI=AX;BX=word(&w,DS,(uint16_t)(SI+4));STORE(-2,BX);STORE(-4,0);
    for(;;){
        if(!step(&w,0xc856))goto finish;
        push(&w,LOCAL(-4));push(&w,LOCAL(8));push(&w,LOCAL(6));AX=(uint16_t)(load+0x178f);DS=AX;if(!member(&w))goto finish;w.sp=add(&w,w.sp,6);STORE(-6,AX);STORE(-8,DX);SI=AX;DS=DX;b=byte(&w,DS,(uint16_t)(SI+15));b=(uint8_t)(b&0xf0);AX=(uint16_t)((AX&0xff00)|b);CF=0;
        if(b==0){
            b=(uint8_t)((byte(&w,DS,(uint16_t)(SI+14))>>4)&15);BX=(uint16_t)((BX&0xff00)|b);CF=0;put(&w,ss,(uint16_t)(BP-20),b,1);
            if(b!=0){
                AX=word(&w,DS,SI);STORE(-10,AX);DX=word(&w,DS,(uint16_t)(SI+2));STORE(-12,DX);wide=(uint32_t)AX*DX;AX=(uint16_t)wide;DX=(uint16_t)(wide>>16);CF=(uint16_t)(DX!=0);STORE(-14,AX);SI=add(&w,SI,16);STORE(-16,SI);put(&w,ss,(uint16_t)(BP-18),4,1);
                do{
                    if(!step(&w,0xc8b9))goto finish;
                    b=byte(&w,ss,(uint16_t)(BP-20));CF=(uint16_t)(b&1);put(&w,ss,(uint16_t)(BP-20),(uint16_t)(b>>1),1);
                    if(CF){
                        ES=LOCAL(12);DI=LOCAL(10);DS=LOCAL(-8);DX=0;CF=0;BX=LOCAL(-12);
                        do{
                            SI=LOCAL(-16);SI=add(&w,SI,DX);CX=LOCAL(-10);
                            do{
                                if(!step(&w,0xc8d4))goto finish;
                                b=byte(&w,DS,SI);AX=(uint16_t)((AX&0xff00)|b);put(&w,ES,DI,AX,1);++out->byte_transfers;stride=w.r.registers.direction?0xffff:1;DI=(uint16_t)(DI+stride);SI=add(&w,SI,BX);CX=(uint16_t)(CX-1);
                            }while(CX!=0);
                            DX=(uint16_t)(DX+1);CF=(uint16_t)(DX<BX);
                        }while(DX!=BX);
                        ES=LOCAL(-8);DI=LOCAL(-16);DS=LOCAL(12);SI=LOCAL(10);CX=LOCAL(-14);
                        while(CX!=0){
                            if(!step(&w,0xc8ef))goto finish;
                            b=byte(&w,DS,SI);put(&w,ES,DI,b,1);++out->byte_transfers;stride=w.r.registers.direction?0xffff:1;SI=(uint16_t)(SI+stride);DI=(uint16_t)(DI+stride);CX=(uint16_t)(CX-1);
                        }
                    }
                    AX=LOCAL(-14);v=add(&w,LOCAL(-16),AX);STORE(-16,v);b=(uint8_t)(byte(&w,ss,(uint16_t)(BP-18))-1);put(&w,ss,(uint16_t)(BP-18),b,1);
                }while(b!=0);
            }
        }
        v=(uint16_t)(LOCAL(-4)+1);STORE(-4,v);v=LOCAL(-2);STORE(-2,(uint16_t)(v-1));if(sw(v)-1<=0)break;
    }
    DI=pop(&w);SI=pop(&w);DS=pop(&w);w.sp=BP;BP=pop(&w);out->next_ip=pop(&w);out->next_segment=pop(&w);out->status=0;
finish:
    out->current_sp=w.sp;out->returned=w.r;
}
