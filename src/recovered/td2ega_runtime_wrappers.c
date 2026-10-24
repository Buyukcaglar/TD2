#include "td2ega_runtime_wrappers.h"
#include <stddef.h>
typedef struct work {uint8_t *m;uint32_t bytes;uint16_t load,cs,ss,sp;uint32_t limit;td2ega_state_registers r;td2ega_runtime_wrappers_result *o;} work;
static uint32_t address(uint16_t s,uint16_t o){return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(work *w,uint16_t s,uint16_t o){uint32_t a=address(s,o);return (uint16_t)(w->m[a]|((uint16_t)w->m[(a+1)&UINT32_C(0xfffff)]<<8));}
static uint8_t byte(work *w,uint16_t o){return w->m[address(w->r.registers.ds,o)];}
static void put(work *w,uint16_t s,uint16_t o,uint16_t v,unsigned n){uint32_t a=address(s,o);w->m[a]=(uint8_t)v;if(n==2)w->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++w->o->bus_writes;}
static void push(work *w,uint16_t v){w->sp=(uint16_t)(w->sp-2);put(w,w->ss,w->sp,v,2);}
static uint16_t pop(work *w){uint16_t v=word(w,w->ss,w->sp);w->sp=(uint16_t)(w->sp+2);return v;}
static int call(work *w,uint16_t entry)
{
    td2ega_scalar_state_result a;td2ega_small_state_result b;uint16_t expected=w->sp,ret=entry==0?0x1861:0x0e0b,status;
    if(w->limit==0){w->o->status=3;w->o->next_segment=w->cs;w->o->next_ip=entry==0?0x185d:0x0e06;return 0;}w->o->calls=1;push(w,w->cs);push(w,ret);
    if(entry==0){td2ega_scalar_state(w->m,w->bytes,w->load,w->ss,w->sp,2,&w->r,&a);w->r=a.returned;w->sp=a.current_sp;w->o->bus_writes+=a.bus_writes;w->o->next_segment=a.next_segment;w->o->next_ip=a.next_ip;status=a.status;}
    else{td2ega_small_state(w->m,w->bytes,w->load,w->ss,w->sp,9,&w->r,&b);w->r=b.returned;w->sp=b.current_sp;w->o->bus_writes+=b.writes;w->o->next_segment=b.next_segment;w->o->next_ip=b.next_ip;status=b.status;}
    if(status!=0){w->o->status=status;return 0;}if(w->o->next_segment!=w->cs || w->o->next_ip!=ret || w->sp!=expected){w->o->status=1;return 0;}return 1;
}
#define AX w.r.registers.ax
#define BX w.r.registers.bx
#define SI w.r.registers.si
#define BP w.r.bp
#define DS w.r.registers.ds
#define CF w.r.carry
void td2ega_runtime_wrappers(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,uint16_t sp,uint16_t entry,const td2ega_state_registers *in,uint32_t limit,td2ega_runtime_wrappers_result *out)
{
    work w;uint16_t v;uint32_t wide;
    if(out==NULL)return;
    *out=(td2ega_runtime_wrappers_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || entry>1 || sp<(entry==0?22:26) || sp>UINT16_C(0xffe0) || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1)return;
    w=(work){m,bytes,load,(uint16_t)(load+0x13a8),ss,sp,limit,*in,out};push(&w,BP);BP=w.sp;
    if(entry==0){
        v=word(&w,ss,(uint16_t)(BP+6));CF=(uint16_t)(v<0xffff);
        if(v==0xffff)goto zero;
        BX=word(&w,ss,(uint16_t)(BP+6));CF=0;if((byte(&w,(uint16_t)(BX+0x6f57))&4)==0)goto zero;if(!call(&w,0))goto finish;CF=0;if(AX!=0){AX=1;goto restored;}
zero:
        AX=0;CF=0;
restored:
        BP=pop(&w);
    }else{
        push(&w,SI);SI=word(&w,ss,(uint16_t)(BP+6));CF=0;
        if((byte(&w,(uint16_t)(SI+6))&0x83)!=0){
            CF=0;if((byte(&w,(uint16_t)(SI+6))&8)!=0){push(&w,word(&w,DS,(uint16_t)(SI+4)));if(!call(&w,1))goto finish;wide=(uint32_t)w.sp+2;w.sp=(uint16_t)wide;CF=(uint16_t)(wide>65535);v=(uint16_t)(byte(&w,(uint16_t)(SI+6))&0xf7);put(&w,DS,(uint16_t)(SI+6),v,1);AX=0;CF=0;put(&w,DS,SI,AX,2);put(&w,DS,(uint16_t)(SI+4),AX,2);put(&w,DS,(uint16_t)(SI+2),AX,2);}
        }
        SI=pop(&w);BP=pop(&w);
    }
    out->next_ip=pop(&w);out->next_segment=pop(&w);out->status=0;
finish:
    out->current_sp=w.sp;out->returned=w.r;
}
