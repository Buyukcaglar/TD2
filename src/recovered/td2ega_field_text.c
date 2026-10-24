#include "td2ega_field_text.h"
#include <stddef.h>
typedef struct work {uint8_t *m;uint16_t ss,sp,cs;td2ega_state_registers r;td2ega_field_text_result *o;} work;
static uint32_t address(uint16_t s,uint16_t o){return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(work *w,uint16_t s,uint16_t o){uint32_t a=address(s,o);return (uint16_t)(w->m[a]|((uint16_t)w->m[(a+1)&UINT32_C(0xfffff)]<<8));}
static uint8_t byte(work *w,uint16_t o){return w->m[address(w->r.registers.ds,o)];}
static void put(work *w,uint16_t s,uint16_t o,uint16_t v,unsigned n){uint32_t a=address(s,o);w->m[a]=(uint8_t)v;if(n==2)w->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++w->o->bus_writes;}
static void push(work *w,uint16_t v){w->sp=(uint16_t)(w->sp-2);put(w,w->ss,w->sp,v,2);}
static uint16_t pop(work *w){uint16_t v=word(w,w->ss,w->sp);w->sp=(uint16_t)(w->sp+2);return v;}
static int32_t sw(uint16_t v){return v&0x8000?(int32_t)v-65536:(int32_t)v;}
static int step(work *w,uint32_t limit,uint16_t ip){if(w->o->iterations==limit){w->o->status=3;w->o->next_segment=w->cs;w->o->next_ip=ip;return 0;}++w->o->iterations;return 1;}
#define AX w.r.registers.ax
#define BX w.r.registers.bx
#define SI w.r.registers.si
#define BP w.r.bp
#define CF w.r.carry
void td2ega_field_text(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,uint16_t sp,const td2ega_state_registers *in,uint32_t call_limit,uint32_t child_limit,uint32_t iteration_limit,td2ega_field_text_result *out)
{
    work w;td2ega_string_memory_result child;uint16_t v,expected;uint32_t wide;uint8_t b;
    if(out==NULL)return;
    *out=(td2ega_field_text_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || sp<30 || sp>UINT16_C(0xffe0) || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1)return;
    w=(work){m,ss,sp,(uint16_t)(load+0x432),*in,out};push(&w,BP);BP=w.sp;CF=(uint16_t)(w.sp<2);w.sp=(uint16_t)(w.sp-2);push(&w,SI);v=word(&w,ss,(uint16_t)(BP+8));push(&w,v);v=word(&w,ss,(uint16_t)(BP+6));push(&w,v);
    if(call_limit==0){out->status=3;out->next_segment=w.cs;out->next_ip=0x13;goto done;}++out->calls;expected=w.sp;push(&w,w.cs);push(&w,0x18);td2ega_string_memory(m,bytes,load,ss,w.sp,1,&w.r,child_limit,&child);w.r=child.returned;w.sp=child.current_sp;out->child_operations+=child.operations;out->bus_writes+=child.bus_writes;out->next_segment=child.next_segment;out->next_ip=child.next_ip;
    if(child.status!=0){out->status=child.status;goto done;}if(child.next_segment!=w.cs || child.next_ip!=0x18 || w.sp!=expected){out->status=1;goto done;}wide=(uint32_t)w.sp+4;CF=(uint16_t)(wide>65535);w.sp=(uint16_t)wide;put(&w,ss,(uint16_t)(BP-2),17,2);
    for(;;){
        if(!step(&w,iteration_limit,0x2e))goto done;v=word(&w,ss,(uint16_t)(BP-2));CF=0;if(sw(v)<=0)break;BX=word(&w,ss,(uint16_t)(BP-2));SI=word(&w,ss,(uint16_t)(BP+6));b=byte(&w,(uint16_t)(BX+SI));CF=(uint16_t)(b<32);if(b!=32)break;put(&w,w.r.registers.ds,(uint16_t)(BX+SI),0,1);v=word(&w,ss,(uint16_t)(BP-2));put(&w,ss,(uint16_t)(BP-2),(uint16_t)(v-1),2);
    }
    put(&w,ss,(uint16_t)(BP-2),0,2);
    for(;;){
        if(!step(&w,iteration_limit,0x51))goto done;SI=word(&w,ss,(uint16_t)(BP-2));v=word(&w,ss,(uint16_t)(BP+6));wide=(uint32_t)SI+v;CF=(uint16_t)(wide>65535);SI=(uint16_t)wide;b=byte(&w,SI);CF=0;if(b==0)break;CF=(uint16_t)(b<32);if(b==32)put(&w,w.r.registers.ds,SI,95,1);v=word(&w,ss,(uint16_t)(BP-2));put(&w,ss,(uint16_t)(BP-2),(uint16_t)(v+1),2);
    }
    SI=pop(&w);w.sp=BP;BP=pop(&w);out->next_ip=pop(&w);out->next_segment=pop(&w);out->status=0;
done:
    out->current_sp=w.sp;out->returned=w.r;
}
