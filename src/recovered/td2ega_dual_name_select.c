#include "td2ega_dual_name_select.h"
#include <stddef.h>
typedef struct work {uint8_t *m;uint32_t bytes;uint16_t load,ss,sp,cs;td2ega_state_registers r;uint32_t call_limit,operation_limit,iteration_limit;td2ega_dual_name_select_result *o;} work;
static uint32_t address(uint16_t s,uint16_t o){return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(work *w,uint16_t s,uint16_t o){uint32_t a=address(s,o);return (uint16_t)(w->m[a]|((uint16_t)w->m[(a+1)&UINT32_C(0xfffff)]<<8));}
static uint16_t rd(work *w,uint16_t o){return word(w,w->r.registers.ds,o);}
static void put(work *w,uint16_t s,uint16_t o,uint16_t v){uint32_t a=address(s,o);w->m[a]=(uint8_t)v;w->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++w->o->bus_writes;}
static void wr(work *w,uint16_t o,uint16_t v){put(w,w->r.registers.ds,o,v);}
static void push(work *w,uint16_t v){w->sp=(uint16_t)(w->sp-2);put(w,w->ss,w->sp,v);}
static uint16_t pop(work *w){uint16_t v=word(w,w->ss,w->sp);w->sp=(uint16_t)(w->sp+2);return v;}
static int valid(const td2ega_state_registers *r){return r->carry<=1 && r->registers.interrupts_enabled<=1 && r->registers.direction<=1;}
static int32_t signed_word(uint16_t v){return v<0x8000?(int32_t)v:(int32_t)v-65536;}
static void multiply(work *w,uint16_t operand)
{int32_t product=signed_word(w->r.registers.ax)*signed_word(operand);uint32_t bits=(uint32_t)product;w->r.registers.ax=(uint16_t)bits;w->r.registers.dx=(uint16_t)(bits>>16);w->r.carry=(uint16_t)(product!=signed_word(w->r.registers.ax));}
static void name_offset(work *w)
{uint32_t wide=(uint32_t)w->r.registers.ax+0x8d24;w->r.carry=(uint16_t)(wide>65535);w->r.registers.ax=(uint16_t)wide;}
static int helper(work *w,uint16_t site,uint16_t entry)
{
    td2ega_string_memory_result h;uint16_t expected=w->sp;
    if(w->o->calls==w->call_limit){w->o->status=3;w->o->next_segment=w->cs;w->o->next_ip=site;return 0;}++w->o->calls;push(w,w->cs);push(w,(uint16_t)(site+5));
    td2ega_string_memory(w->m,w->bytes,w->load,w->ss,w->sp,entry,&w->r,w->operation_limit,&h);w->r=h.returned;w->sp=h.current_sp;w->o->operations+=h.operations;w->o->bus_writes+=h.bus_writes;w->o->next_segment=h.next_segment;w->o->next_ip=h.next_ip;
    if(h.status!=0){w->o->status=h.status;return 0;}if(h.next_segment!=w->cs || h.next_ip!=(uint16_t)(site+5) || w->sp!=expected){w->o->status=1;return 0;}return 1;
}
#define AX w.r.registers.ax
#define BX w.r.registers.bx
#define BP w.r.bp
#define CF w.r.carry
void td2ega_dual_name_select(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,uint16_t sp,const td2ega_state_registers *in,uint32_t calls,uint32_t operations,uint32_t iterations,td2ega_dual_name_select_result *out)
{
    work w;uint16_t v;
    if(out==NULL)return;
    *out=(td2ega_dual_name_select_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || sp<28 || sp>UINT16_C(0xffe0) || !valid(in))return;
    w=(work){m,bytes,load,ss,sp,load,*in,calls,operations,iterations,out};push(&w,BP);BP=w.sp;CF=(uint16_t)(w.sp<2);w.sp=(uint16_t)(w.sp-2);wr(&w,0x9266,0xffff);wr(&w,0x8cfe,0xffff);put(&w,ss,(uint16_t)(BP-2),0);
    for(;;){if(out->iterations==w.iteration_limit){out->status=3;out->next_segment=w.cs;out->next_ip=0x06ad;goto done;}++out->iterations;AX=rd(&w,0x8a7a);v=word(&w,ss,(uint16_t)(BP-2));CF=(uint16_t)(v<AX);if(signed_word(v)>=signed_word(AX))break;
        AX=0x8428;push(&w,AX);AX=30;multiply(&w,word(&w,ss,(uint16_t)(BP-2)));name_offset(&w);push(&w,AX);if(!helper(&w,0x0678,3))goto done;w.sp=(uint16_t)(w.sp+4);CF=0;if(AX==0){AX=word(&w,ss,(uint16_t)(BP-2));wr(&w,0x9266,AX);}
        AX=0x90b0;push(&w,AX);AX=30;multiply(&w,word(&w,ss,(uint16_t)(BP-2)));name_offset(&w);push(&w,AX);if(!helper(&w,0x0698,3))goto done;w.sp=(uint16_t)(w.sp+4);CF=0;if(AX==0){AX=word(&w,ss,(uint16_t)(BP-2));wr(&w,0x8cfe,AX);}v=(uint16_t)(BP-2);put(&w,ss,v,(uint16_t)(word(&w,ss,v)+1));
    }
    v=rd(&w,0x9266);CF=0;if(signed_word(v)<0)wr(&w,0x9266,0);
    AX=30;multiply(&w,rd(&w,0x9266));name_offset(&w);push(&w,AX);AX=0x8428;push(&w,AX);if(!helper(&w,0x06d1,1))goto done;w.sp=(uint16_t)(w.sp+4);CF=0;
    AX=30;multiply(&w,rd(&w,0x9266));BX=AX;AX=rd(&w,(uint16_t)(BX+0x8d3e));wr(&w,0x8a82,AX);
    v=rd(&w,0x8cfe);CF=0;if(signed_word(v)<0){v=rd(&w,0x8a7a);CF=(uint16_t)(v<1);wr(&w,0x8cfe,(uint16_t)(signed_word(v)>1?1:0));}
    AX=30;multiply(&w,rd(&w,0x8cfe));name_offset(&w);push(&w,AX);AX=0x90b0;push(&w,AX);if(!helper(&w,0x0714,1))goto done;w.sp=(uint16_t)(w.sp+4);CF=0;
    AX=30;multiply(&w,rd(&w,0x8cfe));BX=AX;AX=rd(&w,(uint16_t)(BX+0x8d3e));wr(&w,0x9264,AX);w.sp=BP;BP=pop(&w);out->next_ip=pop(&w);out->next_segment=pop(&w);out->status=0;
done:
    out->current_sp=w.sp;out->returned=w.r;
}
