#include "td2ega_wait_roots.h"
#include <stddef.h>
typedef struct context {
    uint8_t *m;uint16_t load,ss,sp,cs;uint32_t limit;
    td2ega_state_registers r;td2ega_input_bridge_service input;
    td2ega_wait_roots_observer observer;void *user;
    td2ega_wait_roots_result *out;int invalid_control;
} context;
static uint32_t address(uint16_t s,uint16_t o)
{return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(const uint8_t *m,uint16_t s,uint16_t o)
{uint32_t a=address(s,o);return (uint16_t)(m[a]|((uint16_t)m[(a+1)&UINT32_C(0xfffff)]<<8));}
static void put(context *c,uint16_t s,uint16_t o,uint16_t v)
{uint32_t a=address(s,o);c->m[a]=(uint8_t)v;c->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++c->out->bus_writes;}
static void push(context *c,uint16_t v)
{c->sp=(uint16_t)(c->sp-2);put(c,c->ss,c->sp,v);}
static uint16_t pop(context *c)
{uint16_t v=word(c->m,c->ss,c->sp);c->sp=(uint16_t)(c->sp+2);return v;}
static int input_service(void *user,uint8_t *m,const td2ega_input_bridge_request *q,
    td2ega_input_bridge_response *response)
{
    context *c=(context *)user;
    if(q->kind!=1){c->invalid_control=1;return 0;}
    put(c,q->stack_segment,q->stack_sp,0x6a02);put(c,q->stack_segment,(uint16_t)(q->stack_sp+2),c->cs);++c->out->dynamic_calls;
    if(!c->input(c->user,m,q,response))return 0;
    if(word(m,q->stack_segment,q->stack_sp)!=0x6a02 || word(m,q->stack_segment,(uint16_t)(q->stack_sp+2))!=c->cs){c->invalid_control=1;return 0;}
    return 1;
}
static int call(context *c,uint16_t site,uint16_t target)
{
    uint16_t ret=(uint16_t)(site+5),frame,returned_ip,returned_cs;
    if(c->out->events==c->limit){c->out->status=3;return 0;}
    ++c->out->events;push(c,c->cs);push(c,ret);frame=c->sp;
    if(target==0x69fe){
        td2ega_input_bridge_result child;++c->out->input_calls;
        td2ega_input_bridge(c->m,UINT32_C(0x100000),c->load,c->ss,c->sp,TD2EGA_INPUT_CALL,&c->r,input_service,c,1,&child);
        c->r=child.returned;c->sp=child.current_sp;
        if(child.status!=0){c->out->status=(uint16_t)(c->invalid_control?2:child.status);return 0;}
        returned_ip=word(c->m,c->ss,frame);returned_cs=word(c->m,c->ss,(uint16_t)(frame+2));
    }else{
        td2ega_wait_roots_counter_request q={0};++c->out->counter_calls;q.site=site;q.segment=c->cs;q.offset=target;q.stack_segment=c->ss;q.stack_sp=c->sp;q.incoming=c->r;
        if(!c->observer(c->user,c->m,&q)){c->out->status=4;return 0;}
        if(target==0x79c8){
            td2ega_wait_result child;td2ega_counter_snapshot(c->m,UINT32_C(0x100000),&c->r,&child);c->r=child.returned;
            if(child.status!=0){c->out->status=child.status;return 0;}
            returned_ip=pop(c);returned_cs=pop(c);
        }else{
            td2ega_small_state_result child;td2ega_small_state(c->m,UINT32_C(0x100000),c->load,c->ss,c->sp,4,&c->r,&child);c->r=child.returned;c->sp=child.current_sp;c->out->bus_writes+=child.writes;
            if(child.status!=0){c->out->status=child.status;return 0;}
            returned_ip=child.next_ip;returned_cs=child.next_segment;
        }
    }
    if(returned_ip!=ret || returned_cs!=c->cs){c->out->status=1;c->out->next_ip=returned_ip;c->out->next_segment=returned_cs;return 0;}
    return 1;
}
void td2ega_wait_roots(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,
    uint16_t sp,uint16_t entry,const td2ega_state_registers *in,
    td2ega_input_bridge_service input,td2ega_wait_roots_observer observer,
    void *user,uint32_t limit,td2ega_wait_roots_result *out)
{
    context c;uint16_t high,low;
    if(out==NULL)return;
    *out=(td2ega_wait_roots_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || entry>3 || sp<512 || sp>UINT16_C(0xffe0) || (entry!=2 && input==NULL) || (entry!=0 && observer==NULL) || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1)return;
    c=(context){m,load,ss,sp,(uint16_t)(load+0x6c9),limit,*in,input,observer,user,out,0};
#define R c.r.registers
#define CALL(site,target) do{if(!call(&c,site,target))goto finish;}while(0)
#define W(offset) word(c.m,R.ds,offset)
    if(entry==2){
        CALL(0x7a3b,0x79c8);high=W(0x681a);c.r.carry=(uint16_t)(R.dx<high);
        if(R.dx<high){R.ax=0;c.r.carry=0;goto returned;}
        if(R.dx>high){R.ax=1;goto returned;}
        low=W(0x6818);c.r.carry=(uint16_t)(R.ax<low);if(R.ax<low){R.ax=0;c.r.carry=0;}else R.ax=1;goto returned;
    }
loop:
    CALL(entry==0?0x6a30:entry==1?0x6a4a:0xc63e,0x69fe);c.r.carry=0;if(R.ax!=0)goto returned;
    if(entry==0)goto loop;
    CALL(entry==1?0x6a54:0xc648,entry==1?0x79c8:0xc692);high=W(entry==1?0x681a:0x68d8);c.r.carry=(uint16_t)(R.dx<high);if(R.dx<high)goto loop;
    if(entry==1 && R.dx>high){R.ax=0;c.r.carry=0;goto returned;}
    low=W(entry==1?0x6818:0x68d6);c.r.carry=(uint16_t)(R.ax<low);if(R.ax<low)goto loop;R.ax=0;c.r.carry=0;
returned:
    out->next_ip=pop(&c);out->next_segment=pop(&c);out->status=0;
finish:
    out->current_sp=c.sp;out->returned=c.r;
#undef R
#undef CALL
#undef W
}
