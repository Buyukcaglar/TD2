#include "td2ega_timer_handler_bus.h"
#include <stddef.h>

typedef struct work {
    uint8_t *m;uint32_t bytes;uint16_t cs,ss,sp;
    td2ega_state_registers r;td2ega_input_flags f;
    const td2ega_timer_handler_bus_limits *caps;
    const td2ega_timer_handler_bus_services *services;
    td2ega_timer_handler_bus_result *out;
} work;
static uint32_t address(uint16_t s,uint16_t o)
{return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(work *w,uint16_t s,uint16_t o)
{uint32_t a=address(s,o);return (uint16_t)(w->m[a]|((uint16_t)w->m[(a+1)&UINT32_C(0xfffff)]<<8));}
static uint16_t rd(work *w,uint16_t o){return word(w,w->r.registers.ds,o);}
static uint8_t byte(work *w,uint16_t o){return w->m[address(w->r.registers.ds,o)];}
static void put(work *w,uint16_t s,uint16_t o,uint16_t v)
{uint32_t a=address(s,o);w->m[a]=(uint8_t)v;w->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++w->out->bus_writes;}
static void wr(work *w,uint16_t o,uint16_t v){put(w,w->r.registers.ds,o,v);}
static void wb(work *w,uint16_t o,uint8_t v)
{w->m[address(w->r.registers.ds,o)]=v;++w->out->bus_writes;}
static void push(work *w,uint16_t v){w->sp=(uint16_t)(w->sp-2);put(w,w->ss,w->sp,v);}
static uint16_t pop(work *w){uint16_t v=word(w,w->ss,w->sp);w->sp=(uint16_t)(w->sp+2);return v;}
static void sync(work *w)
{w->r.carry=(uint16_t)(w->f.word&1);w->r.registers.interrupts_enabled=(uint16_t)((w->f.word>>9)&1);w->r.registers.direction=(uint16_t)((w->f.word>>10)&1);}
static void enable(work *w,uint16_t v)
{w->f.word=(uint16_t)((w->f.word&~UINT16_C(0x200))|(v<<9));sync(w);}
static void compare(work *w,uint16_t a,uint16_t b,unsigned width)
{w->f=td2ega_input_flag_sub(w->f,a,b,width);sync(w);}
static void logic(work *w,uint16_t v,unsigned width)
{w->f=td2ega_input_flag_logic(w->f,v,width,w->services->undefined_af);sync(w);}
static uint16_t increment(work *w,uint16_t v,int decrement)
{
    uint16_t carry=(uint16_t)(w->f.word&1),mask=(uint16_t)(w->f.mask&1),result;
    result=(uint16_t)(decrement?v-1:v+1);
    w->f=decrement?td2ega_input_flag_sub(w->f,v,1,16):td2ega_input_flag_add16(w->f,v,1);
    w->f.word=(uint16_t)((w->f.word&~1)|carry);w->f.mask=(uint16_t)((w->f.mask&~1)|mask);sync(w);return result;
}
static int stop(work *w,uint16_t status,uint16_t site)
{w->out->status=status;w->out->stage=site;w->out->next_segment=w->cs;w->out->next_ip=site;return 0;}
static int budget(work *w,uint32_t *count,uint32_t cap,uint16_t site)
{w->out->stage=site;if(*count==cap)return stop(w,3,site);++*count;return 1;}
static int port(work *w,uint16_t site,uint16_t operation,uint16_t number)
{
    td2ega_music_port_request q;uint8_t value=0;
    if(!budget(w,&w->out->ports,w->caps->ports,site))return 0;
    q=(td2ega_music_port_request){operation,number,(uint8_t)w->r.registers.ax,w->r.registers.interrupts_enabled};
    if(!w->services->port(w->services->context,&q,&value))return stop(w,4,site);
    if(operation==0)w->r.registers.ax=(uint16_t)((w->r.registers.ax&0xff00)|value);
    return 1;
}
static int valid_flags(uint16_t flags,uint16_t mask,const td2ega_state_registers *r)
{
    return !(flags&~UINT16_C(0x0ed7)) && (flags&2) && (mask==0xffff || mask==0xffef) &&
        (flags&1)==r->carry && ((flags>>9)&1)==r->registers.interrupts_enabled && ((flags>>10)&1)==r->registers.direction;
}
static int external(work *w,uint16_t kind,uint16_t segment,uint16_t offset,uint16_t resume,uint16_t expected_sp)
{
    td2ega_timer_handler_bus_call q;td2ega_timer_handler_bus_return r;
    q=(td2ega_timer_handler_bus_call){kind,segment,offset,w->ss,w->sp,w->f.word,w->f.mask,0,w->r};
    r=(td2ega_timer_handler_bus_return){0};
    if(!w->services->call(w->services->context,w->m,w->bytes,&q,&r))return stop(w,4,(uint16_t)(kind?0x6259:0x6217));
    w->sp=r.current_sp;w->r=r.returned;w->out->bus_writes+=r.bus_writes;
    w->out->next_segment=r.next_segment;w->out->next_ip=r.next_ip;
    if(!valid_flags(r.flags_word,r.flags_mask,&r.returned)){w->out->status=5;return 0;}
    w->f=(td2ega_input_flags){r.flags_word,r.flags_mask};
    if(r.status!=0){w->out->status=r.status;return 0;}
    if(r.current_sp!=expected_sp || r.next_segment!=w->cs || r.next_ip!=resume){w->out->status=1;return 0;}
    return 1;
}
static int bridge(work *w)
{
    uint16_t v,expected,segment,offset,saved_flags;
    if(!budget(w,&w->out->steps,w->caps->steps,0x6230))return 0;
    compare(w,byte(w,0x5e94),0,8);
    if(byte(w,0x5e94)!=0){
        v=rd(w,0x5e96);wr(w,0x5e96,increment(w,v,1));
        if(!(v>1 && v<0x8000)){wb(w,0x5e94,0);wb(w,0x5e95,0);}
    }
    w->r.registers.ax=0;logic(w,0,16);w->r.registers.es=0;
    w->r.registers.ax=rd(w,0x5e88);put(w,w->r.registers.es,0x20,w->r.registers.ax);
    w->r.registers.ax=rd(w,0x5e8a);put(w,w->r.registers.es,0x22,w->r.registers.ax);
    if(!budget(w,&w->out->calls,w->caps->calls,0x6259))return 0;
    expected=w->sp;saved_flags=w->f.word;
    push(w,saved_flags);push(w,w->cs);push(w,0x625b);enable(w,0);++w->out->old_interrupts;
    /* Explicit real-address INT profile: vector read after frame writes. */
    segment=word(w,0,0x22);offset=word(w,0,0x20);
    if(!external(w,1,segment,offset,0x625b,expected))return 0;
    w->r.registers.ax=0x61bf;put(w,w->r.registers.es,0x20,w->r.registers.ax);
    w->r.registers.ax=w->cs;put(w,w->r.registers.es,0x22,w->r.registers.ax);
    w->out->next_ip=pop(w);w->out->next_segment=w->cs;return 1;
}
void td2ega_timer_handler_bus(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,uint16_t sp,uint16_t entry,uint16_t flags,uint16_t mask,const td2ega_state_registers *in,const td2ega_timer_handler_bus_limits *caps,const td2ega_timer_handler_bus_services *services,td2ega_timer_handler_bus_result *out)
{
    work w;uint16_t v,at,expected,segment,offset,raw;
    if(out==NULL)return;*out=(td2ega_timer_handler_bus_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || caps==NULL || services==NULL || services->port==NULL || services->call==NULL || services->undefined_af>1 || entry>1 || !valid_flags(flags,mask,in) || (entry==0 && (sp<68 || sp>0xffe0)) || (entry==1 && (sp<6 || sp>0xfffa)))return;
    w=(work){m,bytes,(uint16_t)(load+0x6c9),ss,sp,*in,{flags,mask},caps,services,out};
    if(entry==1){if(bridge(&w))out->status=0;goto done;}
    if(!budget(&w,&out->steps,caps->steps,0x61bf))goto done;
    enable(&w,0);push(&w,w.r.registers.ds);push(&w,w.r.registers.es);push(&w,w.r.registers.ax);push(&w,w.r.registers.bx);push(&w,w.r.registers.cx);push(&w,w.r.registers.dx);push(&w,w.r.registers.si);push(&w,w.r.registers.di);push(&w,w.r.bp);
    w.r.registers.ax=(uint16_t)((w.r.registers.ax&0xff00)|0x20);
    if(!port(&w,0x61cb,1,0x20))goto done;
    w.r.registers.ax=(uint16_t)(load+0x178f);w.r.registers.ds=w.r.registers.ax;enable(&w,1);
    v=rd(&w,0x5e9a);wr(&w,0x5e9a,increment(&w,v,1));
    if(!(v>1 && v<0x8000)){
        v=increment(&w,rd(&w,0x5e90),0);wr(&w,0x5e90,v);if(v==0)wr(&w,0x5e92,increment(&w,rd(&w,0x5e92),0));
        w.r.registers.ax=rd(&w,0x5e98);wr(&w,0x5e9a,w.r.registers.ax);compare(&w,byte(&w,0x5e95),0,8);
        if(byte(&w,0x5e95)!=0){
            if(!budget(&w,&out->calls,caps->calls,0x61f0))goto done;
            expected=w.sp;push(&w,0x61f3);
            if(!bridge(&w))goto done;
            if(w.sp!=expected || out->next_segment!=w.cs || out->next_ip!=0x61f3){out->status=1;goto done;}
        }
    }
    compare(&w,byte(&w,0x5efe),0,8);
    if(byte(&w,0x5efe)!=0){
        if(!port(&w,0x6220,0,0x61))goto done;
        w.r.registers.ax=(uint16_t)(w.r.registers.ax&0xfffc);logic(&w,(uint8_t)w.r.registers.ax,8);
        if(!port(&w,0x6224,1,0x61))goto done;
    }else{
        w.r.registers.bx=rd(&w,0x5e9c);at=(uint16_t)(w.r.registers.bx+0x5e9e);wr(&w,at,increment(&w,rd(&w,at),0));
        v=increment(&w,rd(&w,0x5e8c),0);wr(&w,0x5e8c,v);if(v==0)wr(&w,0x5e8e,increment(&w,rd(&w,0x5e8e),0));
        w.r.registers.di=0;logic(&w,0,16);
        for(;;){
            if(!budget(&w,&out->steps,caps->steps,0x620e))goto done;
            w.r.registers.ax=rd(&w,(uint16_t)(w.r.registers.di+0x5f14));logic(&w,w.r.registers.ax,16);
            if(w.r.registers.ax==0)break;
            enable(&w,0);
            if(!budget(&w,&out->calls,caps->calls,0x6217))goto done;
            segment=rd(&w,(uint16_t)(w.r.registers.di+0x5f14));offset=rd(&w,(uint16_t)(w.r.registers.di+0x5f12));expected=w.sp;
            push(&w,w.cs);push(&w,0x621b);++out->callbacks;
            if(!external(&w,0,segment,offset,0x621b,expected))goto done;
            w.f=td2ega_input_flag_add16(w.f,w.r.registers.di,4);w.r.registers.di=(uint16_t)(w.r.registers.di+4);sync(&w);
        }
    }
    w.r.bp=pop(&w);w.r.registers.di=pop(&w);w.r.registers.si=pop(&w);w.r.registers.dx=pop(&w);w.r.registers.cx=pop(&w);w.r.registers.bx=pop(&w);w.r.registers.ax=pop(&w);w.r.registers.es=pop(&w);w.r.registers.ds=pop(&w);
    raw=word(&w,w.ss,(uint16_t)(w.sp+4));
    if((raw&~UINT16_C(0x0ed7)) || !(raw&2)){stop(&w,5,0x622f);goto done;}
    out->next_ip=pop(&w);out->next_segment=pop(&w);w.f=(td2ega_input_flags){pop(&w),0xffff};sync(&w);out->status=0;
done:
    out->current_sp=w.sp;out->returned=w.r;out->flags_word=w.f.word;out->flags_mask=w.f.mask;
}
