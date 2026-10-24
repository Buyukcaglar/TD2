#include "td2ega_timer_control_bus.h"
#include <stddef.h>
typedef struct work {
    uint8_t *m;uint16_t cs,ss,sp;td2ega_state_registers r;td2ega_input_flags f;
    td2ega_music_port_service port;void *context;uint32_t max_steps,max_ports;
    td2ega_timer_control_bus_result *out;
} work;
static uint32_t address(uint16_t s,uint16_t o){return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(work *w,uint16_t s,uint16_t o)
{uint32_t a=address(s,o);return (uint16_t)(w->m[a]|((uint16_t)w->m[(a+1)&UINT32_C(0xfffff)]<<8));}
static uint16_t rd(work *w,uint16_t o){return word(w,w->r.registers.ds,o);}
static void put(work *w,uint16_t s,uint16_t o,uint16_t v,unsigned width)
{uint32_t a=address(s,o);w->m[a]=(uint8_t)v;if(width==2)w->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++w->out->bus_writes;}
static void wr(work *w,uint16_t o,uint16_t v){put(w,w->r.registers.ds,o,v,2);}
static void wb(work *w,uint16_t o,uint8_t v){put(w,w->r.registers.ds,o,v,1);}
static void push(work *w,uint16_t v){w->sp=(uint16_t)(w->sp-2);put(w,w->ss,w->sp,v,2);}
static uint16_t pop(work *w){uint16_t v=word(w,w->ss,w->sp);w->sp=(uint16_t)(w->sp+2);return v;}
static void sync(work *w)
{w->r.carry=(uint16_t)(w->f.word&1);w->r.registers.interrupts_enabled=(uint16_t)((w->f.word>>9)&1);w->r.registers.direction=(uint16_t)((w->f.word>>10)&1);}
static void enable(work *w,uint16_t v){w->f.word=(uint16_t)((w->f.word&~0x200)|(v<<9));sync(w);}
static void logic(work *w,uint16_t v,unsigned width){w->f=td2ega_input_flag_logic(w->f,v,width,0);sync(w);}
static void cmp(work *w,uint16_t a,uint16_t b){w->f=td2ega_input_flag_sub(w->f,a,b,16);sync(w);}
static uint16_t add(work *w,uint16_t a,uint16_t b){w->f=td2ega_input_flag_add16(w->f,a,b);sync(w);return (uint16_t)(a+b);}
static int stop(work *w,uint16_t status,uint16_t site)
{w->out->status=status;w->out->halt_site=site;w->out->next_segment=w->cs;w->out->next_ip=site;return 0;}
static int step(work *w,uint16_t site){if(w->out->steps==w->max_steps)return stop(w,3,site);++w->out->steps;return 1;}
static int io(work *w,uint16_t site,uint16_t operation,uint16_t number)
{
    td2ega_music_port_request q;uint8_t value=0;
    if(w->out->ports==w->max_ports)return stop(w,3,site);++w->out->ports;
    q=(td2ega_music_port_request){operation,number,(uint8_t)w->r.registers.ax,w->r.registers.interrupts_enabled};
    if(!w->port(w->context,&q,&value))return stop(w,4,site);
    if(operation==0)w->r.registers.ax=(uint16_t)((w->r.registers.ax&0xff00)|value);return 1;
}
#define AX w.r.registers.ax
#define BX w.r.registers.bx
#define CX w.r.registers.cx
#define DX w.r.registers.dx
#define ES w.r.registers.es
#define IO(site,op,p) do{if(!io(&w,(site),(op),(p)))goto done;}while(0)
void td2ega_timer_control_bus(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,uint16_t sp,uint16_t entry,uint16_t flags,uint16_t mask,const td2ega_state_registers *in,td2ega_music_port_service port,void *context,uint32_t max_steps,uint32_t max_ports,td2ega_timer_control_bus_result *out)
{
    work w;uint16_t v,ret_site=0x6109;int32_t divisor,q,rem;
    if(out==NULL)return;*out=(td2ega_timer_control_bus_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || port==NULL || entry>2 || (entry<2 && sp<2) || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1 || (flags&~UINT16_C(0x0ed7)) || !(flags&2) || (mask!=0xffff && mask!=0xffef && mask!=0xf72b && mask!=0xf72a) || (flags&1)!=in->carry || ((flags>>9)&1)!=in->registers.interrupts_enabled || ((flags>>10)&1)!=in->registers.direction)return;
    w=(work){m,(uint16_t)(load+0x6c9),ss,sp,*in,{flags,mask},port,context,max_steps,max_ports,out};
    if(!step(&w,(uint16_t)(entry==0?0x601c:entry==1?0x6059:0x610a)))goto done;
    if(entry==2)goto cleanup;
    push(&w,w.r.bp);w.r.bp=w.sp;
    if(entry==0){DX=0x2e9c;wr(&w,0x5e98,5);wr(&w,0x5e9a,5);wr(&w,0x5e96,100);wb(&w,0x5e94,1);}
    else{
        DX=1;AX=0;logic(&w,0,16);v=word(&w,w.ss,(uint16_t)(w.r.bp+6));out->initial_divisor=v;divisor=(v&0x8000)?(int32_t)v-65536:(int32_t)v;
        if(divisor==0){stop(&w,6,0x6061);goto done;}q=65536/divisor;
        if(q<(-32767-1) || q>32767){stop(&w,6,0x6061);goto done;}
        rem=65536-q*divisor;AX=(uint16_t)q;DX=(uint16_t)rem;out->quotient=AX;
        w.f.mask=(uint16_t)(w.f.mask&~TD2EGA_INPUT_ARITH_FLAGS);sync(&w);
        wr(&w,0x5e98,AX);wr(&w,0x5e9a,AX);DX=word(&w,w.ss,(uint16_t)(w.r.bp+6));wb(&w,0x5e94,0);wb(&w,0x5e95,1);
    }
    enable(&w,0);wr(&w,0x5f12,0);wr(&w,0x5f14,0);enable(&w,1);
    IO(0x60a7,0,0x61);AX=(uint16_t)(AX&0xfffc);logic(&w,(uint8_t)AX,8);IO(0x60ab,1,0x61);AX=(uint16_t)((AX&0xff00)|0xb6);IO(0x60af,1,0x43);
    IO(0x60b1,0,0x21);AX=(uint16_t)((AX&0xff00)|((uint8_t)AX|3));logic(&w,(uint8_t)AX,8);IO(0x60b5,1,0x21);
    BX=0;wr(&w,0x5e9c,0);CX=40;
    do{if(!step(&w,0x60c3))goto done;wr(&w,(uint16_t)(BX+0x5e9e),0);BX=add(&w,BX,2);CX=(uint16_t)(CX-1);}while(CX!=0);
    AX=0;ES=0;enable(&w,0);AX=word(&w,ES,0x20);cmp(&w,AX,0x61bf);if(AX!=0x61bf)wr(&w,0x5e88,AX);
    AX=word(&w,ES,0x22);BX=w.cs;cmp(&w,AX,BX);
    if(AX!=BX){wr(&w,0x5e8a,AX);put(&w,ES,0x20,0x61bf,2);put(&w,ES,0x22,w.cs,2);}
    IO(0x60f9,0,0x21);AX=(uint16_t)(AX&0xfffc);logic(&w,(uint8_t)AX,8);IO(0x60fd,1,0x21);enable(&w,1);
    AX=(uint16_t)((AX&0xff00)|(uint8_t)DX);IO(0x6102,1,0x40);AX=(uint16_t)((AX&0xff00)|(uint8_t)(DX>>8));IO(0x6106,1,0x40);w.r.bp=pop(&w);goto returned;
cleanup:
    AX=0;logic(&w,0,16);ES=0;AX=word(&w,ES,0x22);DX=w.cs;cmp(&w,AX,DX);if(AX!=DX){ret_site=0x6118;goto returned;}
    AX=word(&w,ES,0x20);cmp(&w,AX,0x61bf);if(AX!=0x61bf){ret_site=0x6122;goto returned;}
    IO(0x6123,0,0x21);AX=(uint16_t)((AX&0xff00)|((uint8_t)AX|3));logic(&w,(uint8_t)AX,8);IO(0x6127,1,0x21);enable(&w,0);
    AX=rd(&w,0x5e88);put(&w,ES,0x20,AX,2);AX=rd(&w,0x5e8a);put(&w,ES,0x22,AX,2);
    IO(0x6138,0,0x21);AX=(uint16_t)(AX&0xfffc);logic(&w,(uint8_t)AX,8);IO(0x613c,1,0x21);enable(&w,1);AX=(uint16_t)(AX&0xff00);IO(0x6141,1,0x40);IO(0x6143,1,0x40);
    IO(0x6145,0,0x61);AX=(uint16_t)(AX&0xfffc);logic(&w,(uint8_t)AX,8);IO(0x6149,1,0x61);ret_site=0x614b;
returned:
    out->halt_site=ret_site;if(w.sp>0xfffc){stop(&w,5,ret_site);goto done;}
    out->next_ip=pop(&w);out->next_segment=pop(&w);out->status=0;
done:
    out->current_sp=w.sp;out->returned=w.r;out->flags_word=w.f.word;out->flags_mask=w.f.mask;
}
