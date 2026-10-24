#include "td2ega_effect_tick_bus.h"
#include <stddef.h>
typedef struct work {
    uint8_t *m;uint16_t cs,ss,sp;td2ega_state_registers r;td2ega_input_flags f;
    td2ega_music_port_service port;void *context;uint32_t max_steps,max_ports;
    td2ega_effect_tick_bus_result *out;
} work;
static uint32_t address(uint16_t s,uint16_t o){return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint8_t byte(work *w,uint16_t s,uint16_t o){return w->m[address(s,o)];}
static uint16_t word(work *w,uint16_t s,uint16_t o)
{uint32_t a=address(s,o);return (uint16_t)(w->m[a]|((uint16_t)w->m[(a+1)&UINT32_C(0xfffff)]<<8));}
static uint16_t rd(work *w,uint16_t o){return word(w,w->r.registers.ds,o);}
static uint8_t rb(work *w,uint16_t o){return byte(w,w->r.registers.ds,o);}
static void put(work *w,uint16_t o,uint16_t v,unsigned width)
{uint32_t a=address(w->r.registers.ds,o);w->m[a]=(uint8_t)v;if(width==2)w->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++w->out->bus_writes;}
static void sync(work *w){w->r.carry=(uint16_t)(w->f.word&1);}
static void logic(work *w,uint16_t v,unsigned width){w->f=td2ega_input_flag_logic(w->f,v,width,0);sync(w);}
static void cmp(work *w,uint16_t a,uint16_t b,unsigned width){w->f=td2ega_input_flag_sub(w->f,a,b,width);sync(w);}
static uint16_t add(work *w,uint16_t a,uint16_t b){w->f=td2ega_input_flag_add16(w->f,a,b);sync(w);return (uint16_t)(a+b);}
static uint16_t change(work *w,uint16_t v,int decrement)
{
    uint16_t cf=(uint16_t)(w->f.word&1),mask=(uint16_t)(w->f.mask&1);
    w->f=decrement?td2ega_input_flag_sub(w->f,v,1,16):td2ega_input_flag_add16(w->f,v,1);
    w->f.word=(uint16_t)((w->f.word&~1)|cf);w->f.mask=(uint16_t)((w->f.mask&~1)|mask);sync(w);return (uint16_t)(decrement?v-1:v+1);
}
static void shl(work *w){uint16_t old=w->r.registers.bx;w->r.registers.bx=(uint16_t)(old<<1);w->f=td2ega_input_flag_shl1(w->f,old,0);sync(w);}
static uint16_t low(uint16_t v,uint8_t b){return (uint16_t)((v&0xff00)|b);}
static int stop(work *w,uint16_t status,uint16_t site)
{w->out->status=status;w->out->halt_site=site;w->out->next_segment=w->cs;w->out->next_ip=site;return 0;}
static int step(work *w,uint16_t site)
{if(w->out->steps==w->max_steps)return stop(w,3,site);++w->out->steps;return 1;}
static int io(work *w,uint16_t site,uint16_t operation,uint16_t number)
{
    td2ega_music_port_request q;uint8_t value=0;
    if(w->out->ports==w->max_ports)return stop(w,3,site);++w->out->ports;
    q=(td2ega_music_port_request){operation,number,(uint8_t)w->r.registers.ax,w->r.registers.interrupts_enabled};
    if(!w->port(w->context,&q,&value))return stop(w,4,site);
    if(operation==0)w->r.registers.ax=low(w->r.registers.ax,value);return 1;
}
#define AX w.r.registers.ax
#define BX w.r.registers.bx
#define CX w.r.registers.cx
#define B(o) rb(&w,UINT16_C(o))
#define W(o) rd(&w,UINT16_C(o))
#define PB(o,v) put(&w,UINT16_C(o),(uint8_t)(v),1)
#define PW(o,v) put(&w,UINT16_C(o),(uint16_t)(v),2)
#define IO(site,op,p) do{if(!io(&w,(site),(op),(p)))goto done;}while(0)
void td2ega_effect_tick_bus(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,uint16_t sp,uint16_t flags,uint16_t mask,const td2ega_state_registers *in,td2ega_music_port_service port,void *context,uint32_t max_steps,uint32_t max_ports,td2ega_effect_tick_bus_result *out)
{
    work w;uint16_t count_at=0,start_at=0,return_at=0,value,ret_site=0x6287,in_site=0x6281,out_site=0x6285;
    if(out==NULL)return;*out=(td2ega_effect_tick_bus_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || port==NULL || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1 || (flags&~UINT16_C(0x0ed7)) || !(flags&2) || (mask!=0xffff && mask!=0xffef) || (flags&1)!=in->carry || ((flags>>9)&1)!=in->registers.interrupts_enabled || ((flags>>10)&1)!=in->registers.direction)return;
    w=(work){m,(uint16_t)(load+0x6c9),ss,sp,*in,{flags,mask},port,context,max_steps,max_ports,out};
    if(!step(&w,0x6269))goto done;
    value=(uint16_t)(B(0x5efb)&1);logic(&w,value,8);
    if(value==0){PB(0x5efc,0);PW(0x5eee,0);PW(0x5ef6,0);goto silence;}
    value=W(0x5ef6);cmp(&w,value,0,16);
    if(value!=0){AX=W(0x5ef6);PW(0x5ef6,change(&w,W(0x5ef6),1));value=W(0x5ef8);cmp(&w,AX,value,16);if(AX==value){ret_site=0x62a2;in_site=0x629c;out_site=0x62a0;goto silence;}goto returned;}
event:
    if(!step(&w,0x62b7))goto done;AX=W(0x5eee);logic(&w,AX,16);if(AX==0)goto queue;
    w.r.registers.es=AX;w.r.registers.si=W(0x5ef0);BX=low(BX,byte(&w,w.r.registers.es,w.r.registers.si));logic(&w,(uint8_t)BX,8);
    if((uint8_t)BX>=0x80){
        value=(uint8_t)BX;BX=low(BX,(uint8_t)(0-value));w.f=td2ega_input_flag_sub(w.f,0,value,8);sync(&w);
        BX=(uint8_t)BX;logic(&w,0,8);cmp(&w,BX,11,16);if(BX>11)goto queue;shl(&w);
        value=word(&w,w.cs,(uint16_t)(0x6334+BX));out->raw_target=value;
        switch(value){
        case 0x62fd:goto queue;
        case 0x634c:AX=low(AX,byte(&w,w.r.registers.es,(uint16_t)(w.r.registers.si+1)));PB(0x5efa,AX);PW(0x5ef0,add(&w,W(0x5ef0),2));goto event;
        case 0x635b:count_at=0x5f00;start_at=0x5f06;goto begin_loop;
        case 0x6370:count_at=0x5f02;start_at=0x5f08;goto begin_loop;
        case 0x6385:count_at=0x5f04;start_at=0x5f0a;goto begin_loop;
        case 0x639a:count_at=0x5f00;start_at=0x5f06;return_at=0x5f0c;goto repeat_loop;
        case 0x63b4:count_at=0x5f02;start_at=0x5f08;return_at=0x5f0e;goto repeat_loop;
        case 0x63ce:count_at=0x5f04;start_at=0x5f0a;return_at=0x5f10;goto repeat_loop;
        case 0x63e8:count_at=0x5f00;return_at=0x5f0c;goto return_loop;
        case 0x63ff:count_at=0x5f02;return_at=0x5f0e;goto return_loop;
        case 0x6416:count_at=0x5f04;return_at=0x5f10;goto return_loop;
        default:stop(&w,6,0x632f);goto done;
        }
    }
    AX=word(&w,w.r.registers.es,(uint16_t)(w.r.registers.si+1));PW(0x5ef6,AX);PW(0x5ef0,add(&w,W(0x5ef0),3));logic(&w,(uint8_t)BX,8);
    ret_site=0x62fc;
    if((uint8_t)BX==0){PW(0x5ef8,0);in_site=0x62ae;out_site=0x62b2;goto silence;}
    CX=low(CX,B(0x5efa));logic(&w,(uint8_t)CX,8);
    if((uint8_t)CX==0){AX=0;logic(&w,0,16);}else{unsigned shift=(uint8_t)CX&31u;AX=shift>=16u?0:(uint16_t)(AX>>shift);}
    /* SHR flags have no consumer before XOR BH,BH defines them. */
    PW(0x5ef8,AX);BX=(uint8_t)BX;logic(&w,0,8);shl(&w);AX=word(&w,w.r.registers.ds,(uint16_t)(0x5f2e+BX));
    IO(0x62f0,1,0x42);AX=(uint16_t)((AX<<8)|(AX>>8));IO(0x62f4,1,0x42);IO(0x62f6,0,0x61);AX=low(AX,(uint8_t)(AX|3));logic(&w,(uint8_t)AX,8);IO(0x62fa,1,0x61);goto returned;
begin_loop:
    AX=word(&w,w.r.registers.es,(uint16_t)(w.r.registers.si+1));put(&w,count_at,AX,2);PW(0x5ef0,add(&w,W(0x5ef0),3));AX=W(0x5ef0);put(&w,start_at,AX,2);goto event;
repeat_loop:
    value=change(&w,rd(&w,count_at),1);put(&w,count_at,value,2);
    if(!(value&0x8000)){put(&w,return_at,w.r.registers.si,2);AX=rd(&w,start_at);PW(0x5ef0,AX);goto event;}
    PW(0x5ef0,change(&w,W(0x5ef0),0));goto event;
return_loop:
    value=rd(&w,count_at);cmp(&w,value,0,16);if(value==0){AX=rd(&w,return_at);PW(0x5ef0,AX);goto event;}PW(0x5ef0,change(&w,W(0x5ef0),0));goto event;
queue:
    PB(0x5efc,0);value=B(0x5efd);cmp(&w,value,0,8);
    if(value!=0){AX=W(0x5ef4);PW(0x5ef0,AX);AX=W(0x5ef2);PW(0x5eee,AX);goto event;}
    PW(0x5ef6,0);ret_site=0x6323;in_site=0x631d;out_site=0x6321;
silence:
    IO(in_site,0,0x61);AX=low(AX,(uint8_t)(AX&0xfc));logic(&w,(uint8_t)AX,8);IO(out_site,1,0x61);
returned:
    out->halt_site=ret_site;
    if(w.sp>0xfffc){stop(&w,5,ret_site);goto done;}
    out->next_ip=word(&w,w.ss,w.sp);w.sp=(uint16_t)(w.sp+2);out->next_segment=word(&w,w.ss,w.sp);w.sp=(uint16_t)(w.sp+2);out->status=0;
done:
    out->current_sp=w.sp;out->returned=w.r;out->flags_word=w.f.word;out->flags_mask=w.f.mask;
}
