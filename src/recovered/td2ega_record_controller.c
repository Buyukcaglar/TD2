#include "td2ega_record_controller.h"
#include <stddef.h>
typedef struct work {uint8_t *m;uint32_t bytes;uint16_t load,cs,ss,sp;uint32_t limit,child_limit;td2ega_state_registers r;uint16_t flags,mask;td2ega_record_controller_result *o;} work;
static uint32_t address(uint16_t s,uint16_t o){return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(work *w,uint16_t s,uint16_t o){uint32_t a=address(s,o);return (uint16_t)(w->m[a]|((uint16_t)w->m[(a+1)&UINT32_C(0xfffff)]<<8));}
static uint16_t rd(work *w,uint16_t o){return word(w,w->r.registers.ds,o);}
static uint8_t byte(work *w,uint16_t o){return w->m[address(w->r.registers.ds,o)];}
static void put(work *w,uint16_t s,uint16_t o,uint16_t v,unsigned n){uint32_t a=address(s,o);w->m[a]=(uint8_t)v;if(n==2)w->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++w->o->bus_writes;}
static void wr(work *w,uint16_t o,uint16_t v){put(w,w->r.registers.ds,o,v,2);}
static void wb(work *w,uint16_t o,uint16_t v){put(w,w->r.registers.ds,o,v,1);}
static void push(work *w,uint16_t v){w->sp=(uint16_t)(w->sp-2);put(w,w->ss,w->sp,v,2);}
static uint16_t pop(work *w){uint16_t v=word(w,w->ss,w->sp);w->sp=(uint16_t)(w->sp+2);return v;}
static int32_t sw(uint16_t v){return v&0x8000?(int32_t)v-65536:(int32_t)v;}
static uint16_t add(work *w,uint16_t a,uint16_t b){uint32_t v=(uint32_t)a+b;w->r.carry=(uint16_t)(v>65535);return (uint16_t)v;}
static uint16_t sub(work *w,uint16_t a,uint16_t b){w->r.carry=(uint16_t)(a<b);return (uint16_t)(a-b);}
static void cmp(work *w,uint16_t a,uint16_t b){w->r.carry=(uint16_t)(a<b);}
static int step(work *w,uint16_t ip){if(w->o->steps==w->limit){w->o->status=3;w->o->next_segment=w->cs;w->o->next_ip=ip;return 0;}++w->o->steps;return 1;}
static int call(work *w,uint16_t site,uint16_t selector)
{
    td2ega_record_flags_result view;td2ega_record_math_result result;uint16_t expected=w->sp,ret=(uint16_t)(site+3);
    if(!step(w,site))return 0;
    ++w->o->calls;push(w,ret);
    if(selector==3){td2ega_record_flags(w->m,w->bytes,w->load,w->ss,w->sp,&w->r,w->child_limit,&view);result=view.body;w->flags=view.defined_flags;w->mask=view.defined_mask;if(site==0x4e1d)w->o->first_return_site=view.return_site;}
    else{td2ega_record_math(w->m,w->bytes,w->load,w->ss,w->sp,selector,&w->r,w->child_limit,&result);w->flags=(uint16_t)(2|result.returned.carry|(result.returned.registers.interrupts_enabled<<9)|(result.returned.registers.direction<<10));w->mask=0x603;}
    w->r=result.returned;w->sp=result.current_sp;w->o->child_iterations+=result.iterations;w->o->bus_writes+=result.bus_writes;w->o->next_segment=result.next_segment;w->o->next_ip=result.next_ip;if(result.status!=0){w->o->status=result.status;return 0;}if(result.next_segment!=w->cs || result.next_ip!=ret || w->sp!=expected){w->o->status=1;return 0;}return 1;
}
#define AX w.r.registers.ax
#define BX w.r.registers.bx
#define CX w.r.registers.cx
#define DX w.r.registers.dx
#define SI w.r.registers.si
#define DI w.r.registers.di
#define BP w.r.bp
#define CF w.r.carry
void td2ega_record_controller(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,uint16_t sp,const td2ega_state_registers *in,uint16_t undefined_af,uint32_t limit,uint32_t child_limit,td2ega_record_controller_result *out)
{
    work w;uint16_t v,image;uint8_t b;
    if(out==NULL)return;
    *out=(td2ega_record_controller_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || sp<20 || sp>UINT16_C(0xffe0) || undefined_af>1 || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1)return;
    w=(work){m,bytes,load,(uint16_t)(load+0x6c9),ss,sp,limit,child_limit,*in,0,0,out};SI=0;CF=0;
    do{
        if(!step(&w,0x4d41))goto finish;
        CX=rd(&w,(uint16_t)(SI+0x3817));BX=rd(&w,(uint16_t)(SI+0x3815));CX=sub(&w,CX,rd(&w,0x8432));if(CF){CX=(uint16_t)((CX&255)|((uint16_t)(uint8_t)((CX>>8)+1)<<8));BX=(uint16_t)(BX-1);cmp(&w,BX,0x3b51);if(BX<0x3b51)BX=add(&w,BX,rd(&w,0x380d));}wr(&w,(uint16_t)(SI+0x3817),CX);wr(&w,(uint16_t)(SI+0x3815),BX);AX=rd(&w,(uint16_t)(SI+0x3819));v=rd(&w,(uint16_t)(SI+0x3813));cmp(&w,v,6);
        if(v!=6){CF=0;if((byte(&w,(uint16_t)(BX-8))&0x80)!=0){CF=0;if(byte(&w,0x37f6)!=0){AX=sub(&w,AX,20);cmp(&w,AX,0xfda8);if(sw(AX)<=-600)AX=0xfda8;goto first_angle;}}}
        AX=add(&w,AX,20);cmp(&w,AX,0xff38);if(sw(AX)>=-200)AX=0xff38;
first_angle:
        wr(&w,(uint16_t)(SI+0x3819),AX);SI=add(&w,SI,8);v=rd(&w,0x5354);cmp(&w,SI,v);
    }while(SI!=v);
    SI=0;CF=0;
    do{
        if(!step(&w,0x4da3))goto finish;
        CX=rd(&w,(uint16_t)(SI+0x39a7));BX=rd(&w,(uint16_t)(SI+0x39a5));CX=add(&w,CX,rd(&w,0x8432));CF=0;if((CX>>8)!=0){CX=(uint16_t)((CX&255)|((uint16_t)(uint8_t)((CX>>8)-1)<<8));BX=(uint16_t)(BX+1);v=rd(&w,0x3811);cmp(&w,BX,v);if(BX>=v)BX=sub(&w,BX,rd(&w,0x380d));}wr(&w,(uint16_t)(SI+0x39a7),CX);wr(&w,(uint16_t)(SI+0x39a5),BX);AX=rd(&w,(uint16_t)(SI+0x39a9));v=rd(&w,(uint16_t)(SI+0x39a3));cmp(&w,v,6);
        if(v!=6){CF=0;if((byte(&w,BX)&0x80)!=0){AX=add(&w,AX,20);cmp(&w,AX,600);if(sw(AX)>=600)AX=600;goto second_angle;}}
        AX=sub(&w,AX,20);cmp(&w,AX,200);if(sw(AX)<=200)AX=200;
second_angle:
        wr(&w,(uint16_t)(SI+0x39a9),AX);SI=add(&w,SI,8);v=rd(&w,0x5356);cmp(&w,SI,v);
    }while(SI!=v);
    wb(&w,0x33b4,0);wb(&w,0x33b9,0);SI=rd(&w,0x330c);DI=rd(&w,0x3332);BP=0x3813;CX=rd(&w,0x5354);AX=rd(&w,0x52c8);DX=rd(&w,0x52ca);if(!call(&w,0x4e1d,3))goto finish;AX=rd(&w,0x330c);wr(&w,0x330c,SI);image=(uint16_t)((w.flags&w.mask)|((undefined_af?0x10:0)&(uint16_t)~w.mask));push(&w,image);++out->flag_words_written;cmp(&w,AX,SI);
    if(AX!=SI){
        CF=0;if(SI==0)SI=CX;SI=sub(&w,SI,8);v=rd(&w,(uint16_t)(SI+0x3813));cmp(&w,v,4);if(v==4){v=rd(&w,0x52da);CF=0;if(v==0){b=byte(&w,0x52cf);cmp(&w,b,0x46);if(b>0x46){AX=rd(&w,0x52ce);wr(&w,0x3354,AX);wb(&w,0x33b7,1);if(!call(&w,0x4e55,2))goto finish;}}}
    }
    image=word(&w,ss,w.sp);out->last_pop_flags=image;if(image&0x7100){out->status=5;out->next_segment=w.cs;out->next_ip=0x4e58;goto finish;}(void)pop(&w);CF=(uint16_t)(image&1);w.r.registers.interrupts_enabled=(uint16_t)((image>>9)&1);w.r.registers.direction=(uint16_t)((image>>10)&1);if(image&0x40)wb(&w,0x5490,2);
    b=byte(&w,0x33b7);cmp(&w,b,7);if(b==7)wb(&w,0x33b9,1);SI=rd(&w,0x330e);DI=rd(&w,0x3332);AX=rd(&w,0x52c8);DX=rd(&w,0x52ca);if(!call(&w,0x4e7b,1))goto finish;wr(&w,0x330e,SI);wb(&w,0x33b9,0);SI=rd(&w,0x330e);DI=rd(&w,0x3332);BP=0x39a3;CX=rd(&w,0x5356);AX=rd(&w,0x52c8);DX=rd(&w,0x52ca);if(!call(&w,0x4e9d,3))goto finish;wr(&w,0x330e,SI);if(w.flags&0x40)wb(&w,0x5490,2);CF=0;
    if(byte(&w,0x3379)!=0){
        b=byte(&w,0x33b5);AX=(uint16_t)((AX&0xff00)|b);wb(&w,0x33b4,b);SI=rd(&w,0x3310);DI=rd(&w,0x52d4);BP=0x3813;CX=rd(&w,0x5354);AX=rd(&w,0x52d0);DX=rd(&w,0x52d2);if(!call(&w,0x4ed1,3))goto finish;wr(&w,0x3310,SI);
        if(w.flags&0x40){CF=0;if(byte(&w,0x3375)==0){wb(&w,0x3375,30);v=(uint16_t)(rd(&w,0x331c)+1);wr(&w,0x331c,v);}}
        SI=rd(&w,0x3312);DI=rd(&w,0x52d4);AX=rd(&w,0x52d0);DX=rd(&w,0x52d2);if(!call(&w,0x4ef9,1))goto finish;wr(&w,0x3312,SI);SI=rd(&w,0x3312);DI=rd(&w,0x52d4);BP=0x39a3;CX=rd(&w,0x5356);AX=rd(&w,0x52d0);DX=rd(&w,0x52d2);if(!call(&w,0x4f16,3))goto finish;wr(&w,0x3312,SI);
        if(w.flags&0x40){CF=0;if(byte(&w,0x3375)==0){wb(&w,0x3375,30);v=(uint16_t)(rd(&w,0x331c)+1);wr(&w,0x331c,v);}}
    }
    CF=0;if(byte(&w,0x33b8)!=0){
        wb(&w,0x33b4,0);SI=rd(&w,0x3314);DI=rd(&w,0x52dc);BP=0x3813;CX=rd(&w,0x5354);AX=rd(&w,0x52d8);DX=rd(&w,0x52da);if(!call(&w,0x4f51,3))goto finish;wr(&w,0x3314,SI);b=byte(&w,0x33ba);AX=(uint16_t)((AX&0xff00)|b);wb(&w,0x33b9,b);SI=rd(&w,0x3316);DI=rd(&w,0x52dc);AX=rd(&w,0x52d8);DX=rd(&w,0x52da);if(!call(&w,0x4f6d,1))goto finish;wr(&w,0x3316,SI);SI=rd(&w,0x3316);DI=rd(&w,0x52dc);BP=0x39a3;CX=rd(&w,0x5356);AX=rd(&w,0x52d8);DX=rd(&w,0x52da);if(!call(&w,0x4f8a,3))goto finish;wr(&w,0x3316,SI);
    }else{w.flags=(uint16_t)(0x46|(w.r.registers.interrupts_enabled<<9)|(w.r.registers.direction<<10));w.mask=0xed7;}
    out->next_ip=pop(&w);out->next_segment=w.cs;out->status=0;
finish:
    out->current_sp=w.sp;out->returned=w.r;if(out->status==0){out->defined_flags=w.flags;out->defined_mask=w.mask;}else{out->defined_flags=(uint16_t)(2|CF|(w.r.registers.interrupts_enabled<<9)|(w.r.registers.direction<<10));out->defined_mask=0x603;}
}
