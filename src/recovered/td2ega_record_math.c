#include "td2ega_record_math.h"
#include <stddef.h>
typedef struct work {uint8_t *m;uint16_t cs,ss,sp;uint32_t limit;td2ega_state_registers r;td2ega_record_math_result *o;} work;
static uint32_t address(uint16_t s,uint16_t o){return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(work *w,uint16_t s,uint16_t o){uint32_t a=address(s,o);return (uint16_t)(w->m[a]|((uint16_t)w->m[(a+1)&UINT32_C(0xfffff)]<<8));}
static uint16_t rd(work *w,uint16_t o){return word(w,w->r.registers.ds,o);}
static uint8_t byte(work *w,uint16_t o){return w->m[address(w->r.registers.ds,o)];}
static void put(work *w,uint16_t s,uint16_t o,uint16_t v,unsigned n){uint32_t a=address(s,o);w->m[a]=(uint8_t)v;if(n==2)w->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++w->o->bus_writes;}
static void wr(work *w,uint16_t o,uint16_t v){put(w,w->r.registers.ds,o,v,2);}
static void push(work *w,uint16_t v){w->sp=(uint16_t)(w->sp-2);put(w,w->ss,w->sp,v,2);}
static uint16_t pop(work *w){uint16_t v=word(w,w->ss,w->sp);w->sp=(uint16_t)(w->sp+2);return v;}
static int32_t sw(uint16_t v){return v&0x8000?(int32_t)v-65536:(int32_t)v;}
static uint16_t add(work *w,uint16_t a,uint16_t b){uint32_t v=(uint32_t)a+b;w->r.carry=(uint16_t)(v>65535);return (uint16_t)v;}
static uint16_t sub(work *w,uint16_t a,uint16_t b){w->r.carry=(uint16_t)(a<b);return (uint16_t)(a-b);}
static void cmp(work *w,uint16_t a,uint16_t b){w->r.carry=(uint16_t)(a<b);}
static int32_t difference(work *w,uint16_t low,uint16_t high){uint16_t a,b,c;int32_t d;a=rd(w,low);(void)sub(w,a,w->r.registers.ax);c=w->r.carry;b=rd(w,high);d=sw(b)-sw(w->r.registers.dx)-c;w->r.carry=(uint16_t)((uint32_t)b<(uint32_t)w->r.registers.dx+c);w->r.registers.bx=(uint16_t)(b-w->r.registers.dx-c);return d;}
static int step(work *w,uint16_t ip){if(w->o->iterations==w->limit){w->o->status=3;w->o->next_segment=w->cs;w->o->next_ip=ip;return 0;}++w->o->iterations;return 1;}
#define AX w.r.registers.ax
#define BX w.r.registers.bx
#define CX w.r.registers.cx
#define DX w.r.registers.dx
#define SI w.r.registers.si
#define DI w.r.registers.di
#define BP w.r.bp
#define CF w.r.carry
void td2ega_record_math(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,uint16_t sp,uint16_t entry,const td2ega_state_registers *in,uint32_t limit,td2ega_record_math_result *out)
{
    work w;uint16_t value,at;uint8_t v,dl;int32_t d;unsigned ring;
    if(out==NULL)return;
    *out=(td2ega_record_math_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || entry>4 || sp<16 || sp>UINT16_C(0xffe0) || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1)return;
    w=(work){m,(uint16_t)(load+0x6c9),ss,sp,limit,*in,out};
    if(entry==0){
        v=byte(&w,BX);AX=(uint16_t)((AX&0xff00)|v);CF=0;wr(&w,0x3340,100);wr(&w,0x3342,(v&0x80)?100:0);push(&w,AX);CX=4;DX=0;CF=0;
        do{
            if(!step(&w,0x52bf))goto finish;
            v=byte(&w,BX);AX=(uint16_t)((AX&0xff00)|v);BX=add(&w,BX,10);AX=(uint16_t)(AX&0xff7f);CF=0;AX=(uint8_t)AX;AX=add(&w,AX,AX);AX=add(&w,AX,AX);SI=AX;
            /* Last SHL has SF=OF=0: the following JL cannot take from this entry. */
            v=byte(&w,(uint16_t)(SI+0x347f));AX=(uint16_t)((AX&0xff00)|v);v=(uint8_t)(0-v);AX=(uint16_t)((AX&0xff00)|v);CF=(uint16_t)(v!=0);dl=(uint8_t)DX;CF=(uint16_t)(dl<v);if(dl<=v)DX=(uint16_t)((DX&0xff00)|v);CX=(uint16_t)(CX-1);
        }while(CX!=0);
        CF=0;dl=(uint8_t)DX;if(dl&0x80){dl=(uint8_t)(0-dl);DX=(uint16_t)((DX&0xff00)|dl);CF=(uint16_t)(dl!=0);}BX=DX;BX=add(&w,BX,BX);AX=rd(&w,(uint16_t)(BX+0x32ee));DX=DI;value=(uint16_t)((uint8_t)AX*(uint8_t)DX);AX=value;CF=(uint16_t)(value>255);BX=pop(&w);wr(&w,0x3344,AX);
    }else if(entry==1){
        CX=SI;BP=0;CF=0;
        for(;;){
            if(!step(&w,0x5026))goto finish;
            CF=0;if(SI==0)SI=rd(&w,0x5356);SI=sub(&w,SI,8);d=difference(&w,(uint16_t)(SI+0x39a7),(uint16_t)(SI+0x39a5));if(d>=0)BX=sub(&w,BX,rd(&w,0x380d));cmp(&w,BX,0xfffd);if(sw(BX)<-3)break;CF=0;
            if(BP==0){v=byte(&w,0x33b4);CF=0;if(v&0x80)break;v=byte(&w,0x33b9);CF=0;if(v==0){DI=sub(&w,DI,180);value=rd(&w,(uint16_t)(SI+0x39a9));cmp(&w,value,DI);if(sw(value)<sw(DI))break;DI=add(&w,DI,360);value=rd(&w,(uint16_t)(SI+0x39a9));cmp(&w,value,DI);if(sw(value)>sw(DI))break;}}
            DX=sub(&w,DX,3);cmp(&w,DX,0x3b51);if(DX<0x3b51)DX=add(&w,DX,rd(&w,0x380d));wr(&w,(uint16_t)(SI+0x39a7),AX);wr(&w,(uint16_t)(SI+0x39a5),DX);BP=(uint16_t)(BP+1);
        }
        SI=CX;CF=0;if(BP!=0)goto returned;BX=add(&w,BX,rd(&w,0x380d));cmp(&w,BX,1);if(sw(BX)>1)goto returned;CF=0;if(SI==0)SI=rd(&w,0x5356);SI=sub(&w,SI,8);
    }else if(entry==2){
        AX=rd(&w,0x52c8);DX=rd(&w,0x52ca);wr(&w,0x334c,0xff9c);put(&w,w.r.registers.ds,0x33b8,1,1);BP=rd(&w,0x330e);DI=rd(&w,0x330c);DX=sub(&w,DX,26);(void)difference(&w,0x52d0,0x52d2);value=BX;BX=(uint16_t)(0-BX);CF=(uint16_t)(value!=0);wr(&w,0x334e,BX);SI=BP;
        for(ring=0;ring<2;++ring){
            uint16_t end=ring==0?0x5356:0x5354,base=ring==0?0x39a5:0x3815,origin=ring==0?BP:DI;
            if(ring==1)SI=DI;
            for(;;){
                if(!step(&w,(uint16_t)(ring==0?0x5477:0x54aa)))goto finish;
                CF=0;if(SI==0)SI=rd(&w,end);SI=sub(&w,SI,8);cmp(&w,SI,origin);if(SI==origin)break;d=difference(&w,(uint16_t)(SI+base+2),(uint16_t)(SI+base));if(d<0)break;cmp(&w,BX,26);if(sw(BX)>=26)break;
            }
            SI=add(&w,SI,8);value=rd(&w,end);cmp(&w,SI,value);if(SI==value){SI=0;CF=0;}wr(&w,(uint16_t)(ring==0?0x3316:0x3314),SI);
        }
        wr(&w,0x52de,0x3200);wr(&w,0x52dc,200);wr(&w,0x52d8,AX);wr(&w,0x52da,DX);put(&w,w.r.registers.ds,0x33ba,0,1);
    }else if(entry==3){
        at=(uint16_t)(BP+SI);d=difference(&w,(uint16_t)(at+4),(uint16_t)(at+2));if(d>0)BX=sub(&w,BX,rd(&w,0x380d));cmp(&w,BX,0xfffc);if(sw(BX)<-4)goto returned;CF=0;
        if(byte(&w,0x33b9)==0){v=byte(&w,0x33b4);CF=0;if(v!=0 && !(v&0x80))goto skip_record;DI=sub(&w,DI,180);value=rd(&w,(uint16_t)(BP+SI+6));cmp(&w,value,DI);if(sw(value)<sw(DI))goto skip_record;DI=add(&w,DI,360);value=rd(&w,(uint16_t)(BP+SI+6));cmp(&w,value,DI);if(sw(value)>sw(DI))goto skip_record;}
        push(&w,SI);DI=SI;DX=(uint16_t)(DX+1);value=rd(&w,0x3811);cmp(&w,DX,value);if(DX>=value)DX=sub(&w,DX,rd(&w,0x380d));
        for(;;){
            if(!step(&w,0x4fda))goto finish;
            wr(&w,(uint16_t)(BP+SI+4),AX);wr(&w,(uint16_t)(BP+SI+2),DX);DX=add(&w,DX,3);value=rd(&w,0x3811);cmp(&w,DX,value);if(DX>=value)DX=sub(&w,DX,rd(&w,0x380d));SI=add(&w,SI,8);cmp(&w,SI,CX);if(SI==CX){SI=0;CF=0;}cmp(&w,SI,DI);if(SI==DI)break;d=difference(&w,(uint16_t)(BP+SI+4),(uint16_t)(BP+SI+2));if(d>=0)BX=sub(&w,BX,rd(&w,0x380d));cmp(&w,BX,0xfffc);if(sw(BX)<-4)break;
        }
        SI=pop(&w);AX=0;CF=0;goto returned;
skip_record:
        SI=add(&w,SI,8);cmp(&w,SI,CX);if(SI==CX){SI=0;CF=0;}DX=(uint16_t)(DX+1);
    }else{
        AX=rd(&w,0x52c8);DX=rd(&w,0x52ca);DI=SI;d=difference(&w,(uint16_t)(BP+SI+4),(uint16_t)(BP+SI+2));if(d<0)BX=add(&w,BX,rd(&w,0x380d));cmp(&w,BX,60);if(BX>60)goto backward;DX=add(&w,DX,61);value=rd(&w,0x3811);cmp(&w,DX,value);if(DX>=value)DX=sub(&w,DX,rd(&w,0x380d));
        for(;;){
            if(!step(&w,0x5b87))goto finish;
            wr(&w,(uint16_t)(BP+SI+4),AX);wr(&w,(uint16_t)(BP+SI+2),DX);DX=add(&w,DX,3);value=rd(&w,0x3811);cmp(&w,DX,value);if(DX>=value)DX=sub(&w,DX,rd(&w,0x380d));SI=add(&w,SI,8);cmp(&w,SI,CX);if(SI==CX){SI=0;CF=0;}cmp(&w,SI,DI);if(SI==DI)break;d=difference(&w,(uint16_t)(BP+SI+4),(uint16_t)(BP+SI+2));if(d>0)BX=sub(&w,BX,rd(&w,0x380d));cmp(&w,BX,0xffc2);if(sw(BX)<-62)break;
        }
backward:
        AX=rd(&w,0x52c8);DX=rd(&w,0x52ca);SI=DI;CF=0;if(SI==0)SI=CX;SI=sub(&w,SI,8);d=difference(&w,(uint16_t)(BP+SI+4),(uint16_t)(BP+SI+2));if(d>0)BX=sub(&w,BX,rd(&w,0x380d));cmp(&w,BX,0xfff6);if(sw(BX)<-10)goto returned;DX=sub(&w,DX,10);cmp(&w,DX,0x3b51);if(DX<0x3b51)DX=add(&w,DX,rd(&w,0x380d));
        for(;;){
            if(!step(&w,0x5bf6))goto finish;
            wr(&w,(uint16_t)(BP+SI+4),AX);wr(&w,(uint16_t)(BP+SI+2),DX);DX=sub(&w,DX,3);cmp(&w,DX,0x3b51);if(DX<0x3b51)DX=add(&w,DX,rd(&w,0x380d));CF=0;if(SI==0)SI=CX;SI=sub(&w,SI,8);cmp(&w,SI,DI);if(SI==DI)break;d=difference(&w,(uint16_t)(BP+SI+4),(uint16_t)(BP+SI+2));if(d<0)BX=add(&w,BX,rd(&w,0x380d));cmp(&w,BX,30);if(sw(BX)>30)break;
        }
    }
returned:
    out->next_ip=pop(&w);out->next_segment=w.cs;out->status=0;
finish:
    out->current_sp=w.sp;out->returned=w.r;
}
