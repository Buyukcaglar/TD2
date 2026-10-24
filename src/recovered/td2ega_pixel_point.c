#include "td2ega_pixel_point.h"
#include <stddef.h>
typedef struct work {uint8_t *m;uint16_t ss,sp,cs;td2ega_state_registers r;td2ega_line_draw_service service;void *context;uint32_t limit;td2ega_pixel_point_result *o;} work;
static uint32_t address(uint16_t s,uint16_t o){return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(work *w,uint16_t s,uint16_t o){uint32_t a=address(s,o);return (uint16_t)(w->m[a]|((uint16_t)w->m[(a+1)&UINT32_C(0xfffff)]<<8));}
static void push(work *w,uint16_t v){uint32_t a;w->sp=(uint16_t)(w->sp-2);a=address(w->ss,w->sp);w->m[a]=(uint8_t)v;w->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++w->o->bus_writes;}
static uint16_t pop(work *w){uint16_t v=word(w,w->ss,w->sp);w->sp=(uint16_t)(w->sp+2);return v;}
static void low(work *w,uint16_t v){w->r.registers.ax=(uint16_t)((w->r.registers.ax&0xff00)|(v&255));}
static void high(work *w,uint16_t v){w->r.registers.ax=(uint16_t)((w->r.registers.ax&255)|((v&255)<<8));}
static int effect(work *w,uint16_t site,uint16_t kind,uint16_t value,uint16_t *read_value)
{
    td2ega_line_draw_request q={0};td2ega_line_draw_response r={0};
    w->o->next_segment=w->cs;w->o->next_ip=site;
    if(w->o->events==w->limit){w->o->status=3;return 0;}
    q.kind=kind;q.site=site;q.segment=w->cs;q.stack_segment=w->ss;q.stack_sp=w->sp;q.port=w->r.registers.dx;q.value=value;q.address=kind==5?0:address(w->r.registers.es,w->r.registers.di);q.incoming=w->r;r.returned=w->r;r.value=value;
    if(w->service==NULL || !w->service(w->context,w->m,&q,&r)){w->o->status=4;return 0;}
    ++w->o->events;if(kind==5)++w->o->ports;else if(kind==2){++w->o->reads;*read_value=(uint8_t)r.value;}else{++w->o->writes;++w->o->bus_writes;}
    return 1;
}
#define AX w.r.registers.ax
#define BX w.r.registers.bx
#define CX w.r.registers.cx
#define DX w.r.registers.dx
#define SI w.r.registers.si
#define DI w.r.registers.di
#define DS w.r.registers.ds
#define ES w.r.registers.es
#define BP w.r.bp
#define CF w.r.carry
void td2ega_pixel_point(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,uint16_t sp,const td2ega_state_registers *in,td2ega_line_draw_service service,void *context,uint32_t limit,td2ega_pixel_point_result *out)
{
    work w;uint16_t v,hardware;uint32_t wide;
    if(out==NULL)return;
    *out=(td2ega_pixel_point_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1)return;
    w=(work){m,ss,sp,(uint16_t)(load+0x6c9),*in,service,context,limit,out};push(&w,BP);BP=w.sp;push(&w,SI);push(&w,DI);
    DI=word(&w,ss,(uint16_t)(BP+6));BX=(uint16_t)(DI&7);DI=(uint16_t)(DI>>3);SI=word(&w,ss,(uint16_t)(BP+8));SI=(uint16_t)(SI<<1);wide=(uint32_t)SI+word(&w,w.cs,0xaf44);SI=(uint16_t)wide;CF=(uint16_t)(wide>65535);wide=(uint32_t)DI+word(&w,w.cs,SI);DI=(uint16_t)wide;CF=(uint16_t)(wide>65535);CX=(uint16_t)((CX&0xff00)|m[address(ss,(uint16_t)(BP+0xa))]);AX=word(&w,w.cs,0xaf3c);CF=(uint16_t)(AX<0xa000);
    hardware=(uint16_t)(AX==0xa000);
    if(hardware){
        ES=AX;DX=0x3c4;AX=0xff02;if(!effect(&w,0xba70,5,AX,NULL))goto done;DX=0x3ce;high(&w,m[address(DS,(uint16_t)(BX+0x68ce))]);low(&w,8);if(!effect(&w,0xba7a,5,AX,NULL))goto done;AX=0x205;if(!effect(&w,0xba7e,5,AX,NULL))goto done;
        if(!effect(&w,0xba7f,2,0,&v))goto done;CX=(uint16_t)((CX&255)|(v<<8));if(!effect(&w,0xba82,3,(uint8_t)CX,NULL))goto done;AX=0xff08;if(!effect(&w,0xba88,5,AX,NULL))goto done;AX=5;if(!effect(&w,0xba8c,5,AX,NULL))goto done;
    }else{
        v=m[address(DS,(uint16_t)(BX+0x68ce))];DX=(uint16_t)(v|((uint16_t)(uint8_t)~v<<8));BX=0;CF=0;
        do{
            AX=word(&w,w.cs,(uint16_t)(0xaf3c+BX));CF=0;
            if(AX!=0){ES=AX;
                if((CX&1)!=0){if(!effect(&w,0xbab6,6,(uint8_t)DX,NULL))goto done;}
                else{if(!effect(&w,0xbaab,2,0,&v))goto done;low(&w,v);low(&w,(uint8_t)AX&(uint8_t)(DX>>8));CF=0;if(!effect(&w,0xbab0,3,(uint8_t)AX,NULL))goto done;}
            }
            CF=(uint16_t)(CX&1);CX=(uint16_t)((CX&0xff00)|((CX&255)>>1));BX=(uint16_t)(BX+2);CF=(uint16_t)(BX<8);
        }while(BX<8);
    }
    DI=pop(&w);SI=pop(&w);BP=pop(&w);
    if(w.sp>0xfffc){out->status=5;out->next_segment=w.cs;out->next_ip=hardware?0xba90:0xbac6;goto done;}
    out->next_ip=pop(&w);out->next_segment=pop(&w);out->status=0;
done:
    out->current_sp=w.sp;out->returned=w.r;
}
