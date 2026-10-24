#include "td2ega_number_field.h"
#include <stddef.h>
typedef struct work {uint8_t *m;uint16_t ss,sp;td2ega_state_registers r;td2ega_number_field_result *o;} work;
static uint32_t address(uint16_t s,uint16_t o){return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(work *w,uint16_t s,uint16_t o){uint32_t a=address(s,o);return (uint16_t)(w->m[a]|((uint16_t)w->m[(a+1)&UINT32_C(0xfffff)]<<8));}
static uint16_t rd(work *w,uint16_t o){return word(w,w->r.registers.ds,o);}
static uint8_t byte(work *w,uint16_t o){return w->m[address(w->r.registers.ds,o)];}
static void put(work *w,uint16_t s,uint16_t o,uint16_t v){uint32_t a=address(s,o);w->m[a]=(uint8_t)v;w->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++w->o->bus_writes;}
static void push(work *w,uint16_t v){w->sp=(uint16_t)(w->sp-2);put(w,w->ss,w->sp,v);}
static uint16_t pop(work *w){uint16_t v=word(w,w->ss,w->sp);w->sp=(uint16_t)(w->sp+2);return v;}
static int32_t sw(uint16_t v){return v&0x8000?(int32_t)v-65536:(int32_t)v;}
static int signed_byte(uint8_t v){return v&128?(int)v-256:v;}
#define AX w.r.registers.ax
#define BX w.r.registers.bx
#define CX w.r.registers.cx
#define DX w.r.registers.dx
#define SI w.r.registers.si
#define DI w.r.registers.di
#define BP w.r.bp
#define CF w.r.carry
void td2ega_number_field(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,uint16_t sp,const td2ega_state_registers *in,uint32_t limit,td2ega_number_field_result *out)
{
    work w;uint8_t b;uint16_t v;int32_t product;uint32_t wide;
    if(out==NULL)return;
    *out=(td2ega_number_field_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || sp<16 || sp>UINT16_C(0xffe0) || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1)return;
    w=(work){m,ss,sp,*in,out};push(&w,BP);BP=w.sp;CF=(uint16_t)(w.sp<4);w.sp=(uint16_t)(w.sp-4);push(&w,DI);push(&w,SI);SI=word(&w,ss,(uint16_t)(BP+8));put(&w,ss,(uint16_t)(BP-2),1);b=byte(&w,SI);CF=(uint16_t)(b<42);
    if(b==42){BX=rd(&w,0x8404);DI=rd(&w,BX);v=rd(&w,0x8404);wide=(uint32_t)v+2;CF=(uint16_t)(wide>65535);put(&w,w.r.registers.ds,0x8404,(uint16_t)wide);SI=(uint16_t)(SI+1);goto final;}
    CF=(uint16_t)(b<45);if(b==45){put(&w,ss,(uint16_t)(BP-2),0xffff);SI=(uint16_t)(SI+1);}DI=0;CF=0;b=byte(&w,SI);CF=(uint16_t)(b<48);if(signed_byte(b)<48)goto final;CF=(uint16_t)(b<57);if(signed_byte(b)>57)goto final;v=rd(&w,0x83fa);CF=(uint16_t)(v<DI);if(v==DI){b=byte(&w,SI);CF=(uint16_t)(b<48);if(b==48)put(&w,w.r.registers.ds,0x8402,48);}
    for(;;){
        if(out->digits==limit){out->status=3;out->next_segment=(uint16_t)(load+0x13a8);out->next_ip=0x213c;goto done;}++out->digits;
        b=byte(&w,SI);AX=(uint16_t)(b&128?(uint16_t)(0xff00|b):b);CX=DI;CX=(uint16_t)(CX<<1);CX=(uint16_t)(CX<<1);CX=(uint16_t)(CX+DI);CX=(uint16_t)(CX<<1);CX=(uint16_t)(CX+AX);CF=(uint16_t)(CX<48);CX=(uint16_t)(CX-48);DI=CX;SI=(uint16_t)(SI+1);b=byte(&w,SI);CF=(uint16_t)(b<48);if(signed_byte(b)<48)break;CF=(uint16_t)(b<57);if(signed_byte(b)>57)break;
    }
final:
    AX=word(&w,ss,(uint16_t)(BP-2));product=sw(AX)*sw(DI);AX=(uint16_t)product;DX=(uint16_t)((uint32_t)product>>16);CF=(uint16_t)(product!=sw(AX));DI=AX;BX=word(&w,ss,(uint16_t)(BP+6));put(&w,w.r.registers.ds,BX,DI);AX=SI;SI=pop(&w);DI=pop(&w);w.sp=BP;BP=pop(&w);out->next_ip=pop(&w);out->next_segment=pop(&w);out->status=0;
done:
    out->current_sp=w.sp;out->returned=w.r;
}
