#include "td2ega_ring_selection.h"
#include <stddef.h>
typedef struct work {uint8_t *m;uint16_t cs,ss,sp;td2ega_state_registers r;td2ega_ring_selection_result *o;} work;
static uint32_t address(uint16_t s,uint16_t o){return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(work *w,uint16_t s,uint16_t o){uint32_t a=address(s,o);return (uint16_t)(w->m[a]|((uint16_t)w->m[(a+1)&UINT32_C(0xfffff)]<<8));}
static void put(work *w,uint16_t s,uint16_t o,uint16_t v,unsigned n){uint32_t a=address(s,o);w->m[a]=(uint8_t)v;if(n==2)w->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++w->o->bus_writes;}
static void push(work *w,uint16_t v){w->sp=(uint16_t)(w->sp-2);put(w,w->ss,w->sp,v,2);}
static uint16_t pop(work *w){uint16_t v=word(w,w->ss,w->sp);w->sp=(uint16_t)(w->sp+2);return v;}
#define AX w.r.registers.ax
#define DX w.r.registers.dx
#define SI w.r.registers.si
#define DS w.r.registers.ds
#define BP w.r.bp
#define CF w.r.carry
void td2ega_ring_selection(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,uint16_t sp,const td2ega_state_registers *in,uint32_t limit,td2ega_ring_selection_result *out)
{
    work w;TD2EgaByteRing ring;uint16_t expected,v;unsigned i;
    static const uint16_t words[8]={0x4800,0x5000,0x000d,0x000d,0x4d00,0x4b00,0x001b,0x0000};
    if(out==NULL)return;
    *out=(td2ega_ring_selection_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || sp<30 || sp>UINT16_C(0xffe0) || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1)return;
    w=(work){m,(uint16_t)(load+0x19e),ss,sp,*in,out};push(&w,BP);BP=w.sp;w.sp=(uint16_t)(w.sp-6);CF=0;
    if(limit==0){out->status=3;out->next_segment=w.cs;out->next_ip=0x000a;goto finish;}
    expected=w.sp;push(&w,w.cs);push(&w,0x000f);out->calls=1;push(&w,SI);
    /* Actual ABI prologue precedes the actual recovered C transformation.
     * Snapshot after its SS writes; commit DEC cursor before selected byte.
     * This profile is serialized flat RAM, without read side effects. */
    ring.cursor=word(&w,DS,0x66e6);for(i=0;i<256;++i)ring.bytes[i]=m[address(DS,(uint16_t)(0x66e8+i))];AX=td2ega_byte_ring_step(&ring);put(&w,DS,0x66e6,ring.cursor,2);put(&w,DS,(uint16_t)(0x66e8+(ring.cursor&255)),ring.bytes[ring.cursor&255],1);CF=0;SI=pop(&w);out->next_ip=pop(&w);out->next_segment=pop(&w);
    if(out->next_segment!=w.cs || out->next_ip!=0x000f || w.sp!=expected){out->status=1;goto finish;}
    AX=(uint16_t)(AX&7);DX=0;CF=0;put(&w,ss,(uint16_t)(BP-4),AX,2);put(&w,ss,(uint16_t)(BP-2),DX,2);v=AX;
    /* These immediates come from the source comparison/store chain. Locals
     * occupy distinct SS words; no further callee or asynchronous mutation. */
    put(&w,ss,(uint16_t)(BP-6),words[v],2);CF=(uint16_t)(v<7);AX=word(&w,ss,(uint16_t)(BP-6));w.sp=BP;BP=pop(&w);out->next_ip=pop(&w);out->next_segment=pop(&w);out->status=0;
finish:
    out->current_sp=w.sp;out->returned=w.r;
}
