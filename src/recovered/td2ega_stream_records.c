#include "td2ega_stream_records.h"
#include <stddef.h>
typedef struct work {
    uint8_t *m;uint16_t cs,ss,sp;uint32_t limit;
    td2ega_state_registers r;td2ega_stream_records_result *out;
} work;
static uint32_t address(uint16_t s,uint16_t o)
{return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(work *w,uint16_t s,uint16_t o)
{uint32_t a=address(s,o);return (uint16_t)(w->m[a]|((uint16_t)w->m[(a+1)&UINT32_C(0xfffff)]<<8));}
static uint8_t byte(work *w,uint16_t o)
{return w->m[address(w->r.registers.ds,o)];}
static void put(work *w,uint16_t s,uint16_t o,uint16_t v,unsigned size)
{uint32_t a=address(s,o);w->m[a]=(uint8_t)v;if(size==2)w->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++w->out->bus_writes;}
static void push(work *w,uint16_t v)
{w->sp=(uint16_t)(w->sp-2);put(w,w->ss,w->sp,v,2);}
static uint16_t pop(work *w)
{uint16_t v=word(w,w->ss,w->sp);w->sp=(uint16_t)(w->sp+2);return v;}
static uint16_t signbyte(uint8_t v)
{return (uint16_t)(v|((v&0x80)?0xff00:0));}
static int step(work *w,uint16_t ip)
{if(w->out->iterations==w->limit){w->out->status=3;w->out->next_segment=w->cs;w->out->next_ip=ip;return 0;}++w->out->iterations;return 1;}
void td2ega_stream_records(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,
    uint16_t sp,uint16_t entry,const td2ega_state_registers *in,uint32_t limit,
    td2ega_stream_records_result *out)
{
    work w;uint8_t value;uint16_t old;int branch;
    if(out==NULL)return;
    *out=(td2ega_stream_records_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || entry>2 || sp<32 || sp>UINT16_C(0xffe0) || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1)return;
    w=(work){m,(uint16_t)(load+0x13a8),ss,sp,limit,*in,out};push(&w,w.r.bp);w.r.bp=w.sp;
    if(entry==0){
        push(&w,w.r.registers.di);push(&w,w.r.registers.si);w.r.registers.si=word(&w,ss,(uint16_t)(w.r.bp+6));put(&w,w.r.registers.ds,0x6df2,(uint16_t)(word(&w,w.r.registers.ds,0x6df2)+1),2);branch=0;
        if(w.r.registers.si==0x6dfc){
            if((byte(&w,(uint16_t)(w.r.registers.si+6))&0xc)==0){
                w.r.registers.ax=signbyte(byte(&w,(uint16_t)(w.r.registers.si+7)));w.r.registers.cx=w.r.registers.ax;w.r.registers.ax=(uint16_t)(w.r.registers.ax*6);w.r.registers.di=w.r.registers.ax;if((byte(&w,(uint16_t)(w.r.registers.di+0x6e94))&1)==0)branch=1;
            }
        }
        if(!branch && (w.r.registers.si==0x6e04 || w.r.registers.si==0x6e14)){
            if((byte(&w,(uint16_t)(w.r.registers.si+6))&8)==0){
                w.r.registers.ax=signbyte(byte(&w,(uint16_t)(w.r.registers.si+7)));w.r.registers.cx=w.r.registers.ax;w.r.registers.ax=(uint16_t)(w.r.registers.ax*6);w.r.registers.di=w.r.registers.ax;
                if((byte(&w,(uint16_t)(w.r.registers.di+0x6e94))&1)==0 && word(&w,w.r.registers.ds,0x6e00)!=0x8440)branch=2;
            }
        }
        if(branch){
            put(&w,w.r.registers.ds,(uint16_t)(w.r.registers.si+4),0x8440,2);
            if(branch==2){w.r.registers.ax=signbyte(byte(&w,(uint16_t)(w.r.registers.si+6)));put(&w,w.r.registers.ds,0x83d4,w.r.registers.ax,2);}
            put(&w,w.r.registers.ds,(uint16_t)(w.r.registers.di+0x6e94),1,1);put(&w,w.r.registers.ds,(uint16_t)(w.r.registers.di+0x6e96),0x200,2);
            if(branch==2)put(&w,w.r.registers.ds,(uint16_t)(w.r.registers.si+6),(uint16_t)(byte(&w,(uint16_t)(w.r.registers.si+6))&0xfb),1);
            if(branch==1){put(&w,w.r.registers.ds,(uint16_t)(w.r.registers.si+2),0x200,2);put(&w,w.r.registers.ds,(uint16_t)(w.r.registers.si+6),(uint16_t)(byte(&w,(uint16_t)(w.r.registers.si+6))|2),1);}
            else{put(&w,w.r.registers.ds,(uint16_t)(w.r.registers.si+6),(uint16_t)(byte(&w,(uint16_t)(w.r.registers.si+6))|2),1);put(&w,w.r.registers.ds,(uint16_t)(w.r.registers.si+2),0x200,2);}
            put(&w,w.r.registers.ds,w.r.registers.si,0x8440,2);w.r.registers.ax=1;
        }else w.r.registers.ax=0;
        w.r.carry=0;w.r.registers.si=pop(&w);w.r.registers.di=pop(&w);w.r.bp=pop(&w);
    }else{
        w.sp=(uint16_t)(w.sp-2);w.r.carry=0;push(&w,w.r.registers.si);
        if(entry==1){
            w.r.registers.si=0x6f1e;w.r.registers.cx=(uint16_t)((w.r.registers.cx&0xff00)|(uint8_t)word(&w,ss,(uint16_t)(w.r.bp+6)));
            for(;;){if(!step(&w,0x2181))goto finish;value=byte(&w,w.r.registers.si);w.r.carry=0;if(value==0){w.r.registers.ax=0;break;}w.r.carry=(uint16_t)((uint8_t)w.r.registers.cx<value);if((uint8_t)w.r.registers.cx==value){w.r.registers.ax=1;break;}++w.r.registers.si;}
        }else{
            w.r.registers.si=0x6df4;w.r.registers.cx=word(&w,w.r.registers.ds,0x6f0c);
            for(;;){
                if(!step(&w,0x21a8))goto finish;w.r.carry=0;
                if((byte(&w,(uint16_t)(w.r.registers.si+6))&0x83)==0){
                    w.r.registers.ax=0;put(&w,w.r.registers.ds,(uint16_t)(w.r.registers.si+2),0,2);put(&w,w.r.registers.ds,(uint16_t)(w.r.registers.si+6),0,1);put(&w,w.r.registers.ds,(uint16_t)(w.r.registers.si+4),0,2);put(&w,w.r.registers.ds,w.r.registers.si,0,2);put(&w,w.r.registers.ds,(uint16_t)(w.r.registers.si+7),0xff,1);w.r.registers.ax=w.r.registers.si;break;
                }
                w.r.registers.ax=w.r.registers.si;old=w.r.registers.si;w.r.registers.si=(uint16_t)(old+8);w.r.carry=(uint16_t)(w.r.registers.ax<w.r.registers.cx);if(w.r.registers.ax==w.r.registers.cx){w.r.registers.ax=0;w.r.carry=0;break;}
            }
        }
        w.r.registers.si=pop(&w);w.sp=w.r.bp;w.r.bp=pop(&w);
    }
    out->next_ip=pop(&w);out->next_segment=pop(&w);out->status=0;
finish:
    out->current_sp=w.sp;out->returned=w.r;
}
