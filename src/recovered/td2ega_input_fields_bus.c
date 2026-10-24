#include "td2ega_input_fields_bus.h"
#include <stddef.h>
typedef struct work {uint8_t *m;uint32_t bytes,limit;uint16_t load,ss,sp,cs,zf;td2ega_state_registers r;td2ega_input_fields_bus_result *o;} work;
static uint32_t address(uint16_t s,uint16_t o){return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);}
static uint16_t word(work *w,uint16_t s,uint16_t o){uint32_t a=address(s,o);return (uint16_t)(w->m[a]|((uint16_t)w->m[(a+1)&UINT32_C(0xfffff)]<<8));}
static uint16_t rd(work *w,uint16_t o){return word(w,w->r.registers.ds,o);}
static uint8_t byte(work *w,uint16_t o){return w->m[address(w->r.registers.ds,o)];}
static void put(work *w,uint16_t s,uint16_t o,uint16_t v){uint32_t a=address(s,o);w->m[a]=(uint8_t)v;w->m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);++w->o->bus_writes;}
static void wr(work *w,uint16_t o,uint16_t v){put(w,w->r.registers.ds,o,v);}
static void wb(work *w,uint16_t o,uint8_t v){w->m[address(w->r.registers.ds,o)]=v;++w->o->bus_writes;}
static void push(work *w,uint16_t v){w->sp=(uint16_t)(w->sp-2);put(w,w->ss,w->sp,v);}
static uint16_t pop(work *w){uint16_t v=word(w,w->ss,w->sp);w->sp=(uint16_t)(w->sp+2);return v;}
static int32_t sw(uint16_t v){return v<0x8000?v:(int32_t)v-65536;}
static void cmp(work *w,uint16_t a,uint16_t b){w->r.carry=(uint16_t)(a<b);w->zf=(uint16_t)(a==b);}
static uint16_t add(work *w,uint16_t a,uint16_t b){uint32_t v=(uint32_t)a+b;w->r.carry=(uint16_t)(v>65535);w->zf=(uint16_t)((uint16_t)v==0);return (uint16_t)v;}
static uint16_t sub(work *w,uint16_t a,uint16_t b){uint16_t v=(uint16_t)(a-b);w->r.carry=(uint16_t)(a<b);w->zf=(uint16_t)(v==0);return v;}
static uint8_t addb(work *w,uint8_t a,uint8_t b){uint16_t v=(uint16_t)(a+b);w->r.carry=(uint16_t)(v>255);w->zf=(uint16_t)((uint8_t)v==0);return (uint8_t)v;}
static uint8_t subb(work *w,uint8_t a,uint8_t b){uint8_t v=(uint8_t)(a-b);w->r.carry=(uint16_t)(a<b);w->zf=(uint16_t)(v==0);return v;}
static uint16_t logic(work *w,uint16_t v){w->r.carry=0;w->zf=(uint16_t)(v==0);return v;}
static uint16_t shl(work *w,uint16_t v){w->r.carry=(uint16_t)(v>>15);v=(uint16_t)(v<<1);w->zf=(uint16_t)(v==0);return v;}
static void low(work *w,uint16_t v){w->r.registers.ax=(uint16_t)((w->r.registers.ax&0xff00)|(v&255));}
static void high(work *w,uint8_t v){w->r.registers.ax=(uint16_t)((w->r.registers.ax&255)|((uint16_t)v<<8));}
static void delta(work *w)
{
    td2ega_music_registers *r=&w->r.registers;uint16_t v;uint8_t b;
    r->ax=sub(w,r->dx,r->cx);cmp(w,r->cx,r->dx);
    if(sw(r->cx)<=sw(r->dx)){
        cmp(w,r->ax,0xa8c);if(w->r.carry)return;b=byte(w,0x2f56);cmp(w,b,0);if(b==0)return;
        wb(w,0x33b2,3);high(w,byte(w,0x52cf));b=subb(w,(uint8_t)(r->ax>>8),5);high(w,b);wb(w,0x52cf,b);return;
    }
    r->ax=sub(w,0,r->ax);cmp(w,r->ax,0xbb8);if(w->r.carry)return;r->dx=r->ax;low(w,byte(w,0x2418));b=subb(w,(uint8_t)r->ax,byte(w,0x33c6));low(w,b);if(w->r.carry)low(w,logic(w,0));
    r->bx=(uint16_t)((r->bx&255)|((uint16_t)byte(w,0x3329)<<8));v=(uint16_t)((uint8_t)r->ax*(r->bx>>8));r->ax=v;w->r.carry=(uint16_t)((v>>8)!=0);cmp(w,v,0x1b58);if(!w->r.carry)wb(w,0x33b2,(uint8_t)(r->dx>>8));
}
static int child(work *w,uint16_t site,int product)
{
    uint16_t expected=w->sp,ret;uint32_t v;td2ega_control_bus_result h;
    w->o->next_segment=w->cs;w->o->next_ip=site;if(w->o->calls==w->limit){w->o->status=3;return 0;}++w->o->calls;push(w,(uint16_t)(site+3));
    if(product){
        td2ega_control_bus(w->m,w->bytes,w->load,w->ss,w->sp,3,&w->r,0,&h);w->r=h.returned;w->sp=h.current_sp;w->o->bus_writes+=h.bus_writes;w->o->next_segment=h.next_segment;w->o->next_ip=h.next_ip;
        if(h.status!=0){w->o->status=h.status;return 0;}ret=h.next_ip;if(h.next_segment!=w->cs){w->o->status=1;return 0;}
        if(byte(w,0x2f56)==0)w->zf=1;else{v=(uint32_t)rd(w,0x3328)*rd(w,0x52ce);w->zf=(uint16_t)((v>>16)==800);}
    }else{delta(w);ret=pop(w);w->o->next_segment=w->cs;w->o->next_ip=ret;}
    if(ret!=(uint16_t)(site+3) || w->sp!=expected){w->o->status=1;return 0;}return 1;
}
#define AX w.r.registers.ax
#define BX w.r.registers.bx
#define CX w.r.registers.cx
#define DX w.r.registers.dx
#define BP w.r.bp
#define CF w.r.carry
void td2ega_input_fields_bus(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,uint16_t sp,uint16_t entry,uint16_t prepared,const td2ega_state_registers *in,uint32_t max_calls,td2ega_input_fields_bus_result *out)
{
    work w;uint16_t v;uint8_t b,al,dl,dh;unsigned i;
    if(out==NULL)return;
    *out=(td2ega_input_fields_bus_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || entry>3 || prepared>1 || (entry<2?(sp<20 || sp>UINT16_C(0xffe0)):sp==UINT16_C(0xffff)) || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1)return;
    w=(work){m,bytes,max_calls,load,ss,sp,(uint16_t)(load+0x6c9),0,*in,out};
    if(entry==2){delta(&w);goto root;}
    if(entry==3){BX=0;CF=0;w.zf=1;DX=BX;for(i=0;i<8;++i){b=byte(&w,(uint16_t)(BX+0x335d));AX=(uint16_t)(b|((b&0x80)?0xff00:0));DX=add(&w,DX,AX);BX=(uint16_t)(BX+1);w.zf=(uint16_t)(BX==0);cmp(&w,(uint8_t)BX,8);}wr(&w,0x30e4,DX);AX=rd(&w,0x52ce);wr(&w,0x30e6,AX);goto root;}
    if(entry==1){
        wb(&w,0x2f5a,1);wb(&w,0x336b,1);AX=rd(&w,0x2f4c);BX=rd(&w,0x2f4e);v=rd(&w,0x3324);cmp(&w,AX,v);
        if(AX==v){v=rd(&w,0x3326);cmp(&w,BX,v);if(sw(BX)<sw(v))BX=add(&w,BX,6);else if(BX!=v)BX=sub(&w,BX,6);}
        else{v=rd(&w,0x23c8);cmp(&w,BX,v);if(BX==v){v=rd(&w,0x3324);cmp(&w,AX,v);AX=sw(AX)<sw(v)?add(&w,AX,6):sub(&w,AX,6);}else BX=sw(BX)>sw(v)?sub(&w,BX,6):add(&w,BX,6);}
        wr(&w,0x2f4c,AX);wr(&w,0x2f4e,BX);v=rd(&w,0x3324);cmp(&w,AX,v);if(AX!=v)goto root;v=rd(&w,0x3326);cmp(&w,BX,v);if(BX!=v)goto root;logic(&w,(uint16_t)(byte(&w,0x33b0)&0x30));if(!w.zf)goto root;
        wb(&w,0x3365,(uint8_t)(BX>>8));wb(&w,0x3366,(uint8_t)(BX>>8));wb(&w,0x336c,1);BX=(uint16_t)((BX&0xff00)|byte(&w,0x2f56));cmp(&w,(uint8_t)BX,(uint8_t)(BX>>8));if(w.zf)goto root;BX=shl(&w,BX);AX=rd(&w,(uint16_t)(BX+0x23b8));wr(&w,0x3328,AX);if(!child(&w,0x443a,1) || !child(&w,0x443d,0))goto done;goto root;
    }
    dl=byte(&w,0x3365);dh=byte(&w,0x3366);DX=(uint16_t)(dl|((uint16_t)dh<<8));low(&w,byte(&w,0x33b0));BP=rd(&w,0x332c);b=byte(&w,0x33d5);cmp(&w,b,0);
    if(b!=0){BX=logic(&w,(uint16_t)(AX&15));CX=(uint16_t)((CX&0xff00)|byte(&w,(uint16_t)(BX+0x339d)));wb(&w,0x336d,(uint8_t)CX);low(&w,5);goto automatic;}
    v=rd(&w,0x8a9a);cmp(&w,v,1);if(prepared?v!=1:v>1)goto tables;
    wr(&w,0x3352,0);low(&w,1);wb(&w,0x2f59,10);logic(&w,dl);if(dl!=0)goto tables;v=rd(&w,0x23aa);cmp(&w,BP,v);if(BP>v)goto force_bit;v=rd(&w,0x23ae);cmp(&w,BP,v);if(BP>v)goto tables;b=byte(&w,0x2f56);cmp(&w,b,1);if(b<=1)goto tables;low(&w,5);
force_bit:
    low(&w,logic(&w,(uint16_t)((uint8_t)AX|0x10)));
tables:
    BX=logic(&w,(uint16_t)(AX&15));CX=(uint16_t)((CX&0xff00)|byte(&w,(uint16_t)(BX+0x339d)));wb(&w,0x336d,(uint8_t)CX);CX=(uint16_t)((CX&0xff00)|byte(&w,(uint16_t)(BX+0x33a6)));logic(&w,(uint8_t)CX);if((uint8_t)CX>=0x80)wb(&w,0x336c,(uint8_t)CX);b=byte(&w,0x90a8);cmp(&w,b,0);if(b==0)goto settle;
automatic:
    logic(&w,dl);if(dl!=0)goto settle;v=rd(&w,0x23ac);cmp(&w,BP,v);if(BP>=v){high(&w,byte(&w,0x2f56));b=byte(&w,0x23a6);cmp(&w,(uint8_t)(AX>>8),b);if((uint8_t)(AX>>8)!=b){low(&w,0x11);BX=(uint16_t)((BX&0xff00)|1);}}
    else{b=byte(&w,0x2f56);cmp(&w,b,1);if(b>1){v=rd(&w,0x23ae);cmp(&w,BP,v);if(BP<=v){low(&w,0x15);BX=(uint16_t)((BX&0xff00)|5);}}}
settle:
    logic(&w,(uint16_t)((uint8_t)AX&0x30));if(!w.zf)goto action;logic(&w,dh);if(dh==0)goto quiet;logic(&w,dl);if(dl!=0)goto quiet;wb(&w,0x3366,dl);if(!child(&w,0x4332,1) || !child(&w,0x4335,0))goto done;goto root;
quiet:
    logic(&w,(uint16_t)((uint8_t)AX&0x30));if(!w.zf)goto action;wb(&w,0x3367,0);logic(&w,dh);if(dh==0){low(&w,byte(&w,(uint16_t)(BX+0x33a6)));wb(&w,0x336c,(uint8_t)AX);}goto root;
action:
    low(&w,1);wb(&w,0x3366,(uint8_t)AX);wb(&w,0x2f5a,(uint8_t)AX);wb(&w,0x2f59,10);CX=(uint16_t)(CX&0xff00);CF=0;w.zf=1;v=rd(&w,0x8a9a);cmp(&w,v,1);if(v==1)goto common;b=byte(&w,0x33af);cmp(&w,b,0);if(b==0)goto common;b=byte(&w,0x5490);cmp(&w,b,0);if(b!=0)goto common;cmp(&w,(uint8_t)BX,(uint8_t)CX);if(w.zf)goto publish;CX=(uint16_t)((CX&0xff00)|(uint8_t)((uint8_t)CX+1));w.zf=(uint16_t)((uint8_t)CX==0);CX=(uint16_t)((CX&255)|((uint16_t)byte(&w,(uint16_t)(BX+0x2406))<<8));low(&w,byte(&w,(uint16_t)(BX+0x240f)));BX=(uint16_t)((BX&0xff00)|(CX>>8));b=addb(&w,(uint8_t)BX,7);BX=(uint16_t)((BX&0xff00)|b);goto commit;
common:
    high(&w,byte(&w,(uint16_t)(BX+0x3394)));cmp(&w,(uint8_t)(AX>>8),(uint8_t)CX);if(w.zf)goto publish;low(&w,byte(&w,0x2f56));low(&w,addb(&w,(uint8_t)AX,(uint8_t)(AX>>8)));b=byte(&w,0x23a6);cmp(&w,(uint8_t)AX,b);if((uint8_t)AX>b)goto publish;CX=(uint16_t)((CX&0xff00)|(uint8_t)((uint8_t)CX+1));w.zf=(uint16_t)((uint8_t)CX==0);b=byte(&w,0x3367);cmp(&w,b,1);if(b==1)goto publish;BX=(uint16_t)((BX&0xff00)|(uint8_t)AX);
commit:
    al=(uint8_t)AX;wb(&w,0x2f56,al);BX=shl(&w,BX);BX=shl(&w,BX);AX=rd(&w,(uint16_t)(BX+0x23c6));wr(&w,0x3324,AX);AX=rd(&w,(uint16_t)(BX+0x23c8));wr(&w,0x3326,AX);wb(&w,0x3365,(uint8_t)CX);
publish:
    wb(&w,0x3367,(uint8_t)CX);
root:
    out->next_ip=pop(&w);out->next_segment=w.cs;out->status=0;out->zero_flag=w.zf;out->flags_valid=1;
done:
    out->current_sp=w.sp;out->returned=w.r;
}
