#include "td2ega_sim_controller.h"
#include <stddef.h>

typedef struct work {uint8_t *m;uint32_t bytes;uint16_t load,ss,sp,cs,zf;td2ega_state_registers r;const td2ega_sim_controller_limits *l;td2ega_sim_controller_result *o;} work;
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
static uint16_t logic(work *w,uint16_t v){w->r.carry=0;w->zf=(uint16_t)(v==0);return v;}
static uint16_t shl(work *w,uint16_t v){w->r.carry=(uint16_t)(v>>15);v=(uint16_t)(v<<1);w->zf=(uint16_t)(v==0);return v;}
static uint16_t shr(work *w,uint16_t v){w->r.carry=(uint16_t)(v&1);v=(uint16_t)(v>>1);w->zf=(uint16_t)(v==0);return v;}
static uint16_t sar(work *w,uint16_t v){w->r.carry=(uint16_t)(v&1);v=(uint16_t)((v>>1)|(v&0x8000));w->zf=(uint16_t)(v==0);return v;}
static void low(work *w,uint16_t v){w->r.registers.ax=(uint16_t)((w->r.registers.ax&0xff00)|(v&255));}
static uint16_t signbyte(uint8_t v){return (uint16_t)(v|((v&0x80)?0xff00:0));}
static int budget(work *w,uint16_t site,uint32_t *used,uint32_t limit){w->o->next_segment=w->cs;w->o->next_ip=site;if(*used==limit){w->o->status=3;return 0;}++*used;return 1;}
static int finish_call(work *w,uint16_t status,uint16_t segment,uint16_t ip,uint16_t sp,uint16_t expected_ip,uint16_t expected_sp)
{
    w->sp=sp;w->o->next_segment=segment;w->o->next_ip=ip;
    if(status!=0){w->o->status=status;return 0;}
    if(segment!=w->cs || ip!=expected_ip || sp!=expected_sp){w->o->status=1;return 0;}return 1;
}
static td2ega_sample_adjust_limits child_limits(work *w)
{td2ega_sample_adjust_limits l={w->l->child_calls-w->o->child_calls,w->l->control_calls-w->o->control_calls};return l;}
static int window(work *w,uint16_t site,uint16_t entry)
{
    uint16_t expected=w->sp;td2ega_window_controllers_result h;
    td2ega_window_controllers_limits l={w->l->guard_calls-w->o->guard_calls,w->l->sample_calls-w->o->sample_calls,{0,0}};l.child=child_limits(w);
    ++w->o->direct_calls;push(w,(uint16_t)(site+3));td2ega_window_controllers(w->m,w->bytes,w->load,w->ss,w->sp,entry,&w->r,&l,&h);
    w->r=h.returned;w->zf=h.zero_flag;w->o->guard_calls+=h.guard_calls;w->o->sample_calls+=h.sample_calls;w->o->child_calls+=h.child_calls;w->o->control_calls+=h.control_calls;w->o->bus_writes+=h.bus_writes;
    return finish_call(w,h.status,h.next_segment,h.next_ip,h.current_sp,(uint16_t)(site+3),expected);
}
static int threshold(work *w)
{
    uint16_t expected=w->sp;td2ega_threshold_transition_result h;td2ega_threshold_transition_limits l={w->l->rows-w->o->rows,w->l->control_calls-w->o->control_calls};
    ++w->o->direct_calls;push(w,0x48ab);td2ega_threshold_transition(w->m,w->bytes,w->load,w->ss,w->sp,&w->r,&l,&h);w->r=h.returned;w->zf=h.zero_flag;w->o->rows+=h.rows;w->o->control_calls+=h.control_calls;w->o->bus_writes+=h.bus_writes;
    return finish_call(w,h.status,h.next_segment,h.next_ip,h.current_sp,0x48ab,expected);
}
static int indexed(work *w)
{
    uint16_t expected=w->sp;td2ega_indexed_sample_result h;td2ega_indexed_sample_limits l={w->l->guard_calls-w->o->guard_calls,w->l->sample_calls-w->o->sample_calls,{0,0}};l.child=child_limits(w);
    ++w->o->direct_calls;push(w,0x48ae);td2ega_indexed_sample(w->m,w->bytes,w->load,w->ss,w->sp,&w->r,&l,&h);w->r=h.returned;w->zf=h.zero_flag;w->o->guard_calls+=h.guard_calls;w->o->sample_calls+=h.sample_calls;w->o->child_calls+=h.child_calls;w->o->control_calls+=h.control_calls;w->o->bus_writes+=h.bus_writes;
    return finish_call(w,h.status,h.next_segment,h.next_ip,h.current_sp,0x48ae,expected);
}
static int scalar(work *w)
{
    uint16_t expected=w->sp;td2ega_table_scalar_result h;++w->o->direct_calls;push(w,w->cs);push(w,0x4894);
    td2ega_table_scalar(w->m,w->bytes,w->load,w->ss,w->sp,2,&w->r,&h);w->r=h.returned;w->o->bus_writes+=h.bus_writes;
    return finish_call(w,h.status,h.next_segment,h.next_ip,h.current_sp,0x4894,expected);
}
static int ring(work *w,uint16_t site)
{
    uint16_t expected=w->sp,index,ret,segment;TD2EgaByteRing state={0};
    if(!budget(w,site,&w->o->ring_calls,w->l->ring_calls))return 0;
    ++w->o->direct_calls;push(w,w->cs);push(w,(uint16_t)(site+5));push(w,w->r.registers.si);
    wr(w,0x66e6,(uint16_t)(rd(w,0x66e6)-1));w->r.registers.si=(uint16_t)(rd(w,0x66e6)&255);index=w->r.registers.si;
    state.cursor=(uint16_t)(rd(w,0x66e6)+1);state.bytes[index]=byte(w,(uint16_t)(0x66e8+index));w->r.registers.ax=td2ega_byte_ring_step(&state);wb(w,(uint16_t)(0x66e8+index),(uint8_t)w->r.registers.ax);w->r.carry=0;w->zf=1;w->r.registers.si=pop(w);ret=pop(w);segment=pop(w);
    return finish_call(w,0,segment,ret,w->sp,(uint16_t)(site+5),expected);
}
static int dispatch(work *w)
{
    static const uint16_t targets[11]={0x4929,0x4947,0x494d,0x495d,0x499a,0x49c9,0x49cf,0x49d5,0x49db,0x49e1,0x4a18};
    uint16_t expected=w->sp,target=rd(w,(uint16_t)(w->r.registers.bx+0x33e6)),entry;
    w->o->next_segment=w->cs;w->o->next_ip=0x491d;
    if(w->o->dispatch_calls==w->l->dispatch_calls){w->o->status=3;return 0;}
    for(entry=0;entry<11;++entry)if(targets[entry]==target)break;
    if(entry==11 && target!=0x49e7 && target!=0x4a19){w->o->status=6;w->o->unresolved_target=target;return 0;}
    ++w->o->dispatch_calls;push(w,0x4921);
    if(entry<11){
        td2ega_sim_dispatch_bus_result h;td2ega_sim_dispatch_bus(w->m,w->bytes,w->load,w->ss,w->sp,entry,&w->r,w->zf,&h);w->r=h.returned;w->zf=h.zero_flag;w->o->bus_writes+=h.bus_writes;
        return finish_call(w,h.status,h.next_segment,h.next_ip,h.current_sp,0x4921,expected);
    }else{
        td2ega_sample_guards_result h;td2ega_sample_guards_limits l={w->l->guard_calls-w->o->guard_calls,{0,0}};l.sample=child_limits(w);
        td2ega_sample_guards(w->m,w->bytes,w->load,w->ss,w->sp,(uint16_t)(target==0x4a19),&w->r,&l,&h);w->r=h.returned;w->zf=h.zero_flag;w->o->guard_calls+=h.guard_calls;w->o->child_calls+=h.sample_calls;w->o->control_calls+=h.control_calls;w->o->bus_writes+=h.bus_writes;
        return finish_call(w,h.status,h.next_segment,h.next_ip,h.current_sp,0x4921,expected);
    }
}
#define AX w.r.registers.ax
#define BX w.r.registers.bx
#define CX w.r.registers.cx
#define DX w.r.registers.dx
#define SI w.r.registers.si
#define DI w.r.registers.di
#define BP w.r.bp
#define CF w.r.carry
void td2ega_sim_controller(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,uint16_t sp,const td2ega_state_registers *in,const td2ega_sim_controller_limits *limits,td2ega_sim_controller_result *out)
{
    work w;uint16_t v,t;uint8_t b,al,ah;uint32_t wide;int32_t product;
    if(out==NULL)return;
    *out=(td2ega_sim_controller_result){0};out->status=2;
    if(m==NULL || bytes<UINT32_C(0x100000) || in==NULL || limits==NULL || sp<24 || sp>UINT16_C(0xffe0) || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1)return;
    w=(work){m,bytes,load,ss,sp,(uint16_t)(load+0x6c9),0,*in,limits,out};
    b=byte(&w,0x33b7);cmp(&w,b,8);if(b!=8){cmp(&w,b,2);if(b>=2){BX=rd(&w,0x52cc);cmp(&w,BX,160);if(BX!=160){if(sw(BX)>160){BX=sub(&w,BX,20);cmp(&w,BX,160);if(sw(BX)<=160)BX=160;}else{BX=add(&w,BX,20);cmp(&w,BX,160);if(sw(BX)>=160)BX=160;}wr(&w,0x52cc,BX);}}}
    if(!window(&w,0x46b0,0))goto done;
    low(&w,byte(&w,0x52cf));AX=(uint16_t)(AX&255);CF=0;w.zf=1;wb(&w,0x336f,0);wb(&w,0x336e,0);BX=AX;AX=shl(&w,AX);AX=add(&w,AX,BX);AX=add(&w,AX,rd(&w,0x52c8));
again:
    if(!budget(&w,0x46ca,&out->iterations,limits->iterations))goto done;
    b=byte(&w,0x5490);cmp(&w,b,2);if(b>=2)goto root;
    wr(&w,0x52c8,AX);CF=0;w.zf=(uint16_t)((AX>>8)==0);if(w.zf)goto root;
    BX=rd(&w,0x52ca);BX=add(&w,BX,0x47);BX=(uint16_t)((BX&0xff00)|byte(&w,BX));BX=shl(&w,BX);BX=(uint16_t)(BX&255);CF=0;w.zf=1;BX=shl(&w,BX);low(&w,byte(&w,(uint16_t)(BX+0x347e)));b=(uint8_t)logic(&w,(uint16_t)(byte(&w,0x33bd)^(uint8_t)AX));wb(&w,0x33bd,b);wb(&w,0x336e,1);
    if(!ring(&w,0x46f4))goto done;
    b=byte(&w,0x533e);b=(uint8_t)(b+1);BX=(uint16_t)((BX&0xff00)|b);w.zf=(uint16_t)(b==0);wb(&w,0x533e,b);b=(uint8_t)(b+0x46);b=(uint8_t)logic(&w,(uint16_t)(b&0x7f));BX=b;CF=0;w.zf=1;DI=BX;cmp(&w,(uint8_t)AX,byte(&w,0x337a));if(!CF)goto absent;
    if(!ring(&w,0x4713))goto done;
    low(&w,logic(&w,(uint16_t)((uint8_t)AX&15)));cmp(&w,(uint8_t)AX,15);if(w.zf)goto absent;
    al=(uint8_t)((uint8_t)AX-7);CF=(uint16_t)((uint8_t)AX<7);w.zf=(uint16_t)(al==0);low(&w,al);if(w.zf)goto absent;
    if(al>=0x80){logic(&w,(uint16_t)(byte(&w,0x33bd)&0xe0));if(!w.zf)goto absent;}
    else{
        logic(&w,(uint16_t)(byte(&w,0x33bd)&0x8c));if(!w.zf)goto absent;
        BX=rd(&w,0x52ca);BX=sub(&w,BX,0x3aed);SI=0;CF=0;w.zf=1;
        for(;;){
            if(!budget(&w,0x4735,&out->rows,limits->rows))goto done;
            v=rd(&w,(uint16_t)(SI+0x37a6));cmp(&w,v,0);if(v==0)break;t=rd(&w,(uint16_t)(SI+0x37a8));cmp(&w,BX,t);if(BX<=t){v=rd(&w,(uint16_t)(SI+0x37a6));cmp(&w,BX,v);if(BX>=v)goto absent;break;}SI=add(&w,SI,8);
        }
    }
    wb(&w,(uint16_t)(DI+0x370a),(uint8_t)AX);
    do{
        if(!ring(&w,0x475b))goto done;
        low(&w,logic(&w,(uint16_t)((uint8_t)AX&7)));cmp(&w,(uint8_t)AX,6);
    }while(!CF);
    ah=(uint8_t)AX;AX=(uint16_t)((AX&255)|((uint16_t)ah<<8));al=(uint8_t)((uint8_t)AX<<1);CF=(uint16_t)(((uint8_t)AX>>7)&1);w.zf=(uint16_t)(al==0);low(&w,al);al=(uint8_t)(al<<1);low(&w,al);al=(uint8_t)(al+ah);low(&w,al);AX=(uint16_t)(AX&255);CF=0;w.zf=1;SI=AX;wb(&w,(uint16_t)(DI+0x368a),(uint8_t)AX);SI=shl(&w,SI);SI=shl(&w,SI);v=rd(&w,(uint16_t)(SI+0x1db4));cmp(&w,v,0);if(v!=0)goto update;
absent:
    wb(&w,(uint16_t)(DI+0x368a),0xff);wb(&w,(uint16_t)(DI+0x370a),0xff);
update:
    v=(uint16_t)(rd(&w,0x3320)-1);wr(&w,0x3320,v);w.zf=(uint16_t)(v==0);if(w.zf)wb(&w,0x5490,4);
    v=(uint16_t)(rd(&w,0x5342)-1);wr(&w,0x5342,v);w.zf=(uint16_t)(v==0);if(w.zf){v=(uint16_t)(rd(&w,0x5342)+1);wr(&w,0x5342,v);w.zf=(uint16_t)(v==0);}
    BX=rd(&w,0x2f46);low(&w,byte(&w,0x52cf));al=(uint8_t)AX;AX=(uint16_t)(al*al);CF=(uint16_t)((AX>>8)!=0);CX=AX;wr(&w,0x335a,AX);DX=rd(&w,0x23b4);AX=rd(&w,0x23b2);DX=shl(&w,DX);cmp(&w,DX,CX);
    if(CF){DX=shr(&w,DX);out->next_segment=w.cs;out->next_ip=0x47bf;if(CX==0 || DX>=CX){out->status=4;goto done;}wide=((uint32_t)DX<<16)|AX;t=(uint16_t)(wide%CX);AX=(uint16_t)(wide/CX);DX=t;logic(&w,BX);
        if(sw(BX)<0){v=AX;AX=sub(&w,0,AX);cmp(&w,BX,AX);if(sw(BX)<sw(AX))wb(&w,0x336f,1);(void)v;}else{cmp(&w,BX,AX);if(sw(BX)>sw(AX))wb(&w,0x336f,1);}}
    wr(&w,0x333c,AX);CX=rd(&w,0x2f4a);DX=rd(&w,0x3322);v=rd(&w,0x8a9a);cmp(&w,v,1);
    if(v==1){AX=0;CF=0;w.zf=1;wr(&w,0x2f4a,AX);DX=sub(&w,0,DX);wr(&w,0x2f46,DX);}
    else{b=byte(&w,0x336f);cmp(&w,b,0);if(b!=0){AX=rd(&w,0x333c);BX=sub(&w,0,BX);BX=add(&w,BX,AX);AX=shl(&w,AX);BX=add(&w,BX,AX);BX=sar(&w,BX);}CX=add(&w,CX,DX);CX=add(&w,CX,BX);wr(&w,0x2f4a,CX);wr(&w,0x2f48,CX);}
    CX=rd(&w,0x3338);DX=rd(&w,0x333a);cmp(&w,rd(&w,0x3322),0);AX=rd(&w,0x2f48);cmp(&w,AX,DX);if(sw(AX)>sw(DX))wr(&w,0x2f48,DX);else{cmp(&w,AX,CX);if(sw(AX)<sw(CX))wr(&w,0x2f48,CX);}
    AX=rd(&w,0x2f4a);cmp(&w,AX,DX);if(sw(AX)>sw(DX))wr(&w,0x2f4a,DX);else{cmp(&w,AX,CX);if(sw(AX)<sw(CX))wr(&w,0x2f4a,CX);}
    wr(&w,0x2f48,sar(&w,rd(&w,0x2f48)));wr(&w,0x2f48,sar(&w,rd(&w,0x2f48)));BX=rd(&w,0x52cc);b=byte(&w,0x33b7);cmp(&w,b,8);if(b!=8){b=byte(&w,0x33b7);cmp(&w,b,2);if(b>=2){AX=0;CF=0;w.zf=1;wr(&w,0x2f46,AX);wr(&w,0x2f48,AX);wr(&w,0x2f4a,AX);}}
    AX=rd(&w,0x2f4a);AX=shl(&w,AX);low(&w,(uint16_t)(AX>>8));if(!scalar(&w))goto done;DX=36;product=sw(AX)*sw(DX);AX=(uint16_t)product;DX=(uint16_t)((uint32_t)product>>16);CF=(uint16_t)(product<-32768 || product>32767);low(&w,(uint16_t)(AX>>8));AX=signbyte((uint8_t)AX);BX=sub(&w,BX,AX);wr(&w,0x52cc,BX);
    if(!window(&w,0x48a2,0) || !window(&w,0x48a5,1) || !threshold(&w) || !indexed(&w))goto done;
    BX=rd(&w,0x52ca);BX=(uint16_t)(BX+1);w.zf=(uint16_t)(BX==0);wr(&w,0x52ca,BX);BP=BX;CX=(uint16_t)((CX&0xff00)|byte(&w,BX));CX=(uint16_t)(CX&255);CF=0;w.zf=1;wb(&w,0x5491,(uint8_t)logic(&w,(uint16_t)(byte(&w,0x5491)&0xfe)));CX=shl(&w,CX);wb(&w,0x5491,(uint8_t)logic(&w,(uint16_t)(byte(&w,0x5491)|(CX>>8))));CX=(uint16_t)(CX&255);CF=0;w.zf=1;CX=shl(&w,CX);CX=add(&w,CX,0x347e);SI=CX;DX=rd(&w,SI);wb(&w,0x5491,(uint8_t)logic(&w,(uint16_t)(byte(&w,0x5491)^(uint8_t)DX)));low(&w,(uint16_t)(DX>>8));AX=signbyte((uint8_t)AX);DX=(uint16_t)(DX&0xff00);CF=0;w.zf=1;DX=sar(&w,DX);DX=sar(&w,DX);wr(&w,0x3322,DX);AX=sar(&w,AX);wr(&w,0x5344,add(&w,rd(&w,0x5344),AX));DX=AX;AX=sar(&w,AX);AX=sar(&w,AX);AX=add(&w,AX,DX);wr(&w,0x5346,add(&w,rd(&w,0x5346),AX));BX=add(&w,BX,6);BX=logic(&w,(uint16_t)(BX&7));low(&w,byte(&w,(uint16_t)(SI+1)));wb(&w,(uint16_t)(BX+0x335d),(uint8_t)AX);
    CX=(uint16_t)((CX&0xff00)|w.m[address(w.ss,(uint16_t)(BP+1))]);CX=(uint16_t)(CX&255);CF=0;w.zf=1;CX=logic(&w,(uint16_t)(CX&0x7f));CX=shl(&w,CX);CX=shl(&w,CX);CX=add(&w,CX,0x347e);SI=CX;BX=(uint16_t)((BX&0xff00)|byte(&w,(uint16_t)(SI+3)));BX=(uint16_t)(BX&255);CF=0;w.zf=1;BX=shl(&w,BX);if(!dispatch(&w))goto done;AX=rd(&w,0x52c8);ah=(uint8_t)((AX>>8)-1);AX=(uint16_t)((AX&255)|((uint16_t)ah<<8));w.zf=(uint16_t)(ah==0);goto again;
root:
    out->next_ip=pop(&w);out->next_segment=w.cs;out->status=0;out->zero_flag=w.zf;out->flags_valid=1;
done:
    out->current_sp=w.sp;out->returned=w.r;
}
