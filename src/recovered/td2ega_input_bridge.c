#include "td2ega_input_bridge.h"
#include <stddef.h>
static uint32_t address(uint16_t s,uint16_t o)
{ return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff); }
static uint16_t word(const uint8_t *m,uint16_t s,uint16_t o)
{ uint32_t a=address(s,o);return (uint16_t)(m[a]|((uint16_t)m[(a+1)&UINT32_C(0xfffff)]<<8)); }
static void put(uint8_t *m,uint16_t s,uint16_t o,uint16_t v)
{ uint32_t a=address(s,o);m[a]=(uint8_t)v;m[(a+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8); }
static int service_call(uint8_t *m,uint16_t ss,uint16_t *sp,
    uint16_t kind,uint16_t site,uint16_t segment,uint16_t offset,
    td2ega_state_registers *r,td2ega_input_bridge_service service,void *context,
    uint32_t limit,td2ega_input_bridge_result *out,uint16_t *zero)
{
    td2ega_input_bridge_request q={0};td2ega_input_bridge_response response={0};
    uint16_t bytes=kind==0?6:4;
    if (out->calls==limit) { out->status=3;return 0; }
    *sp=(uint16_t)(*sp-bytes);q.kind=kind;q.site=site;q.segment=segment;q.offset=offset;
    q.stack_segment=ss;q.stack_sp=*sp;q.incoming=*r;
    if (kind==0) q.incoming.registers.interrupts_enabled=0;
    response.returned=*r;++out->calls;
    if (!service(context,m,&q,&response)) { out->status=4;return 0; }
    if (response.returned.carry>1 || response.returned.registers.interrupts_enabled>1 ||
        response.returned.registers.direction>1 || (kind==0 && response.zero>1)) { out->status=2;return 0; }
    *r=response.returned;*zero=response.zero;*sp=(uint16_t)(*sp+bytes);return 1;
}
void td2ega_input_bridge(uint8_t *m,uint32_t bytes,uint16_t load,uint16_t ss,
    uint16_t entry_sp,enum td2ega_input_bridge_entry entry,
    const td2ega_state_registers *in,td2ega_input_bridge_service service,
    void *context,uint32_t limit,td2ega_input_bridge_result *out)
{
    td2ega_state_registers r;uint16_t sp=entry_sp,zero=0,offset,segment,site;
    if (out==NULL) return;
    *out=(td2ega_input_bridge_result){0};out->status=2;
    if (m==NULL || bytes<UINT32_C(0x100000) || in==NULL || service==NULL ||
        entry<TD2EGA_INPUT_CALL || entry>TD2EGA_INPUT_BIOS_DRAIN || entry_sp<256 ||
        entry_sp>UINT16_C(0xfff0) || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1) return;
    r=*in;out->return_bytes=4;
    if (entry==TD2EGA_INPUT_SET) {
        r.bp=(uint16_t)(sp-2);
        r.registers.ax=word(m,ss,(uint16_t)(entry_sp+4));
        put(m,r.registers.ds,UINT16_C(0x64dc),r.registers.ax);
        r.registers.ax=word(m,ss,(uint16_t)(entry_sp+6));
        put(m,r.registers.ds,UINT16_C(0x64de),r.registers.ax);r.bp=in->bp;
    } else if (entry==TD2EGA_INPUT_GET) {
        r.registers.ax=word(m,r.registers.ds,UINT16_C(0x64dc));
        r.registers.dx=word(m,r.registers.ds,UINT16_C(0x64de));
    } else if (entry==TD2EGA_INPUT_CALL) {
        offset=word(m,r.registers.ds,UINT16_C(0x64dc));segment=word(m,r.registers.ds,UINT16_C(0x64de));
        if (!service_call(m,ss,&sp,1,0x69fe,segment,offset,&r,service,context,limit,out,&zero)) goto finish;
    } else {
        do {
            r.registers.ax=(uint16_t)((r.registers.ax&255)|UINT16_C(0x100));
            site=entry==TD2EGA_INPUT_BIOS_POLL?UINT16_C(0x6a05):UINT16_C(0x6a3d);
            if (!service_call(m,ss,&sp,0,site,0,0x16,&r,service,context,limit,out,&zero)) goto finish;
            if (zero) { r.registers.ax=0;r.carry=0;break; }
            r.registers.ax&=255;
            site=entry==TD2EGA_INPUT_BIOS_POLL?UINT16_C(0x6a0e):UINT16_C(0x6a46);
            if (!service_call(m,ss,&sp,0,site,0,0x16,&r,service,context,limit,out,&zero)) goto finish;
            if (entry==TD2EGA_INPUT_BIOS_POLL) {
                r.carry=0;if ((r.registers.ax&255)!=0) r.registers.ax&=255;break;
            }
        } while (1);
    }
    sp=(uint16_t)(sp+4);out->status=0;
finish:
    out->current_sp=sp;out->returned=r;
    (void)load;
}
