#include "td2ega_bios_block.h"
#include <stddef.h>
void td2ega_bios_block(uint8_t *m,uint32_t bytes,uint16_t ss,uint16_t sp,
    const td2ega_state_registers *in,td2ega_bios_block_service service,
    void *context,uint32_t limit,td2ega_bios_block_result *out)
{
    td2ega_bios_block_request q={0};td2ega_state_registers r,returned;uint32_t at;
    if (out==NULL) return;
    *out=(td2ega_bios_block_result){0};out->status=2;
    if (m==NULL || bytes<UINT32_C(0x100000) || in==NULL || service==NULL || sp<32 || sp>UINT16_C(0xfff0) || in->carry>1 || in->registers.interrupts_enabled>1 || in->registers.direction>1) return;
    r=*in;r.bp=(uint16_t)(sp-2);r.registers.es=r.registers.ds;r.registers.ax=UINT16_C(0x1002);
    at=(((uint32_t)ss<<4)+(uint16_t)(sp+4))&UINT32_C(0xfffff);
    r.registers.dx=(uint16_t)(m[at]|((uint16_t)m[(at+1)&UINT32_C(0xfffff)]<<8));out->current_sp=(uint16_t)(sp-2);
    if (limit==0) { out->status=3;out->returned=r;return; }
    q.site=UINT16_C(0xac08);q.interrupt_number=0x10;q.stack_segment=ss;q.stack_sp=(uint16_t)(sp-8);
    q.saved_flags=(uint16_t)(2|r.carry|(r.registers.interrupts_enabled<<9)|(r.registers.direction<<10));q.incoming=r;q.incoming.registers.interrupts_enabled=0;
    returned=r;out->calls=1;out->current_sp=q.stack_sp;
    if (!service(context,m,&q,&returned)) { out->status=4;out->returned=r;return; }
    if (returned.carry>1 || returned.registers.interrupts_enabled>1 || returned.registers.direction>1) { out->returned=r;return; }
    returned.bp=in->bp;out->returned=returned;out->current_sp=(uint16_t)(sp+4);out->status=0;
}
