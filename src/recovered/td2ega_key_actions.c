#include "td2ega_key_actions.h"
#include <stddef.h>

static uint32_t address(uint16_t s, uint16_t o)
{
    return (((uint32_t)s<<4)+o)&UINT32_C(0xfffff);
}
static void put_word(uint8_t *m, uint16_t s, uint16_t o, uint16_t v)
{
    uint32_t at=address(s,o);m[at]=(uint8_t)v;m[(at+1)&UINT32_C(0xfffff)]=(uint8_t)(v>>8);
}
void td2ega_key_action_apply(uint8_t *m, uint32_t bytes, uint16_t load,
    enum td2ega_key_action action, const td2ega_music_registers *incoming,
    td2ega_key_action_service service, void *context, td2ega_music_tick_result *out)
{
    td2ega_music_registers r, returned;
    td2ega_key_action_request q={0};
    uint16_t text=0;
    int guarded=0;
    if (out==NULL) return;
    *out=(td2ega_music_tick_result){0};out->status=2;
    if (m==NULL || bytes<UINT32_C(0x100000) || incoming==NULL || service==NULL ||
        action<TD2EGA_KEY_ENABLE_GAMEPORT || action>TD2EGA_KEY_DIALOG_007C ||
        incoming->direction>1 || incoming->interrupts_enabled>1) return;
    r=*incoming;
#define B(o) m[address(r.ds,UINT16_C(o))]
    q.segment=(uint16_t)(load+UINT16_C(0x16fc));
    switch (action) {
    case TD2EGA_KEY_ENABLE_GAMEPORT:
        B(0x6cfc)=1;B(0x5efe)=1;guarded=1;
        q.segment=(uint16_t)(load+UINT16_C(0x1769));q.offset=UINT16_C(0xe);break;
    case TD2EGA_KEY_DISABLE_GAMEPORT:
        B(0x6cfc)=0;text=UINT16_C(0x603c);break;
    case TD2EGA_KEY_TOGGLE_EFFECTS:
        if ((B(0x5efb)&1)==0) { B(0x5efb)|=1;text=UINT16_C(0x6029); }
        else { B(0x5efb)&=2;put_word(m,r.ds,UINT16_C(0x5eee),0);B(0x5efc)=0;text=UINT16_C(0x6032); }
        break;
    case TD2EGA_KEY_TOGGLE_MUSIC:
        if ((B(0x5efb)&2)==0) { B(0x5efb)|=2;text=UINT16_C(0x6016); }
        else { B(0x5efb)&=1;put_word(m,r.ds,UINT16_C(0x5eee),0);B(0x5efc)=0;text=UINT16_C(0x601f); }
        break;
    case TD2EGA_KEY_DIALOG_0358:
        B(0x5efe)=1;guarded=1;q.offset=UINT16_C(0x358);break;
    default:
        B(0x5efe)=1;guarded=1;q.offset=UINT16_C(0x7c);break;
    }
    if (text!=0) {
        r.ax=text;q.offset=UINT16_C(0x220);q.argument_count=3;
        q.arguments[0]=text;q.arguments[1]=8;q.arguments[2]=0;
    }
    q.registers=r;returned=r;out->steps=1;
    if (!service(context,m,&q,&returned)) { out->status=4;out->registers=r;return; }
    r=returned;
    if (guarded) B(0x5efe)=0;
    out->status=0;out->registers=r;
#undef B
}
