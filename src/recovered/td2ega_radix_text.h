#ifndef TD2EGA_RADIX_TEXT_H
#define TD2EGA_RADIX_TEXT_H
#include "td2ega_state_loop.h"
typedef struct td2ega_radix_text_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t iterations,bus_writes;
    td2ega_state_registers returned;
} td2ega_radix_text_result;
/*0=13A8:29D0, SS[value16,destNear,radix];1=29EC,
 * SS[valueLow,valueHigh,destNear,radix]. Actual shared2BBC body/SS saves.
 * Only selector0 decimal sign-extends/sign-prefixes. Raw radix/digit bytewrap,
 * CLD and do-once reversal; radix0 DIVfaultprefix5, radix1 can cycle.
 * Native0farreturn/2invalid/3before digit-or-reversal budget/5DIVfaultprefix.
 * No host buffer capacity, complete caller/lifetime or core acceptance. */
void td2ega_radix_text(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,uint16_t,
    const td2ega_state_registers *,uint32_t,td2ega_radix_text_result *);
#endif
