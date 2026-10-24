#ifndef TD2EGA_LONG_ARITHMETIC_H
#define TD2EGA_LONG_ARITHMETIC_H
#include "td2ega_signed_motion.h"
#include "td2ega_state_loop.h"
typedef struct td2ega_long_arithmetic_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t steps,calls,bus_writes;
    td2ega_state_registers returned;
} td2ega_long_arithmetic_result;
/*0=13A8:2E42 quotient,1=2F1C remainder; fourSSwords numeratorLo/Hi,
 * denominatorLo/Hi. Actual magnitude rewrites/wordDIV/normalization and
 * actual frozen2EE8 C multiply with real SS ABI/RETF8; roots also RETF8.
 * Native0return/1rawchild/2invalid/3before-shift-or-CALL/5DIVfaultprefix.
 * Raw80000000/FFFFFFFF returns80000000 quotient without host signedUB.
 * No actual exception delivery/caller/FLAGS lifetime/core acceptance. */
void td2ega_long_arithmetic(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    uint16_t,const td2ega_state_registers *,uint32_t,td2ega_long_arithmetic_result *);
#endif
