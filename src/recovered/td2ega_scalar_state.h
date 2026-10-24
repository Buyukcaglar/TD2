#ifndef TD2EGA_SCALAR_STATE_H
#define TD2EGA_SCALAR_STATE_H
#include "td2ega_state_loop.h"
typedef struct td2ega_scalar_state_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t bus_writes;
    td2ega_state_registers returned;
} td2ega_scalar_state_result;
/*0=16AA:0002 ASCII-bytecase/signextension,1=13A8:2A18 signedindex/bit40,
 *2=13A8:190E rawflag/signedpositivecounter,3=0432:1D25 indexedreset.
 * CurrentDSfields/SSargs/savedframes/rawplainfarreturn retained. Native0
 * farreturnoperation/2invalid; upperEAX preservedbyoriginalunprefixed98,
 * confirmedseparately, nooriginalCreturntype inferred. Callerbounds/otherFLAGS/
 * lifetime/IRQ/core/device/game/fidelity acceptance remainsseparate. */
void td2ega_scalar_state(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    uint16_t,const td2ega_state_registers *,td2ega_scalar_state_result *);
#endif
