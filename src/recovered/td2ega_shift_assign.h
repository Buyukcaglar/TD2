#ifndef TD2EGA_SHIFT_ASSIGN_H
#define TD2EGA_SHIFT_ASSIGN_H
#include "td2ega_small_state.h"
typedef struct td2ega_shift_assign_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t shift_count,bus_writes;
    td2ega_state_registers returned;
} td2ega_shift_assign_result;
/*13A8:2FD0 takes twoSSwords[currentDSnearPointer,countWord], actual2FC4
 * CL-byte SHLAX/RCLDX, rereadsnearPointer thenstoresAX/DX inoriginalorder.
 * RETF imm4 consumesfarframe4+argumentbytes4 ->entrySP+8 withoutchangingCF.
 * FullSSframes/rawfarreturncoordinates; nooriginalCreturntype orallcaller/
 * lifetime/capacity/core acceptance inferred. Native0farreturn/1childreturn
 * boundary/2invalid, finitebyte-count body/nohostovershift. */
void td2ega_shift_assign(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    const td2ega_state_registers *,td2ega_shift_assign_result *);
#endif
