#ifndef TD2EGA_SMALL_ALGORITHMS_H
#define TD2EGA_SMALL_ALGORITHMS_H
#include "td2ega_state_loop.h"
typedef struct td2ega_small_algorithms_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t iterations,bus_writes;
    td2ega_state_registers returned;
} td2ega_small_algorithms_result;
/*0=06C9:08CB signedfieldclamp/nearRET,1=52FD rawword/byteDIVratio/nearRET,
 *2=0432:0061 underscore/space-minimum18 withactualSSwordcounter/farRET.
 * Signedoverflow-correctguards/wordwrap/postwriteSSaliases retained.
 * Native0returnoperation/2invalid/3before-labelscan-or-storeprefix.
 * Caller/fields/units/bounds/writers/lifetime/FLAGS/core acceptance separate. */
void td2ega_small_algorithms(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    uint16_t,const td2ega_state_registers *,uint32_t,td2ega_small_algorithms_result *);
#endif
