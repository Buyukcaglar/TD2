#ifndef TD2EGA_SMALL_ARITHMETIC_H
#define TD2EGA_SMALL_ARITHMETIC_H
#include "td2ega_state_loop.h"
typedef struct td2ega_small_arithmetic_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t iterations,bus_writes;
    td2ega_state_registers returned;
} td2ega_small_arithmetic_result;
/*0=06C9:5C30 rawrecordselector/nearRET,1=0143:019E signedcounter/IDIV/farRET,
 *2=06C9:5A25 conditionalpairupdate/nearRET,3=06C9:5C5A rawsquare/DIV/nearRET.
 * ActualDS/SS, word arithmetic/LOOPzero and read-after-write aliases retained.
 * Native0returnoperation/2invalid/3before-selector-iterationprefix/5DIVfaultprefix.
 * UndefinedDIVflags notadmitted; returnedCF setbyfollowingdefinedoperation.
 * Actualcaller/bounds/units/writers/otherFLAGS/lifetime/core gates separate. */
void td2ega_small_arithmetic(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    uint16_t,const td2ega_state_registers *,uint32_t,
    td2ega_small_arithmetic_result *);
#endif
