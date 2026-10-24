#ifndef TD2EGA_RUNTIME_EARLY_EXIT_H
#define TD2EGA_RUNTIME_EARLY_EXIT_H
#include "td2ega_runtime_exit.h"
/* Additional13A8:0582 ownsPUSHBP, actual060D(841A..841A),
 * actual060D(7082..7086), thenJMP059C/inheritedsavedBP/shared0599tail.
 * SameoldresultABI;operations additionallychargeprefix060Diterations.
 * SP80..FFE0/serialized20bitRAM/typedDOS-finalizer profiles. No extra
 * PUSHBP/CALL to0599 atsharedtail. Native1rawchild/2invalid/3budget/
 * 4adapter/5preparedAH4C. FullarithmeticFLAGS unexposed; CFIFDF retained.
 * RealDOSexit/actualcallbacks/allwriters-lifetime-IRQ/core/P1-GATE separate.
 */
void td2ega_runtime_early_exit(uint8_t *,uint32_t,uint16_t,uint16_t,
    uint16_t,const td2ega_state_registers *,td2ega_small_platform_service,
    td2ega_finalizer_service,void *,uint32_t,td2ega_runtime_exit_result *);
#endif
