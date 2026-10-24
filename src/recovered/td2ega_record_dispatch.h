#ifndef TD2EGA_RECORD_DISPATCH_H
#define TD2EGA_RECORD_DISPATCH_H
#include "td2ega_record_math.h"
#include "td2ega_small_algorithms.h"
#include "td2ega_table_scalar.h"
typedef struct td2ega_record_dispatch_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t calls,child_iterations,bus_writes;
    uint16_t raw_target,dispatch_offset,return_kind,discarded_word;
    td2ega_state_registers returned;
} td2ega_record_dispatch_result;
/* Actual06C9:56ED near/noargs/actualmath-ratio-scalar children/fullSS.
 * MutableDS3460rawdispatch supportsactualtargets57AB/57B7/57CF; unknown
 * targetnative6 stopsbefore57A7JMP withactualoperand retained, noterror.
 * Native0actualrootRET/1rawchildRET/2invalid/3beforeCALL-childloop.
 * return_kind1 isliteralPOPAXthennearRET: consumesTWO SSwords, AXactual
 * discardedword; root53A6 caller maynonlocallyreturn. NofarRET invented.
 * RootSP34..FFE0 preserves52FD32. Alltargetwriters/caller/IRQ/core open. */
void td2ega_record_dispatch(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    const td2ega_state_registers *,uint32_t,uint32_t,td2ega_record_dispatch_result *);
#endif
