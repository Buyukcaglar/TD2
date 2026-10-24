#ifndef TD2EGA_SECONDARY_FIELDS_H
#define TD2EGA_SECONDARY_FIELDS_H
#include "td2ega_record_math.h"
#include "td2ega_small_arithmetic.h"
#include "td2ega_small_algorithms.h"
#include "td2ega_table_scalar.h"
typedef struct td2ega_secondary_fields_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t calls,child_iterations,bus_writes;
    td2ega_state_registers returned;
} td2ega_secondary_fields_result;
/* Actual06C9:50A1 near/noargs, actualtenpossiblemath/arithmetic/scalarCALLs.
 * SP34..FFE0 preserves52FDchild32. FullSSnearframes/RET2.
 * Native0rootRET/1rawchildRET/2invalid/3beforeCALL-childloop/5beforeDIVfault.
 * Rawfields/tables/word-bytewrap, no units/record or physicsmeaning assigned.
 * Actualcaller/writers/lifetime/IRQ/core/resource/device gates separate. */
void td2ega_secondary_fields(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    const td2ega_state_registers *,uint32_t,uint32_t,td2ega_secondary_fields_result *);
#endif
