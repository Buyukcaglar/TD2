#ifndef TD2EGA_FIELD_CONTROLLER_H
#define TD2EGA_FIELD_CONTROLLER_H
#include "td2ega_record_math.h"
#include "td2ega_small_arithmetic.h"
#include "td2ega_small_algorithms.h"
#include "td2ega_table_scalar.h"
typedef struct td2ega_field_controller_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t calls,child_iterations,bus_writes;
    td2ega_state_registers returned;
} td2ega_field_controller_result;
/* Actual06C9:5880 near/noargs with actual5299/5C5A/52FD/5334/535B.
 * RootSP34 ensures frozen52FD minimumSP32. FullSSnearframes/RET2.
 * Native0rootRET/1rawchildRET/2invalid/3beforeCALL-or-child-loop prefix.
 * Rawfield/table/angle values, no units or simulation meaning assigned.
 * Actualcaller/writer/lifetime/IRQ/core/resource/device gates separate. */
void td2ega_field_controller(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    const td2ega_state_registers *,uint32_t,uint32_t,td2ega_field_controller_result *);
#endif
