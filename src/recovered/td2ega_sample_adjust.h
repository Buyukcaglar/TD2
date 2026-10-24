#ifndef TD2EGA_SAMPLE_ADJUST_H
#define TD2EGA_SAMPLE_ADJUST_H
#include "td2ega_control_bus.h"
#include "td2ega_byte_ring.h"
typedef struct td2ega_sample_adjust_limits {uint32_t calls,control_calls;} td2ega_sample_adjust_limits;
typedef struct td2ega_sample_adjust_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t calls,control_calls,bus_writes;
    uint16_t zero_flag,flags_valid;
    td2ega_state_registers returned;
} td2ega_sample_adjust_result;
/* Actual4A2E/near/actual45FC-4612/fullSS7977setter-780Ering/IF1afterSTI/
 * actualringCtransform/sourceorderedfieldadjustments/raw256selector-writes.
 * SP20..FFE0 preserves45FCentry18. Native0rootnearRET/1rawchildRET/
 * 2invalid/3budget; rootZFonlyflags_valid1. Serialized20bitRAM only;
 * no IRQ exclusion/sharedsource lifetime/allwriters/core/RNG-purpose/
 * resource-codec/session/gameplay/fidelity admission. */
void td2ega_sample_adjust(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    const td2ega_state_registers *,const td2ega_sample_adjust_limits *,
    td2ega_sample_adjust_result *);
#endif
