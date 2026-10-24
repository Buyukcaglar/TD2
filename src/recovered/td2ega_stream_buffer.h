#ifndef TD2EGA_STREAM_BUFFER_H
#define TD2EGA_STREAM_BUFFER_H
#include "td2ega_heap_public.h"
typedef struct td2ega_stream_buffer_limits {
    uint32_t calls;
    td2ega_heap_public_limits public_heap;
} td2ega_stream_buffer_limits;
typedef struct td2ega_stream_buffer_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t calls,public_calls,heap_calls,align_calls,tail_calls,wrapper_calls,adjust_calls;
    uint32_t services,records,iterations,child_iterations,bus_writes;
    uint16_t zero_flag,flags_valid;
    td2ega_state_registers returned;
} td2ega_stream_buffer_result;
/* Actual13A8:0BE8 near/oneSSnearoffset argument, actual26A8 farframe/count200,
 * AX-only stream pointer/flags/signed-byte-times-six metadata/actualSS saves.
 * SP60..FFE0 preserves26A8entry50. Native0rootRET/1rawchildRET/2invalid/
 * 3budgets/4adapterfailure, flags_valid1onlyrootRET. No storage/caller/
 * capacity/ownership/lifetime/IRQ/core/DOS/session/fidelity acceptance. */
void td2ega_stream_buffer(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    const td2ega_state_registers *,const td2ega_stream_buffer_limits *,
    td2ega_small_platform_service,void *,td2ega_stream_buffer_result *);
#endif
