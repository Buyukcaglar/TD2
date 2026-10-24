#ifndef TD2EGA_STREAM_PUSH_BYTE_H
#define TD2EGA_STREAM_PUSH_BYTE_H
#include "td2ega_stream_buffer.h"
typedef struct td2ega_stream_push_byte_limits {
    uint32_t calls;
    td2ega_stream_buffer_limits buffer;
} td2ega_stream_push_byte_limits;
typedef struct td2ega_stream_push_byte_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t calls,buffer_calls,public_calls,heap_calls,align_calls,tail_calls,wrapper_calls,adjust_calls;
    uint32_t services,records,iterations,child_iterations,bus_writes;
    uint16_t zero_flag,flags_valid;
    td2ega_state_registers returned;
} td2ega_stream_push_byte_result;
/* Actual13A8:21D6 far/twoSSwords-bytevalue-streamnearoffset/actual0BE8/fullSS,
 * rawflags/cursor-count/backwardbytewrite/signedmetadataindex/plainfarRET.
 * SP70..FFE0 preserveschild0BE8entry60. Native0rootRET/1rawchildRET/2invalid/
 * 3budgets/4adapterfailure; flags_valid1onlyrootRET. No caller/storage/domain/
 * capacity/ownership/lifetime/CPU-A20/IRQ/core/DOS/session/fidelity acceptance. */
void td2ega_stream_push_byte(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    const td2ega_state_registers *,const td2ega_stream_push_byte_limits *,
    td2ega_small_platform_service,void *,td2ega_stream_push_byte_result *);
#endif
