#ifndef TD2EGA_STREAM_NEXT_BYTE_H
#define TD2EGA_STREAM_NEXT_BYTE_H
#include "td2ega_stream_pull_byte.h"
typedef struct td2ega_stream_next_byte_limits {
    uint32_t calls;
    td2ega_stream_pull_byte_limits pull;
} td2ega_stream_next_byte_limits;
typedef struct td2ega_stream_next_byte_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t calls,pull_calls,buffer_calls,public_calls,heap_calls,align_calls,tail_calls,wrapper_calls,adjust_calls;
    uint32_t read_calls,read_steps,services,records,iterations,child_iterations,bus_writes;
    uint16_t zero_flag,flags_valid;
    td2ega_state_registers returned;
} td2ega_stream_next_byte_result;
/* Actual18B0/PUSHCS+nearCALL farframe/currentDS83EEcounter-83F2stream/
 * DECSFguard/cursorINC-before-bytefetch/actual0B42allocator-reader/fullSS.
 * RootSP78..FFE0 preserveschild70. Native0rootRET/1rawchild/2invalid/
 * 3budget/4adapter/5readerqualification. flags_valid1onlyrootRET.
 * No actualcaller/allwriters/bufferbounds-storage-capacity-lifetime-exclusion/
 * historicalCPU-A20/core/resource/device/session/fidelity admission. */
void td2ega_stream_next_byte(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    const td2ega_state_registers *,const td2ega_stream_next_byte_limits *,
    td2ega_small_platform_service,void *,td2ega_stream_next_byte_result *);
#endif
