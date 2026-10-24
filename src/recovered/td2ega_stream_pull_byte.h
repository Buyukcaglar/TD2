#ifndef TD2EGA_STREAM_PULL_BYTE_H
#define TD2EGA_STREAM_PULL_BYTE_H
#include "td2ega_stream_buffer.h"
#include "td2ega_read_span.h"
typedef struct td2ega_stream_pull_byte_limits {
    uint32_t calls,services,read_mapper_calls,read_steps;
    td2ega_stream_buffer_limits buffer;
} td2ega_stream_pull_byte_limits;
typedef struct td2ega_stream_pull_byte_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t calls,buffer_calls,public_calls,heap_calls,align_calls,tail_calls,wrapper_calls,adjust_calls;
    uint32_t read_calls,read_steps,services,records,iterations,child_iterations,bus_writes;
    uint16_t zero_flag,flags_valid;
    td2ega_state_registers returned;
} td2ega_stream_pull_byte_result;
/* Actual0B42/far/oneSSnearstreamword/fullSS/signedbytechannel-times6/
 * actual0BE8heapand247Cread/fullSS-childreturns/metadata-rereads/count-store/
 * postincrement-bytefetch/unsignedAXbyte orFFFF. SP70..FFE0 preserves0BE8.
 * GlobalDOSservicebudgetacrossheap-read; parentCALL andchildbudgets distinct.
 * Native0rootRET/1rawchildRET/2invalid/3budget/4adapter/5readpreRETqualification.
 * flags_valid1onlyrootRET. No caller/writer-bufferbounds/storage-lifetime/
 * exclusion/realDOS-INTframes/CPU-A20/core/resource/session acceptance. */
void td2ega_stream_pull_byte(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    const td2ega_state_registers *,const td2ega_stream_pull_byte_limits *,
    td2ega_small_platform_service,void *,td2ega_stream_pull_byte_result *);
#endif
