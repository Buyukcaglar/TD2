#ifndef TD2EGA_RAW_LOAD_H
#define TD2EGA_RAW_LOAD_H
#include <stdint.h>

enum td2ega_raw_operation { TD2EGA_RAW_OPEN = 0, TD2EGA_RAW_READ = 1, TD2EGA_RAW_CLOSE = 2 };
typedef struct td2ega_raw_request {
    uint16_t operation, handle, segment, offset, count;
} td2ega_raw_request;
typedef struct td2ega_raw_response {
    uint16_t ax, carry;
} td2ega_raw_response;
typedef int (*td2ega_raw_service)(void *context, const td2ega_raw_request *request,
                                 td2ega_raw_response *response);
typedef struct td2ega_raw_result {
    uint16_t status; /* 0: normal, 1: original fatal prefix, 2: native diagnostic */
    uint16_t failed_operation;
    uint16_t return_offset, return_segment;
    uint16_t handle, handle_valid;
    uint16_t next_segment; /* original BP-6; increments even after short success */
    uint16_t last_read_segment;
    uint32_t successful_reads;
} td2ega_raw_result;

/* Addresses are opaque original data coordinates. The service owns file I/O
 * and byte storage. Native state/result/service context must be disjoint.
 * max_reads bounds host work; exhaustion is outside the original contract. */
void td2ega_raw_load(td2ega_raw_service service, void *context,
                     uint16_t filename_segment, uint16_t filename_offset,
                     uint16_t destination_offset, uint16_t destination_segment,
                     uint32_t max_reads, td2ega_raw_result *result);
#endif
