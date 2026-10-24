#include "td2ega_raw_load.h"
#include <stddef.h>

void td2ega_raw_load(td2ega_raw_service service, void *context,
                     uint16_t filename_segment, uint16_t filename_offset,
                     uint16_t destination_offset, uint16_t destination_segment,
                     uint32_t max_reads, td2ega_raw_result *result)
{
    td2ega_raw_request request;
    td2ega_raw_response response;
    if (result == NULL) return;
    *result = (td2ega_raw_result){0};
    result->status = 2;
    result->next_segment = destination_segment;
    if (service == NULL) return;
    request = (td2ega_raw_request){TD2EGA_RAW_OPEN, 0, filename_segment, filename_offset, 0};
    response = (td2ega_raw_response){0};
    if (!service(context, &request, &response)) return;
    if (response.carry != 0) {
        result->status = 1;
        result->failed_operation = TD2EGA_RAW_OPEN;
        return;
    }
    result->handle = response.ax;
    result->handle_valid = 1;
    for (;;) {
        if (result->successful_reads == max_reads) return;
        result->last_read_segment = result->next_segment;
        request = (td2ega_raw_request){TD2EGA_RAW_READ, result->handle,
                                     result->last_read_segment, destination_offset, 0x4000};
        response = (td2ega_raw_response){0};
        if (!service(context, &request, &response)) return;
        if (response.carry != 0) {
            /* No CLOSE on this path before original fatal transfer. */
            result->status = 1;
            result->failed_operation = TD2EGA_RAW_READ;
            return;
        }
        result->successful_reads++;
        result->next_segment = (uint16_t)(result->next_segment + 0x400u);
        if (response.ax != 0x4000) break;
    }
    request = (td2ega_raw_request){TD2EGA_RAW_CLOSE, result->handle,
                                 result->last_read_segment, destination_offset, 0};
    response = (td2ega_raw_response){0};
    if (!service(context, &request, &response)) return;
    /* The original ignores close carry and AX. */
    result->return_offset = destination_offset;
    result->return_segment = destination_segment;
    result->status = 0;
}
