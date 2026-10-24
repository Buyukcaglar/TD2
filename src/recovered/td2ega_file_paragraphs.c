#include "td2ega_file_paragraphs.h"
#include <stddef.h>

static uint16_t paragraphs(uint32_t bytes)
{
    return (uint16_t)((bytes >> 4) + ((bytes & 15u) != 0));
}

static int open_file(td2ega_metadata_service service, void *context,
                     uint16_t filename, td2ega_metadata_result *result)
{
    td2ega_metadata_request request = {TD2EGA_META_OPEN, 0, filename, 0, NULL};
    td2ega_metadata_response response = {0};
    if (!service(context, &request, &response)) return 0;
    if (response.carry != 0) {
        result->status = 1;
        result->failed_operation = TD2EGA_META_OPEN;
        return 0;
    }
    result->handle = response.ax;
    result->handle_valid = 1;
    return 1;
}

static int close_file(td2ega_metadata_service service, void *context,
                       td2ega_metadata_result *result)
{
    td2ega_metadata_request request = {TD2EGA_META_CLOSE, result->handle, 0, 0, NULL};
    td2ega_metadata_response response = {0};
    return service(context, &request, &response);
}

void td2ega_file_paragraphs(td2ega_metadata_service service, void *context,
                           uint16_t filename_offset, td2ega_metadata_result *result)
{
    td2ega_metadata_request request;
    td2ega_metadata_response response;
    uint32_t bytes;
    if (result == NULL) return;
    *result = (td2ega_metadata_result){0};
    result->status = 2;
    if (service == NULL || !open_file(service, context, filename_offset, result)) return;
    request = (td2ega_metadata_request){TD2EGA_META_SEEK_END, result->handle, 0, 0, NULL};
    response = (td2ega_metadata_response){0};
    if (!service(context, &request, &response)) return;
    bytes = ((uint32_t)response.dx << 16) | response.ax;
    request.operation = TD2EGA_META_SEEK_START;
    response = (td2ega_metadata_response){0};
    if (!service(context, &request, &response)) return;
    /* Both seek carry flags and the rewind result are ignored. */
    result->paragraphs = paragraphs(bytes);
    if (!close_file(service, context, result)) return;
    result->status = 0;
}

void td2ega_header_paragraphs(td2ega_metadata_service service, void *context,
                             uint16_t filename_offset, const uint8_t seed[4],
                             td2ega_metadata_result *result)
{
    td2ega_metadata_request request;
    td2ega_metadata_response response;
    uint16_t count;
    unsigned i;
    if (result == NULL) return;
    *result = (td2ega_metadata_result){0};
    result->status = 2;
    if (service == NULL || seed == NULL) return;
    for (i = 0; i < 4; i++) result->final_header[i] = seed[i];
    if (!open_file(service, context, filename_offset, result)) return;
    request = (td2ega_metadata_request){TD2EGA_META_READ, result->handle, 0, 4, result->final_header};
    response = (td2ega_metadata_response){0};
    if (!service(context, &request, &response)) return;
    count = response.ax;
    /* Original CMP AX,CX accepts AX4 even when carry is set. */
    if (!close_file(service, context, result)) return;
    if (count != 4) {
        result->status = 1;
        result->failed_operation = TD2EGA_META_READ;
        return;
    }
    result->paragraphs = paragraphs((uint32_t)result->final_header[1] |
                                    ((uint32_t)result->final_header[2] << 8) |
                                    ((uint32_t)result->final_header[3] << 16));
    result->status = 0;
}
