#ifndef TD2EGA_FILE_PARAGRAPHS_H
#define TD2EGA_FILE_PARAGRAPHS_H
#include <stdint.h>

enum td2ega_metadata_operation {
    TD2EGA_META_OPEN = 0, TD2EGA_META_READ = 1, TD2EGA_META_CLOSE = 2,
    TD2EGA_META_SEEK_END = 3, TD2EGA_META_SEEK_START = 4
};
typedef struct td2ega_metadata_request {
    uint16_t operation, handle, filename_offset, count;
    uint8_t *header_destination; /* four bytes only for READ */
} td2ega_metadata_request;
typedef struct td2ega_metadata_response {
    uint16_t ax, dx, carry;
} td2ega_metadata_response;
typedef int (*td2ega_metadata_service)(void *context, const td2ega_metadata_request *request,
                                     td2ega_metadata_response *response);
typedef struct td2ega_metadata_result {
    uint16_t status; /* 0 normal, 1 original fatal prefix, 2 native diagnostic */
    uint16_t failed_operation, paragraphs, handle, handle_valid;
    uint8_t final_header[4];
} td2ega_metadata_result;

void td2ega_file_paragraphs(td2ega_metadata_service service, void *context,
                           uint16_t filename_offset, td2ega_metadata_result *result);
/* seed preserves the original caller's four stack bytes when an error/short
 * service response does not initialize the entire header. */
void td2ega_header_paragraphs(td2ega_metadata_service service, void *context,
                             uint16_t filename_offset, const uint8_t seed[4],
                             td2ega_metadata_result *result);
#endif
