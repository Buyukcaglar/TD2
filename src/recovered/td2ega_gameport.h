#ifndef TD2EGA_GAMEPORT_H
#define TD2EGA_GAMEPORT_H
#include <stdint.h>

typedef struct td2ega_gameport_request {
    uint16_t operation, port, value, interrupts_enabled; /* 0 read, 1 write */
} td2ega_gameport_request;
typedef int (*td2ega_gameport_service)(void *context,
    const td2ega_gameport_request *request, uint8_t *read_value);
typedef struct td2ega_gameport_result {
    uint16_t status, ax, bx, cx, dx, interrupts_enabled;
    uint32_t reads;
} td2ega_gameport_result;

/* Complete6686 over serialized full group and explicit port201 adapter.
 * Adapter preserves original nonresponse registers and does not mutate group.
 * Native service/budget diagnostics may leave partial state and are outside
 * original behavior. No physical elapsed-time unit is inferred from polls.
 */
void td2ega_gameport_sample(uint8_t *group, uint32_t group_bytes,
    td2ega_gameport_service service, void *context, uint16_t incoming_bx,
    uint16_t incoming_cx, uint16_t incoming_dx, uint16_t initial_if,
    uint32_t max_reads, td2ega_gameport_result *result);
void td2ega_gameport_initialize(uint8_t *group);
uint16_t td2ega_gameport_translate(const uint8_t *group, uint16_t input);
#endif
