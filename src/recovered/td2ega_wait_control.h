#ifndef TD2EGA_WAIT_CONTROL_H
#define TD2EGA_WAIT_CONTROL_H
#include "td2ega_state_loop.h"
enum td2ega_wait_mode { TD2EGA_WAIT_COUNTER, TD2EGA_WAIT_INPUT_OR_COUNTER };
typedef struct td2ega_wait_request {
    uint16_t kind, site, segment, offset; /* kind0 counter boundary, kind1 input69FE. */
    td2ega_state_registers incoming;
} td2ega_wait_request;
typedef int (*td2ega_wait_service)(void *context, uint8_t *memory,
    const td2ega_wait_request *request, td2ega_state_registers *returned);
typedef struct td2ega_wait_result {
    uint16_t status, deadline_low, deadline_high;
    uint32_t events;
    td2ega_state_registers returned;
} td2ega_wait_result;

/* 79C8: CLI, readDS5E8C/E, STI, RETF. IF becomes1; no rate/unit inferred.
 * Full20-bit bus and data/code/liveSS separation; resultdisjoint.
 */
void td2ega_counter_snapshot(const uint8_t *memory, uint32_t memory_bytes,
    const td2ega_state_registers *incoming, td2ega_wait_result *result);
/* 7A55/6A6A: raw32-bit distance, moduloaddition followedbyabsoluteunsigned
 * comparison. Counterboundary service models caller-supplied synthetic bus
 * updates before79C8, preservesCPU state (returned ignored); no IRQ delivered.
 * Input69FE service preservesSS/frameBP/controlintegrity; other modeled
 * registers/CFIFDF maychange. Nonwrappingframe/args, incidentalflags excluded.
 * Native2 invalid/3budget/4service are outsideoriginalerror equivalence.
 */
void td2ega_wait_control(uint8_t *memory, uint32_t memory_bytes,
    uint16_t load_segment, uint16_t entry_sp, enum td2ega_wait_mode mode,
    uint32_t distance, const td2ega_state_registers *incoming,
    td2ega_wait_service service, void *context, uint32_t max_events,
    td2ega_wait_result *result);
#endif
