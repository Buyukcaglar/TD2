#ifndef TD2EGA_MUSIC_TICK_H
#define TD2EGA_MUSIC_TICK_H
#include <stdint.h>

typedef struct td2ega_music_registers {
    uint16_t ax, bx, cx, dx, si, di, ds, es;
    uint16_t interrupts_enabled, direction;
} td2ega_music_registers;
typedef struct td2ega_music_port_request {
    uint16_t operation, port, value, interrupts_enabled;
} td2ega_music_port_request;
typedef int (*td2ega_music_port_service)(void *context,
    const td2ega_music_port_request *request, uint8_t *read_value);
typedef struct td2ega_music_tick_result {
    uint16_t status; /* 0 normal RETF; 2 invalid native arguments; 3 budget; 4 adapter. */
    uint32_t steps;
    td2ega_music_registers registers;
} td2ega_music_tick_result;

/* Original75EA, serialized full 20-bit byte view, principal DS on entry.
 * Native result/context are disjoint from memory. Source/group alias order,
 * effective-offset wrap and ordinary word's adjacent byte are retained.
 * Live code/stack are outside admitted data writes; no asynchronous IRQ or
 * device execution. Budget diagnostics are outside original equivalence.
 * SHR uses x86 masked five-bit count; CPU-profile admission remains separate.
 */
void td2ega_music_tick(uint8_t *memory, uint32_t memory_bytes,
    uint16_t load_segment, const td2ega_music_registers *incoming,
    td2ega_music_port_service port, void *context, uint32_t max_steps,
    td2ega_music_tick_result *result);
#endif
