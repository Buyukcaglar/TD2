#ifndef TD2EGA_RING_SELECTION_H
#define TD2EGA_RING_SELECTION_H
#include "td2ega_byte_ring.h"
#include "td2ega_state_loop.h"
typedef struct td2ega_ring_selection_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t calls,bus_writes;
    td2ega_state_registers returned;
} td2ega_ring_selection_result;
/* Actual019E:0004 far root/noargs + actualbyte-ring C transformation.
 * Real caller/childSSframes and source ABI stores, mask7/wordCWD/8rawwords.
 * RootSP>=30; native0rootfarRET/1rawchildfarRET/2invalid/3beforeCALL.
 * Serialized flatRAM only; no IRQ exclusion/reset/seed/lifetime/core proof. */
void td2ega_ring_selection(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    const td2ega_state_registers *,uint32_t,td2ega_ring_selection_result *);
#endif
