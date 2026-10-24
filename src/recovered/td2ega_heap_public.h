#ifndef TD2EGA_HEAP_PUBLIC_H
#define TD2EGA_HEAP_PUBLIC_H
#include "td2ega_heap_walk.h"
typedef struct td2ega_heap_public_limits {
    uint32_t calls;
    td2ega_heap_walk_limits walk;
} td2ega_heap_public_limits;
typedef struct td2ega_heap_public_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t calls,heap_calls,align_calls,tail_calls,wrapper_calls,adjust_calls;
    uint32_t services,records,iterations,child_iterations,bus_writes;
    uint16_t zero_flag,flags_valid;
    td2ega_state_registers returned;
} td2ega_heap_public_result;
/* Actual13A8:26A8 far/oneSSword count, actual2830requiredZF/initglobals/
 * actual26F1/fullSS/DS-ES/currentBP argument/actualsavedDI-SI-BP/farRET.
 * SP50..FFE0 preserves26F1entry42. PlainfarRETconsumesfourframebytes;
 * argumentcallerconsumedADDSP2. Native0rootRET/1rawchildRET/2invalid/
 * 3budgets/4adapterfailure; flags_valid1onlyrootRET. HeapwalkZFisnot
 * a successflag andisnotbranchedonbythisparent. No realDOS/CPU-A20/
 * caller/capacity/ownership/lifetime/IRQ/core/session acceptance. */
void td2ega_heap_public(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    const td2ega_state_registers *,const td2ega_heap_public_limits *,
    td2ega_small_platform_service,void *,td2ega_heap_public_result *);
#endif
