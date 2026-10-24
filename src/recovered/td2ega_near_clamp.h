#ifndef TD2EGA_NEAR_CLAMP_H
#define TD2EGA_NEAR_CLAMP_H
#include "td2ega_state_loop.h"
typedef struct td2ega_near_clamp_result {
    uint16_t status;
    uint32_t words;
    td2ega_state_registers returned;
} td2ega_near_clamp_result;
/* 088E: five ordered DS passes, signed lower/upper comparisons, LOOP word
 * count (zero means65536), 16bit SI arithmetic. PlainnearRET pops2.
 * LiveSS savedAX/controlframes separate from data; nativeframes virtual.
 * No renderer/layout/callerbound/actualresource/core acceptance. */
void td2ega_near_clamp(uint8_t *memory,uint32_t memory_bytes,
    const td2ega_state_registers *incoming,uint32_t max_words,
    td2ega_near_clamp_result *result);
#endif
