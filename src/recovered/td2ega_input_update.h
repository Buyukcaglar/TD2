#ifndef TD2EGA_INPUT_UPDATE_H
#define TD2EGA_INPUT_UPDATE_H
#include "td2ega_input_poll.h"
#include "td2ega_input_control.h"
#include "td2ega_signed_motion.h"
#include "td2ega_control_ops.h"
typedef struct td2ega_input_update_result {
    uint16_t status, stage, bp, di, raw_bits;
    td2ega_key_registers registers;
} td2ega_input_update_result;

/* Complete near420A with recovered native callees. Explicit synthetic service
 * and sharedgroup/ES profiles inherit component contracts. Original field
 * effects/adapter writes are separate from liveSS frames; DS may equal SS.
 * Scanner target domain and segment-preserving callbacks are preconditions.
 * Native diagnostics are outside original error equivalence; no IRQ/core or
 * supplied-resource integration is admitted by this isolated composition.
 */
void td2ega_input_update(uint8_t *group, uint32_t group_bytes,
    const uint8_t *es_view, const td2ega_input_services *services,
    const td2ega_mutable_control *code_state,
    const td2ega_key_registers *incoming, uint16_t incoming_bp,
    uint16_t incoming_di, td2ega_input_update_result *result);
#endif
