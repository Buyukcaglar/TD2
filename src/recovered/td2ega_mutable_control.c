#include "td2ega_mutable_control.h"
#include <stddef.h>

uint16_t td2ega_mutable_control_reset(td2ega_mutable_control *state)
{
    state->returns_state = 0;
    state->branch_424a = TD2EGA_BRANCH_UNSIGNED_LE;
    state->branch_4275 = TD2EGA_BRANCH_UNSIGNED_LE;
    state->branch_42ad = TD2EGA_BRANCH_UNSIGNED_GT;
    state->principal_5656 = 0x63;
    return (uint16_t)(state->load_segment + 0x1793u);
}

static int query_step(td2ega_mutable_control *state, uint16_t index,
                       td2ega_equipment_query query, void *context,
                       td2ega_mutable_result *result)
{
    uint16_t equipment;
    state->saved_near_return = index == 0 ? 0x6e : 0x7b;
    equipment = query(context, index);
    result->query_count++;
    state->scratch_24 = (uint8_t)((equipment & 0xc0u) >> 6);
    result->ax = state->selected_word;
    result->cx = 0x2706;
    if ((uint8_t)state->selected_word > state->scratch_24) return 0;
    if (state->scratch_2b == 0) {
        result->dx = state->selected_word;
        state->scratch_2a = 0;
        result->stub_call_count++;
        state->scratch_2a = 0x10;
        result->stub_call_count++;
        state->scratch_2b = (uint8_t)result->dx;
    }
    state->scratch_2a = 0;
    result->stub_call_count++;
    state->branch_424a = TD2EGA_BRANCH_NOT_EQUAL;
    state->scratch_2a = 0x10;
    result->stub_call_count++;
    state->branch_4275 = TD2EGA_BRANCH_NOT_EQUAL;
    state->branch_42ad = TD2EGA_BRANCH_NOT_EQUAL;
    result->cx = 0x2701;
    result->ax = state->saved_near_return;
    result->near_returns[result->near_return_count++] = state->saved_near_return;
    return 1;
}

void td2ega_mutable_main(td2ega_mutable_control *state, uint16_t entry_sp,
    uint16_t initial_dx, td2ega_equipment_query query, void *context,
    td2ega_mutable_result *result)
{
    if (result == NULL) return;
    *result = (td2ega_mutable_result){0};
    if (state == NULL || query == NULL) {
        result->status = 2;
        return;
    }
    result->low_0010 = (uint16_t)(entry_sp - 10u);
    result->low_0012 = 0x201;
    result->dx = initial_dx;
    state->scratch_2b = 0;
    state->own_nop_bb = 1;
    state->own_nop_154 = 1;
    state->own_nop_3da = 1;
    (void)td2ega_mutable_control_reset(state);
    if (query_step(state, 0, query, context, result) &&
        query_step(state, 1, query, context, result)) {
        state->returns_state = 1;
        state->principal_5656 = 0;
        result->ax = 0;
    }
    result->bx = 0;
}
