#ifndef TD2EGA_MUTABLE_CONTROL_H
#define TD2EGA_MUTABLE_CONTROL_H
#include <stdint.h>

enum td2ega_branch_form {
    TD2EGA_BRANCH_UNSIGNED_LE = 0,
    TD2EGA_BRANCH_UNSIGNED_GT = 1,
    TD2EGA_BRANCH_NOT_EQUAL = 2
};
typedef struct td2ega_mutable_control {
    uint16_t load_segment, selected_word, saved_near_return;
    uint8_t scratch_24, scratch_2a, scratch_2b;
    uint8_t own_nop_bb, own_nop_154, own_nop_3da;
    uint8_t returns_state, branch_424a, branch_4275, branch_42ad, principal_5656;
} td2ega_mutable_control;
typedef uint16_t (*td2ega_equipment_query)(void *context, uint16_t query_index);
typedef struct td2ega_mutable_result {
    uint16_t status; /* 0 bounded normal return, 2 native argument diagnostic */
    uint16_t ax, bx, cx, dx;
    uint16_t low_0010, low_0012;
    uint16_t query_count, stub_call_count, near_return_count, near_returns[2];
} td2ega_mutable_result;

/* Code states become explicit control fields, never host code mutation.
 * Serialized baseline with fixed03D3 JMP/RET stub; query modifies only AX.
 * Ignored comparisons read ordinary readonly code/ROM bytes, without effects.
 * Original TF=0, valid nonwrapping stack and disjoint state/result/context. */
uint16_t td2ega_mutable_control_reset(td2ega_mutable_control *state);
void td2ega_mutable_main(td2ega_mutable_control *state, uint16_t entry_sp,
    uint16_t initial_dx, td2ega_equipment_query query, void *context,
    td2ega_mutable_result *result);
#endif
