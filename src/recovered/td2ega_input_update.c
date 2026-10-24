#include "td2ega_input_update.h"
#include <stddef.h>

static uint16_t word(const uint8_t *g, uint16_t at)
{
    return (uint16_t)((uint16_t)g[at] | ((uint16_t)g[(uint32_t)at + 1] << 8));
}
static void put_word(uint8_t *g, uint16_t at, uint16_t value)
{
    g[at] = (uint8_t)value; g[(uint32_t)at + 1] = (uint8_t)(value >> 8);
}
static td2ega_sim_target_result arithmetic_registers(const td2ega_key_registers *r)
{
    return (td2ega_sim_target_result){r->ax,r->bx,r->cx,r->dx};
}
static void copy_arithmetic(td2ega_key_registers *r, const td2ega_sim_target_result *a)
{
    r->ax = a->ax; r->bx = a->bx; r->cx = a->cx; r->dx = a->dx;
}
void td2ega_input_update(uint8_t *g, uint32_t bytes,
    const uint8_t *es, const td2ega_input_services *s,
    const td2ega_mutable_control *code_state,
    const td2ega_key_registers *incoming, uint16_t incoming_bp,
    uint16_t incoming_di, td2ega_input_update_result *r)
{
    td2ega_input_result input;
    td2ega_sim_target_result a;
    td2ega_small_control_result scanned;
    if (r == NULL) return;
    *r = (td2ega_input_update_result){0}; r->status = 2;
    if (g == NULL || bytes < UINT32_C(65536) || es == NULL || s == NULL || incoming == NULL) return;
    if (code_state == NULL ||
        (code_state->branch_424a != TD2EGA_BRANCH_UNSIGNED_LE && code_state->branch_424a != TD2EGA_BRANCH_NOT_EQUAL) ||
        (code_state->branch_4275 != TD2EGA_BRANCH_UNSIGNED_LE && code_state->branch_4275 != TD2EGA_BRANCH_NOT_EQUAL) ||
        (code_state->branch_42ad != TD2EGA_BRANCH_UNSIGNED_GT && code_state->branch_42ad != TD2EGA_BRANCH_NOT_EQUAL)) return;
    r->registers = *incoming; r->bp = incoming_bp; r->di = incoming_di;
    if (g[UINT16_C(0x33d4)] == 0) {
        td2ega_input_control_result controlled;
        td2ega_signed_motion_result moved;
        uint16_t idle;
        td2ega_input_direction_bits(g,bytes,s,&r->registers,&input);
        r->registers = input.registers; if (input.status != 0) return;
        r->raw_bits = r->registers.ax; g[UINT16_C(0x33b1)] = (uint8_t)r->raw_bits;
        r->registers.ax = td2ega_gameport_translate(g,r->raw_bits);
        /* Original POPBX consumes the pushed6828 argument, not a savedBX. */
        r->registers.bx = (uint16_t)(r->raw_bits & UINT16_C(0x30));
        if (g[UINT16_C(0x90a8)] == 0) r->registers.ax |= r->registers.bx;
        g[UINT16_C(0x33b0)] = (uint8_t)r->registers.ax;
        idle = (uint16_t)(word(g,UINT16_C(0x3352)) + UINT16_C(1)); put_word(g,UINT16_C(0x3352),idle);
        if (idle > UINT16_C(0x960)) g[UINT16_C(0x5490)] = UINT8_C(0xff);
        else if (r->registers.ax != 0) {
            put_word(g,UINT16_C(0x3352),0);
            if (code_state->branch_424a == TD2EGA_BRANCH_NOT_EQUAL ?
                word(g,UINT16_C(0x8a9a)) == UINT16_C(1) :
                word(g,UINT16_C(0x8a9a)) > UINT16_C(1)) g[UINT16_C(0x5490)] = UINT8_C(0xff);
        }
        a = arithmetic_registers(&r->registers);
        td2ega_update_input_control(g,code_state,&a,r->bp,&controlled);
        if (controlled.status != 0) return;
        copy_arithmetic(&r->registers,&controlled.registers); r->bp = controlled.bp;
        if (g[UINT16_C(0x3365)] != 0) {
            a = arithmetic_registers(&r->registers);
            td2ega_advance_control_pair(g,&a,r->bp,&controlled);
            copy_arithmetic(&r->registers,&controlled.registers); r->bp = controlled.bp;
        }
        td2ega_sum_eight_samples(g);
        r->registers.ax = word(g,UINT16_C(0x52ce)); r->registers.bx = 8;
        r->registers.dx = word(g,UINT16_C(0x30e4)); r->stage = 1;
        a = arithmetic_registers(&r->registers); td2ega_update_signed_motion(g,&a,&moved);
        copy_arithmetic(&r->registers,&moved.registers);
    }
    r->stage = 2;
    td2ega_input_consume_if_stack_group(g,bytes,s,&r->registers,&input);
    r->registers = input.registers; if (input.status != 0) return;
    if (r->registers.ax != 0 && (code_state->branch_4275 == TD2EGA_BRANCH_NOT_EQUAL ?
        word(g,UINT16_C(0x8a9a)) == UINT16_C(1) : word(g,UINT16_C(0x8a9a)) > UINT16_C(1))) g[UINT16_C(0x5490)] = UINT8_C(0xff);
    r->stage = 3; a = arithmetic_registers(&r->registers);
    td2ega_small_control_dispatch(g,es,&a,r->di,r->registers.direction,&scanned);
    copy_arithmetic(&r->registers,&scanned.registers); r->di = scanned.di;
    r->registers.direction = scanned.direction; r->status = scanned.status;
}
