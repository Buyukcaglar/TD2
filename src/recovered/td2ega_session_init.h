#ifndef TD2EGA_SESSION_INIT_H
#define TD2EGA_SESSION_INIT_H
#include <stdint.h>
#include "td2ega_timer_control.h"

typedef struct td2ega_session_install_result {
    uint16_t status;
    td2ega_timer_control_result timer;
    td2ega_callback_result callbacks[2];
} td2ega_session_install_result;

/* Data-only compatibility view, initialized by the caller's external provider.
 * These routines preserve the byte-ring state; they do not invent a seed. */
void td2ega_zero_simulation_state(uint8_t *group);
void td2ega_reset_view_state(uint8_t *group);
void td2ega_reset_session_state(uint8_t *group);
/* Serialized group/device profile. current_cs must identify the original
 * nonzero code segment. Result/group/device storage must be disjoint. */
void td2ega_install_simulation_state(uint8_t *group,
    td2ega_timer_control_state *device, td2ega_session_install_result *result);
#endif
