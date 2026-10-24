#ifndef TD2EGA_TIMER_CALLBACKS_H
#define TD2EGA_TIMER_CALLBACKS_H
#include <stdint.h>

/* Five original callback slots plus the following segment terminator.
 * These are opaque original code addresses, never host pointers. */
typedef struct td2ega_callback_words {
    uint16_t word[12];
} td2ega_callback_words;

typedef struct td2ega_callback_write {
    uint16_t word_index;
    uint16_t value;
} td2ega_callback_write;

typedef struct td2ega_callback_result {
    uint16_t status;       /* 0: normal, 1: original fatal-prefix, 2: bad native args */
    uint16_t slot;         /* 0..4, or 5 when not found */
    uint16_t write_count;
    uint16_t enables_interrupts; /* remove match ends with STI; add never masks */
    td2ega_callback_write writes[10];
} td2ega_callback_result;

/* Events retain original word-write order. They do not establish concurrent
 * host atomicity; an integrating scheduler must retain the original policy. */
void td2ega_callback_add(td2ega_callback_words *state, uint16_t offset,
                         uint16_t segment, td2ega_callback_result *result);
void td2ega_callback_remove(td2ega_callback_words *state, uint16_t offset,
                            uint16_t segment, td2ega_callback_result *result);
#endif
