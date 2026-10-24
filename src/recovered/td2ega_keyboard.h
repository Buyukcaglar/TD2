#ifndef TD2EGA_KEYBOARD_H
#define TD2EGA_KEYBOARD_H
#include "td2ega_music_tick.h"
typedef struct td2ega_keyboard_result {
    uint16_t status, return_flags, flags_mask;
    td2ega_music_registers registers;
} td2ega_keyboard_result;
/* Full synthetic20-bit data bus, separatecode/liveSS. Port adapters preserve
 * registers/flags. Installation/restoration RETF; IRQ09 saves/restores its
 * registers and IRETs. INT16 AH1 uses RETF2: IF1 and OR-definedflags instead
 * of restoring the interrupt-frame flags. AF is undefined on that path.
 * BP/SS/frame integrity, supportedCPU/A20/IRQ profiles are separate.
 */
void td2ega_keyboard_install(uint8_t *memory, uint32_t memory_bytes,
    uint16_t code_segment, const td2ega_music_registers *incoming,
    td2ega_music_port_service port, void *context, td2ega_keyboard_result *result);
void td2ega_keyboard_restore(uint8_t *memory, uint32_t memory_bytes,
    const td2ega_music_registers *incoming, td2ega_music_port_service port,
    void *context, td2ega_keyboard_result *result);
void td2ega_keyboard_irq(uint8_t *memory, uint32_t memory_bytes,
    uint16_t load_segment, const td2ega_music_registers *incoming,
    uint16_t irq_flags, td2ega_music_port_service port, void *context,
    td2ega_keyboard_result *result);
void td2ega_keyboard_bios(uint8_t *memory, uint32_t memory_bytes,
    uint16_t load_segment, const td2ega_music_registers *incoming,
    uint16_t entry_flags, uint16_t irq_flags, td2ega_keyboard_result *result);
#endif
