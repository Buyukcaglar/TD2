#ifndef TD2EGA_RUNTIME_REPORT_BUS_H
#define TD2EGA_RUNTIME_REPORT_BUS_H
#include "td2ega_video_reset.h"
#include "td2ega_timer_control_bus.h"
#include "td2ega_runtime_dispatch_bus.h"
typedef struct td2ega_runtime_report_services {
    td2ega_small_platform_service bios;
    td2ega_line_draw_service device;
    td2ega_music_port_service port;
    td2ega_runtime_dispatch_service formatter;
    td2ega_runtime_dispatch_services runtime;
    void *context;
} td2ega_runtime_report_services;
typedef struct td2ega_runtime_report_limits {
    uint32_t steps,calls,keyboard_ports,video_calls,video_events;
    uint32_t timer_steps,timer_ports;
    td2ega_runtime_dispatch_limits runtime;
} td2ega_runtime_report_limits;
typedef struct td2ega_runtime_report_result {
    uint16_t status,current_sp,next_segment,next_ip;
    uint32_t steps,calls,services,callbacks,ports,device_events,device_bytes,bus_writes;
    uint16_t flags_word,flags_mask,stage,halt_site,raw_target,raw_segment;
    td2ega_state_registers returned;
    td2ega_small_platform_request exit_request;
} td2ega_runtime_report_result;
/* Additional actualSS entry0=16A7:0002 report parent,1=06C9:68C4 cleanup.
 * ParentSP106..FFE0 reserves actual29F6 minimum100+farframe4+savedBP2.
 * Standalonecleanup acceptsanywordSP; beforefarRET SP>FFFC isqualification7.
 * Native0 retiredcleanup/no follow,1 rawchild,2 invalid,3 budget,4 adapter,
 * 5 preparedprocess-exit,6 childunknownnearword,7 qualifiedpreRET.
 * stage0 ownparent,1 video,2 keyboard,3 timer,4 formatter,5 runtime29F6.
 * calls countfiveparentCALLs;steps charge ownentry/keyboardentry/fivePUSHes.
 * FormatterRequest.kind2/site0023/target13A8:0B00 carries actualSSfarframe;
 * its fiveargumentwords remaininRAM, read/pushed oneatime throughcurrentBP.
 * Typedformatter isnotoriginal0B00/formatting-body acceptance. No fakeparent
 * POPBP/RETF follows the preparedterminal runtime profile.
 */
void td2ega_runtime_report_bus(uint8_t *,uint32_t,uint16_t,uint16_t,
    uint16_t,uint16_t,uint16_t,uint16_t,const td2ega_state_registers *,
    const td2ega_runtime_report_limits *,const td2ega_runtime_report_services *,
    td2ega_runtime_report_result *);
#endif
