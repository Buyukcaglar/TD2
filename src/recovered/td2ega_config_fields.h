#ifndef TD2EGA_CONFIG_FIELDS_H
#define TD2EGA_CONFIG_FIELDS_H
#include "td2ega_copy_config.h"
/*0=5DFB fourSSwords ->CSAF46/48/4A/4C in read/write order, preservesDF;
 *1=78F8 oneSSnear-destination/currentDS <-26words CSAF3A, CLD.
 * FullSSframe/rawfarreturncoordinates retained; result/work semantics same
 * ascopy_config. Allproducer/writer/lifetime/device/core gates separate. */
void td2ega_config_fields(uint8_t *,uint32_t,uint16_t,uint16_t,uint16_t,
    uint16_t,const td2ega_state_registers *,uint32_t,td2ega_copy_config_result *);
#endif
