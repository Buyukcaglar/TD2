#pragma once
/* The port always runs the TD2EGA.EXE image. TD2CGA.EXE's graphics, and its Hercules mode, are run-time
 * graphics backends (platform/gfx_backend.h, --cga and --hercules), not build variants. */
#define TD_VARIANT_NAME "EGA"
