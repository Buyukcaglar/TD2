#pragma once
/* Differential-test DLL interface (see tools/diffharness/harness.py). */
#include <setjmp.h>
#include "types.h"

#ifdef _WIN32
#define DH_EXPORT __declspec(dllexport)
#else
#define DH_EXPORT __attribute__((visibility("default")))
#endif

/* 8086 register file at the call: inputs before, outputs after. SP points at the return address,
 * with stack arguments above it, exactly as the original function sees them. */
typedef struct { u16 ax, bx, cx, dx, si, di, bp, sp, ds, es, ss; } DhRegs;

extern jmp_buf *dh_fatal_jmp;
extern char dh_fatal_msg[256];
