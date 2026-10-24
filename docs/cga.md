# TD2CGA against TD2EGA

This is what M3 starts from: how the CGA executable differs from the EGA one we already run, function by function. `python tools/cga_compare.py` produces every number here; `python tools/cga_compare.py 06c9:0c17` prints one function's differences side by side. It reads both executables from `runs/game` and unpacks them in memory with `tools/exepack.py` (`unpack()`; it also handles TD2TDY).

## Summary

- **The simulation is the same program in both.** All 15 simulation functions that looked different are identical once the relink is accounted for. They differ only in where variables, tables and functions sit. The port's simulation code serves CGA unchanged.
- **The scene renderer's differences are all about drawing.** Of the 29 scene-renderer functions that looked different, 13 are identical after relinking. The other 16 differ only in how pixels reach the screen: 2-bit pixels instead of four planes, dither patterns instead of colour numbers, interleaved rows, and the colour-select port instead of the palette.
- **So a CGA backend is mostly a presentation job.** The game state and the projection are shared; what changes is the pixel routines, colours and a few scene helpers that write pixels themselves.

## Layout of the two executables

| | TD2EGA | TD2CGA |
|---|---|---|
| Unpacked image | 130,240 bytes | 119,872 bytes |
| Entry | 13A8:03F8 | 1136:03F8 |
| DGROUP (relative) | 178F | 151D |
| Initialised DGROUP data | 83D0h bytes | 8270h bytes |
| Graphics library segment | 06C9 | 06CF |
| Live target descriptor / screen descriptor | CS:AF3A / CS:AF54 | CS:913E / CS:9158 |

- The 22 segments correspond one to one, in the same order (for example 0267 → 026E, 0432 → 0439, 13A8 → 1136).
- CGA's initialised data is 160h bytes shorter, so every uninitialised variable (the whole race state from about DS:8270 on) sits 160h lower in CGA: `clock_seconds` is DS:942E in EGA and DS:92CE in CGA.
- Initialised tables move by varying amounts (C4h, C8h, E0h, F8h, 104h) because CGA's tables of colours, sprites and patterns have different sizes.
- The graphics library's target descriptor has the same 13-word layout in both builds; only its place in the code segment differs.

## How functions are compared

- **Pairing.** Functions come from the Kylofon indexes (`port/td2/port/td2{ega,cga}_functions.json`). They are paired segment by segment by aligning size, instruction count, call count and strings. Pairs are then corrected from the calls: when two paired functions call something at the same place, the two callees are twins.
- **Normalising the relink.** Both disassemblies are rewritten before comparing:
  - Branch targets become instruction labels compared through the alignment, and jumps that leave a function name the function they land in.
  - Calls become the EGA name of the callee, and segment constants become the EGA segment.
- **Accepting a moved address.** A number that differs counts as the same only if the CGA value is provably the moved EGA address. The evidence is one of:
  - the same bytes at both places;
  - the uninitialised-data shift;
  - the same offset inside a paired function;
  - a jump table whose entries point to paired code;
  - the graphics descriptor block;
  - a shift that at least two different variables in the same area show in the code.

  A single coincidence cannot pass, so what is left is a real difference.
- **Index mistakes this corrects.**
  - The indexes sometimes stop a function early (unfollowed jump tables, or the last function of a segment): CGA `police_start`, `steer_update` and `main_menu`. Each function is therefore compared up to the next indexed function, and a cut function gets its twin's length.
  - One EGA index entry, 06C9:1A37, is the tail of `draw_front_objects`; another, 06C9:C030, is the tail of the XOR blitter. 06C9:AF54 is not code at all: it is the screen descriptor.

## Simulation (15 functions): all identical after relinking

`steer_update`, `sim_timer_routine`, `decode_controls`, `curve_sum`, `overrev_check`, `motion`, `roadside_hit`, `traffic`, `meet_check`, `push_behind`, `ai_road_scan`, `ai_lane_min`, `police_reset`, `police_start`, `police_drive`.

Every difference in them was a moved variable, table, jump table or function, or an index cutting the function short.

## Scene renderer (29 functions)

**Identical after relinking (13):** `main_view_load`, `project_front_rows`, `build_spans_front`, `interp_span`, `project_mirror_rows`, `fix_cut_lines_mirror`, `clamp_edge_mirror`, `run_stage`, `stage_load`, `sim_stage_start`, `engine_smoke_sequence`, `draw_ticket`, `msg_missed_gas`.

**Different (16), all in drawing:**

| Function | What CGA does differently |
|---|---|
| `draw_front`, `draw_mirror` | No longer copy the target's four plane segments (CS:AF3C..AF42) to DS:5420..5426; the CGA target is one 2-bit buffer. Fill colours become dither patterns: colour 9 → 4444h, colour 6 → 8822h. |
| `span_fill_to` | Rewritten for 2 bits per pixel. EGA writes four planes with per-plane colour masks (DS:5428..5458). CGA fills one buffer with a 16-bit pattern (DS:09BE), rotated by 2 bits on alternate rows (`test si,2; ror bx,1; ror bx,1`), with 4-pixel byte masks (DS:531C). |
| `hline` | EGA calls `gfx_draw_line`; CGA draws the span itself with left and right masks for 4 pixels per byte (DS:531C..532B) and the row's pattern. |
| `draw_sky_front`, `draw_sky_mirror` | Before the horizon blit, both coordinates are forced odd (`or ax,1; or di,1`). Probably this keeps the dither phase; not confirmed. |
| `draw_ground_front`, `draw_ground_mirror` | One extra byte store at the start, and a constant 7 becomes 0 (its meaning is not checked yet). |
| `draw_tunnel_walls_front`, `draw_tunnel_walls_mirror` | Walk rows through a row-address table in the code segment (`mov di, cs:[bx]`, base at DS:09B6 or DS:2960) because CGA rows are interleaved, with a step of 80 bytes (front) or 20 (mirror) where EGA steps one byte. The constant 8 (the wall colour in EGA) becomes 0 or the pattern 9966h. |
| `draw_front_objects`, `draw_mirror_objects` | Pixel plots use 4 pixels per byte (`and ax,3` instead of `sar bx,1; and ax,7`) and one buffer instead of four planes; colours become patterns (6 → 8822h, 8 → 0); several object positions are forced odd or even; two AND-mask blits (`blit_and_clip_hot`) are dropped; near the end, a block that EGA clips through the descriptor's bottom row instead walks the row table with an 80-byte step. |
| `crash_sequence` | The crash flash writes the colour-select register (port 3D9h, 30h then 0) instead of loading EGA palettes DS:2E08 / DS:2E10 through `gfx_set_palette`. |
| `draw_steering` | The marker's save position is aligned to 4 pixels (`and dx,0FFFCh`) instead of 8. |
| `draw_instruments` | Buffers are created with plane mask FFFFh instead of 0Fh. |
| `create_buffer_like` | Width in pixels is the byte width times 4, not 8. |

## Other differences worth knowing

- **`gfx_video_hook`.** Empty in EGA. CGA writes the mode-control register (3D8h ← 0Eh) and the colour-select register (3D9h ← 30h).
- **Menus and game flow.** Same code with CGA colours (0Fh → 3, 6 → 2, 4 → AAAAh, 0Ah → 5555h) and pixel/byte shifts of 2 instead of 3. `car_slide`, the car-selection slide, builds the picture in an extra 320×176 buffer, where EGA scrolls the screen with write-mode-1 copies, which CGA hardware does not have. `load_shapes` uses a 1,002-byte buffer instead of 502.
- **Graphics library.** All of it differs. The pairing there is weaker, because CGA's library has different routines in a different order. Pairs that the scene code calls are reliable, since they come from call-site votes; others may be wrong.
- **Not compared yet.** Nothing here compares data contents: palettes, pattern tables, row tables, and the PCS sprite format, which the CGA backend will read.

## What this means for the CGA backend

- **The simulation needs nothing.** The port keeps running on the EGA image's DGROUP with its existing simulation code.
- **The graphics library becomes the CGA backend**, implementing the same `GfxBackend` table:
  - 2-bit pixels and interleaved rows at B800h;
  - colour select through 3D8h/3D9h;
  - PCS sprites;
  - the CGA dissolves, scroll and grabs.
- **Sixteen scene-renderer functions write pixels themselves or pass EGA colours.** Two ways to handle them:
  - Give the backend a few scene hooks: span fill, horizontal line, object pixel, wall rows, crash flash, a colour-to-pattern map, and the pixels per byte.
  - Or keep CGA copies of those functions next to the EGA ones.

  The hooks keep one copy of the scene logic and are the better fit for switching live later.
